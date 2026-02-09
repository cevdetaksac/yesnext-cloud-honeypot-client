#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloud Honeypot Client — Threat Detection Engine (v4.0)

Receives structured events from EventLogWatcher and performs:
  1. Enrichment   — add context (IP history, service info)
  2. Scoring      — assign threat score per event type
  3. Correlation  — detect multi-event attack patterns
  4. Decision     — emit ThreatAlert when threshold exceeded

IP-based context pool tracks cumulative threat score, failed/successful
login counts, targeted services, and recent event history per source IP.

Exports:
  ThreatEngine  — main engine class (process_event / get_ip_context / get_recent_threats)
  IPContext      — per-IP state dataclass
"""

import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

from client_helpers import log

# ── Threat Scores ─────────────────────────────────────────────────

THREAT_SCORES: Dict[str, int] = {
    # Authentication
    "successful_logon_rdp":             85,
    "successful_logon_network":         70,
    "successful_logon_sql":             80,
    "failed_logon_single":               5,
    "failed_logon_burst":               40,   # 10+ failures in 5 min
    "failed_then_success":              95,

    # Privilege escalation
    "new_user_created":                 90,
    "user_added_to_admin_group":        90,
    "privilege_assigned":               75,
    "security_group_changed":           70,

    # Persistence
    "new_service_installed":            65,
    "service_start_type_changed":       50,
    "new_process_suspicious":           55,

    # Anti-forensics
    "audit_log_cleared":               100,
    "unexpected_restart":               50,

    # SQL-specific
    "sql_successful_logon":             80,
    "sql_failed_logon":                  5,
    "xp_cmdshell_executed":            100,   # Command execution via SQL

    # RDP-specific
    "rdp_connection_succeeded":         85,
    "rdp_session_logon":                80,
    "rdp_session_reconnect":            60,

    # Honeypot-specific
    "honeypot_credential":              90,   # Anyone hitting a honeypot is malicious
}

# Correlation rule definitions
CORRELATION_RULES = [
    {
        "name": "brute_force_then_access",
        "description": "Brute force followed by successful login — account compromised!",
        "precondition": "failed_logon",
        "precondition_count": 5,
        "precondition_window": 600,          # 10 min
        "trigger": "successful_logon",
        "trigger_window": 1800,              # 30 min
        "same_ip": True,
        "score": 95,
        "severity": "critical",
        "auto_response": ["block_ip", "notify_urgent"],
    },
    {
        "name": "rdp_after_hours",
        "description": "RDP access during off-hours (00:00-06:00)",
        "precondition": None,
        "trigger": "rdp_logon",
        "time_range": (0, 6),                # midnight to 6am
        "score": 60,
        "severity": "high",
        "auto_response": ["notify_urgent"],
    },
    {
        "name": "lateral_movement",
        "description": "Successful logins to 2+ services from same IP",
        "precondition": None,
        "trigger": "multi_service_logon",
        "distinct_services": 2,
        "window": 3600,                      # 1 hour
        "score": 85,
        "severity": "critical",
        "auto_response": ["block_ip", "notify_urgent"],
    },
    {
        "name": "post_exploitation",
        "description": "New service/user creation after successful login",
        "precondition": "successful_logon",
        "precondition_count": 1,
        "precondition_window": 3600,
        "trigger": "persistence_action",     # new service OR new user
        "trigger_window": 3600,
        "same_ip": True,
        "score": 95,
        "severity": "critical",
        "auto_response": ["block_ip", "notify_urgent"],
    },
    {
        "name": "honeypot_brute_force",
        "description": "Multiple honeypot hits from same IP — active attacker",
        "precondition": None,
        "trigger": "honeypot_credential",
        "precondition_count": 3,
        "precondition_window": 600,          # 10 min
        "score": 95,
        "severity": "critical",
        "auto_response": ["block_ip", "notify_urgent"],
    },
]

# Severity thresholds for standalone events
SEVERITY_THRESHOLDS = {
    "critical": 81,
    "high":     61,
    "warning":  31,
    "info":      0,
}

# Events that qualify as "successful logon" for correlation
LOGON_EVENT_TYPES: Set[str] = {
    "successful_logon", "successful_logon_rdp", "successful_logon_network",
    "sql_successful_logon", "rdp_connection_succeeded", "rdp_session_logon",
    "explicit_credential_logon",
}

# Events that qualify as "failed logon"
FAILED_LOGON_TYPES: Set[str] = {
    "failed_logon", "sql_failed_logon",
}

# Events that qualify as "persistence action"
PERSISTENCE_TYPES: Set[str] = {
    "new_service_installed", "new_user_created", "user_added_to_admin_group",
    "service_start_type_changed",
}

# Events related to RDP
RDP_LOGON_TYPES: Set[str] = {
    "rdp_connection_succeeded", "rdp_session_logon", "rdp_session_reconnect",
    "successful_logon_rdp",
}

# Context pool cleanup interval (seconds)
CONTEXT_CLEANUP_INTERVAL = 300       # 5 min
# Max age for IP context entries without new events
CONTEXT_MAX_AGE = 86400              # 24 hours


# ── IP Context ────────────────────────────────────────────────────

@dataclass
class IPContext:
    """Per-IP accumulated threat context."""
    ip: str
    first_seen: float = 0.0
    last_seen: float = 0.0
    failed_attempts: int = 0
    successful_logins: int = 0
    services_targeted: Set[str] = field(default_factory=set)
    usernames_tried: Set[str] = field(default_factory=set)
    threat_score: float = 0.0
    events: deque = field(default_factory=lambda: deque(maxlen=100))
    is_blocked: bool = False
    alerts_sent: int = 0
    last_alert_time: float = 0.0

    def add_event(self, event: dict, score: float):
        """Record an event and update counters."""
        now = time.time()
        self.last_seen = now
        if not self.first_seen:
            self.first_seen = now

        self.threat_score = min(100.0, self.threat_score + score)
        self.events.append({
            "event_type": event.get("event_type", ""),
            "event_id": event.get("event_id", 0),
            "timestamp": now,
            "score": score,
        })

        # Update counters
        etype = event.get("event_type", "")
        if etype in FAILED_LOGON_TYPES or etype == "failed_logon_single":
            self.failed_attempts += 1
        if etype in LOGON_EVENT_TYPES:
            self.successful_logins += 1

        svc = event.get("target_service", "") or event.get("service", "")
        if svc:
            self.services_targeted.add(svc)

        uname = event.get("username", "")
        if uname:
            self.usernames_tried.add(uname)

    def get_recent_events(self, window_seconds: int) -> List[dict]:
        """Get events within the last N seconds."""
        cutoff = time.time() - window_seconds
        return [e for e in self.events if e["timestamp"] >= cutoff]

    def decay_score(self, amount: float = 1.0):
        """Reduce threat score over time (called periodically)."""
        self.threat_score = max(0.0, self.threat_score - amount)


# ── Threat Engine ─────────────────────────────────────────────────

class ThreatEngine:
    """
    Stateful threat detection engine.

    Usage:
        engine = ThreatEngine(on_alert=alert_pipeline.handle_alert)
        engine.start()  # starts housekeeping thread
        # ... events fed via process_event() from EventLogWatcher ...
        engine.stop()
    """

    def __init__(self, on_alert: Optional[Callable] = None):
        """
        Args:
            on_alert:  Callback receiving (alert_dict, ip_context) when threshold hit.
        """
        self.on_alert = on_alert
        self._ip_pool: Dict[str, IPContext] = {}
        self._lock = threading.Lock()
        self._running = False
        self._housekeeping_thread: Optional[threading.Thread] = None

        # Stats
        self._stats = {
            "events_scored": 0,
            "alerts_generated": 0,
            "correlations_matched": 0,
            "active_ips": 0,
            "highest_threat_ip": "",
            "highest_threat_score": 0,
        }

    # ── Public API ────────────────────────────────────────────────

    def start(self):
        """Start the housekeeping (cleanup + score decay) thread."""
        if self._running:
            return
        self._running = True
        self._housekeeping_thread = threading.Thread(
            target=self._housekeeping_loop,
            name="ThreatEngine-Housekeeping",
            daemon=True,
        )
        self._housekeeping_thread.start()
        log("[THREAT] 🚀 Threat engine started")

    def stop(self):
        """Stop the housekeeping thread."""
        self._running = False
        log("[THREAT] Stopped")

    def process_event(self, event: dict):
        """
        Main entry point — called by EventLogWatcher for each parsed event.

        1. Classify & score the event
        2. Update IP context
        3. Run correlation rules
        4. Emit alert if threshold met
        """
        try:
            source_ip = event.get("source_ip", "")
            event_type = event.get("event_type", "")

            if not event_type:
                return

            # 1. Score the event
            score = self._calculate_score(event)

            # 2. Update IP context (even for events without IP, use "local")
            ip_key = source_ip if source_ip else "local"

            with self._lock:
                if ip_key not in self._ip_pool:
                    self._ip_pool[ip_key] = IPContext(ip=ip_key)
                ctx = self._ip_pool[ip_key]
                ctx.add_event(event, score)

            self._stats["events_scored"] += 1

            # 3. Correlation rules
            correlation_match = self._check_correlations(ip_key, ctx, event)

            # 4. Alert decision
            if correlation_match:
                self._emit_alert(
                    event=event,
                    ctx=ctx,
                    score=correlation_match["score"],
                    severity=correlation_match["severity"],
                    rule_name=correlation_match["name"],
                    description=correlation_match["description"],
                    auto_response=correlation_match.get("auto_response", []),
                )
            elif score >= SEVERITY_THRESHOLDS["warning"]:
                severity = self._score_to_severity(ctx.threat_score)
                # Honeypot credential veya critical skor → anında IP blokla
                standalone_auto_response = []
                if event_type == "honeypot_credential" or severity == "critical":
                    standalone_auto_response = ["block_ip", "notify_urgent"]
                self._emit_alert(
                    event=event,
                    ctx=ctx,
                    score=score,
                    severity=severity,
                    rule_name="",
                    description=f"{event_type} detected from {ip_key}",
                    auto_response=standalone_auto_response,
                )

            # Update stats
            self._update_stats()

        except Exception as e:
            log(f"[THREAT] process_event error: {e}")

    def get_ip_context(self, ip: str) -> Optional[IPContext]:
        """Get threat context for a specific IP."""
        with self._lock:
            return self._ip_pool.get(ip)

    def get_all_contexts(self) -> Dict[str, IPContext]:
        """Get all IP contexts (copy)."""
        with self._lock:
            return dict(self._ip_pool)

    def get_recent_threats(self, max_age_seconds: int = 60,
                           min_score: int = 70) -> List[dict]:
        """
        Get IPs with active threats in the last N seconds.
        Used by Safe Last Breath mechanism.
        """
        cutoff = time.time() - max_age_seconds
        threats = []
        with self._lock:
            for ip, ctx in self._ip_pool.items():
                if ip == "local":
                    continue
                if ctx.last_seen >= cutoff and ctx.threat_score >= min_score:
                    threats.append({
                        "ip": ctx.ip,
                        "threat_score": ctx.threat_score,
                        "last_seen": ctx.last_seen,
                        "failed_attempts": ctx.failed_attempts,
                        "successful_logins": ctx.successful_logins,
                        "services": list(ctx.services_targeted),
                    })
        return sorted(threats, key=lambda t: t["threat_score"], reverse=True)

    def get_stats(self) -> dict:
        """Return engine statistics."""
        stats = dict(self._stats)
        with self._lock:
            stats["active_ips"] = len(self._ip_pool)
        return stats

    def get_threat_level(self) -> Tuple[str, str]:
        """
        Return overall threat level for the dashboard.
        Returns: (level, color) — e.g. ("CRITICAL", "#FF4444")
        """
        with self._lock:
            if not self._ip_pool:
                return ("SAFE", "#2ECC71")
            max_score = max(
                (ctx.threat_score for ctx in self._ip_pool.values()),
                default=0
            )
        if max_score >= 81:
            return ("CRITICAL", "#FF4444")
        elif max_score >= 61:
            return ("HIGH", "#FF8C00")
        elif max_score >= 31:
            return ("WARNING", "#FFD700")
        else:
            return ("SAFE", "#2ECC71")

    # ── Scoring ───────────────────────────────────────────────────

    def _calculate_score(self, event: dict) -> float:
        """Calculate threat score for a single event."""
        event_type = event.get("event_type", "")
        logon_type = event.get("logon_type")
        target_service = event.get("target_service", "")

        # Refine event type for RDP/network logons
        score_key = event_type
        if event_type == "successful_logon" and logon_type is not None:
            if logon_type == 10:
                score_key = "successful_logon_rdp"
            elif logon_type == 3:
                score_key = "successful_logon_network"
        elif event_type == "successful_logon" and target_service == "MSSQL":
            score_key = "sql_successful_logon"
        elif event_type == "failed_logon":
            score_key = "failed_logon_single"
        elif event_type == "sql_failed_logon":
            score_key = "sql_failed_logon"

        base_score = THREAT_SCORES.get(score_key, 0)

        # Check for burst (brute force) — failed logon burst multiplier
        if event_type in FAILED_LOGON_TYPES:
            source_ip = event.get("source_ip", "")
            if source_ip:
                with self._lock:
                    ctx = self._ip_pool.get(source_ip)
                    if ctx:
                        recent_failures = sum(
                            1 for e in ctx.get_recent_events(300)
                            if e["event_type"] in FAILED_LOGON_TYPES
                        )
                        if recent_failures >= 10:
                            base_score = THREAT_SCORES.get("failed_logon_burst", 40)

        # Check for failed-then-success pattern
        if event_type in LOGON_EVENT_TYPES:
            source_ip = event.get("source_ip", "")
            if source_ip:
                with self._lock:
                    ctx = self._ip_pool.get(source_ip)
                    if ctx and ctx.failed_attempts >= 3:
                        base_score = max(base_score,
                                         THREAT_SCORES.get("failed_then_success", 95))

        return float(base_score)

    # ── Correlation ───────────────────────────────────────────────

    def _check_correlations(self, ip: str, ctx: IPContext,
                            event: dict) -> Optional[dict]:
        """Run correlation rules against the current IP context."""
        event_type = event.get("event_type", "")

        for rule in CORRELATION_RULES:
            try:
                matched = self._evaluate_rule(rule, ip, ctx, event, event_type)
                if matched:
                    self._stats["correlations_matched"] += 1
                    log(f"[THREAT] 🎯 Correlation: {rule['name']} — IP: {ip}")
                    return rule
            except Exception as e:
                log(f"[THREAT] Correlation rule error ({rule['name']}): {e}")

        return None

    def _evaluate_rule(self, rule: dict, ip: str, ctx: IPContext,
                       event: dict, event_type: str) -> bool:
        """Evaluate a single correlation rule."""

        # ── rdp_after_hours ───────────────────────────────────────
        if rule["name"] == "rdp_after_hours":
            if event_type in RDP_LOGON_TYPES or (
                event_type in LOGON_EVENT_TYPES and
                event.get("target_service") == "RDP"
            ):
                hour = time.localtime().tm_hour
                start, end = rule.get("time_range", (0, 6))
                return start <= hour < end
            return False

        # ── brute_force_then_access ───────────────────────────────
        if rule["name"] == "brute_force_then_access":
            if event_type not in LOGON_EVENT_TYPES:
                return False
            window = rule.get("precondition_window", 600)
            required = rule.get("precondition_count", 5)
            recent = ctx.get_recent_events(window)
            fail_count = sum(
                1 for e in recent
                if e["event_type"] in FAILED_LOGON_TYPES
            )
            return fail_count >= required

        # ── lateral_movement ──────────────────────────────────────
        if rule["name"] == "lateral_movement":
            if event_type not in LOGON_EVENT_TYPES:
                return False
            required = rule.get("distinct_services", 2)
            return len(ctx.services_targeted) >= required

        # ── post_exploitation ─────────────────────────────────────
        if rule["name"] == "post_exploitation":
            if event_type not in PERSISTENCE_TYPES:
                return False
            # Check if there was a successful logon from this IP recently
            window = rule.get("trigger_window", 3600)
            recent = ctx.get_recent_events(window)
            has_logon = any(
                e["event_type"] in LOGON_EVENT_TYPES for e in recent
            )
            return has_logon

        # ── honeypot_brute_force ──────────────────────────────────
        if rule["name"] == "honeypot_brute_force":
            if event_type != "honeypot_credential":
                return False
            window = rule.get("precondition_window", 600)
            required = rule.get("precondition_count", 3)
            recent = ctx.get_recent_events(window)
            hp_count = sum(
                1 for e in recent
                if e["event_type"] == "honeypot_credential"
            )
            return hp_count >= required

        return False

    # ── Alert Emission ────────────────────────────────────────────

    def _emit_alert(self, event: dict, ctx: IPContext, score: float,
                    severity: str, rule_name: str, description: str,
                    auto_response: List[str]):
        """Build alert dict and forward to alert pipeline callback."""

        # Rate limiting — don't spam for same IP/type
        now = time.time()
        cooldowns = {"critical": 60, "high": 300, "warning": 900, "info": 3600}
        cooldown = cooldowns.get(severity, 300)
        if now - ctx.last_alert_time < cooldown:
            return

        ctx.last_alert_time = now
        ctx.alerts_sent += 1
        self._stats["alerts_generated"] += 1

        alert = {
            "alert_id": str(uuid.uuid4()),
            "timestamp": now,
            "severity": severity,
            "threat_type": event.get("event_type", ""),
            "title": self._build_title(event, rule_name),
            "description": description,
            "source_ip": ctx.ip,
            "target_service": event.get("target_service", "") or event.get("service", ""),
            "target_port": event.get("target_port", 0) or event.get("port", 0),
            "username": event.get("username", ""),
            "threat_score": int(ctx.threat_score),
            "event_ids": [event.get("event_id", 0)],
            "correlation_rule": rule_name,
            "recommended_action": self._recommend_action(severity, rule_name),
            "auto_response": auto_response,
            "ip_context": {
                "failed_attempts": ctx.failed_attempts,
                "successful_logins": ctx.successful_logins,
                "services": list(ctx.services_targeted),
                "usernames": list(ctx.usernames_tried)[:10],
            },
        }

        log(f"[THREAT] 🚨 Alert [{severity.upper()}] "
            f"{alert['title']} — IP: {ctx.ip} — Score: {int(ctx.threat_score)}")

        if self.on_alert:
            try:
                self.on_alert(alert)
            except Exception as e:
                log(f"[THREAT] Alert callback error: {e}")

    @staticmethod
    def _build_title(event: dict, rule_name: str) -> str:
        """Build a human-readable alert title."""
        if rule_name:
            titles = {
                "brute_force_then_access": "🔓 Brute Force → Successful Login",
                "rdp_after_hours":         "🌙 RDP Access After Hours",
                "lateral_movement":        "🕸️ Lateral Movement Detected",
                "post_exploitation":       "💀 Post-Exploitation Activity",
            }
            return titles.get(rule_name, f"⚠️ Correlation: {rule_name}")

        etype = event.get("event_type", "")
        titles = {
            "audit_log_cleared":         "🗑️ Audit Log Cleared",
            "xp_cmdshell_executed":      "💉 xp_cmdshell Executed (SQL Injection)",
            "new_user_created":          "👤 New User Account Created",
            "user_added_to_admin_group": "⬆️ User Added to Admin Group",
            "successful_logon_rdp":      "🖥️ RDP Successful Login",
            "successful_logon":          "🔐 Successful Login",
            "failed_logon_burst":        "🔨 Brute Force Attack Detected",
            "new_service_installed":     "⚙️ New Service Installed",
            "rdp_connection_succeeded":  "🖥️ RDP Connection Established",
            "sql_successful_logon":      "🗄️ SQL Successful Login",
            "honeypot_credential":       "🍯 Honeypot Credential Captured",
        }
        return titles.get(etype, f"⚠️ {etype.replace('_', ' ').title()}")

    @staticmethod
    def _recommend_action(severity: str, rule_name: str) -> str:
        """Return recommended action text."""
        if rule_name == "brute_force_then_access":
            return "Block IP immediately, review compromised account, check for lateral movement"
        if rule_name == "post_exploitation":
            return "Block IP, isolate system, review installed services and user accounts"
        if rule_name == "lateral_movement":
            return "Block IP, audit all sessions from this IP across services"
        if severity == "critical":
            return "Investigate immediately — potential active compromise"
        if severity == "high":
            return "Review within 15 minutes — suspicious activity"
        return "Monitor and review during next assessment"

    @staticmethod
    def _score_to_severity(score: float) -> str:
        """Convert numeric score to severity string."""
        if score >= 81:
            return "critical"
        elif score >= 61:
            return "high"
        elif score >= 31:
            return "warning"
        return "info"

    # ── Housekeeping ──────────────────────────────────────────────

    def _housekeeping_loop(self):
        """Periodic cleanup: remove stale IPs, decay scores."""
        while self._running:
            try:
                self._cleanup_stale_contexts()
                self._decay_scores()
            except Exception as e:
                log(f"[THREAT] Housekeeping error: {e}")
            time.sleep(CONTEXT_CLEANUP_INTERVAL)

    def _cleanup_stale_contexts(self):
        """Remove IP contexts that haven't had activity in 24h."""
        cutoff = time.time() - CONTEXT_MAX_AGE
        with self._lock:
            stale_ips = [
                ip for ip, ctx in self._ip_pool.items()
                if ctx.last_seen < cutoff and not ctx.is_blocked
            ]
            for ip in stale_ips:
                del self._ip_pool[ip]
            if stale_ips:
                log(f"[THREAT] Cleaned up {len(stale_ips)} stale IP contexts")

    def _decay_scores(self):
        """Gradually reduce threat scores over time."""
        with self._lock:
            for ctx in self._ip_pool.values():
                # Decay 1 point per cleanup interval for non-blocked IPs
                if not ctx.is_blocked and ctx.threat_score > 0:
                    ctx.decay_score(1.0)

    def _update_stats(self):
        """Update highest-threat stats."""
        with self._lock:
            if self._ip_pool:
                top_ip = max(
                    self._ip_pool.values(),
                    key=lambda c: c.threat_score,
                    default=None,
                )
                if top_ip:
                    self._stats["highest_threat_ip"] = top_ip.ip
                    self._stats["highest_threat_score"] = int(top_ip.threat_score)
