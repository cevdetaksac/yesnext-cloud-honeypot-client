# -*- coding: utf-8 -*-
"""
Cloud Honeypot Client - API Management Module

Bu modül, Cloud Honeypot sunucusu ile olan tüm API iletişimini yönetir.
İstemci kaydı, IP güncellemeleri, heartbeat gönderimi, servis durumu raporlama,
saldırı bildirim (credential capture) ve saldırı sayısı sorgulama işlemlerini
merkezileştirir.

Sınıflar:
    - HoneypotAPIClient: API ile etkileşim kurmak için ana sınıf.

Fonksiyonlar:
    - api_request_with_token: Token ile API isteği wrapper.
    - report_service_action_api: Servis eylemlerini raporlar.
"""

# Import constants for timeout values
try:
    from client_constants import API_REQUEST_TIMEOUT
except ImportError:
    API_REQUEST_TIMEOUT = 8

import json
import requests
import time
from typing import Dict, Optional, Any, Union
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# SSL uyarılarını gizle
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class HoneypotAPIClient:
    """Honeypot API bağlantı yönetimi sınıfı"""
    
    def __init__(self, base_url: str, log_func=None):
        self.base_url = base_url.rstrip('/')
        self.session = self._create_session()
        self.log = log_func if log_func else print
        
    def _create_session(self) -> requests.Session:
        """HTTP session oluştur"""
        session = requests.Session()
        
        # Retry stratejisi
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "OPTIONS"],
            backoff_factor=1
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Default headers
        session.headers.update({
            'User-Agent': 'Cloud-Honeypot-Client/1.0',
            'Content-Type': 'application/json'
        })
        
        return session
    
    def api_request(self, method: str, endpoint: str, data: Optional[Dict] = None,
                   params: Optional[Dict] = None, timeout: int = API_REQUEST_TIMEOUT, verbose_logging: bool = True) -> Optional[Dict]:
        """API isteği gönder"""
        try:
            url = f"{self.base_url}/{endpoint.lstrip('/')}"
            
            # Sık çağrılan endpointler için sessiz mod
            from client_constants import VERBOSE_LOGGING
            is_frequent_endpoint = endpoint in ['attack-count', 'agent/heartbeat', 'agent/service-status']
            show_logs = (verbose_logging or VERBOSE_LOGGING) and not is_frequent_endpoint
            
            if show_logs:
                self.log(f"[API] {method.upper()} isteği: {url}")
            
            if params and show_logs:
                self.log(f"[API] Params: {params}")
            
            if data and show_logs:
                self.log(f"[API] JSON: {data}")
            
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                params=params,
                timeout=timeout,
                verify=False
            )
            
            if show_logs or response.status_code != 200:
                self.log(f"[API] Yanıt: HTTP {response.status_code}")
            
            if response.status_code == 200:
                result = response.json()
                if show_logs:
                    self.log(f"[API] Başarılı yanıt: {result}")
                return result
            else:
                self.log(f"[API] Hata yanıtı: {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            self.log(f"[API] İstek hatası: {e}")
            return None
        except json.JSONDecodeError as e:
            self.log(f"[API] JSON parse hatası: {e}")
            return None
        except Exception as e:
            self.log(f"[API] Beklenmeyen hata: {e}")
            return None

    def register_client(self, server_name: str, ip_address: str) -> Optional[str]:
        """İstemciyi API'ye kaydeder ve bir token alır."""
        try:
            payload = {"server_name": server_name, "ip": ip_address}
            response = self.api_request("POST", "register", data=payload)
            if response and "token" in response:
                token = response["token"]
                self.log(f"İstemci başarıyla kaydedildi, token alındı: {token[:8]}...")
                return token
            self.log("İstemci kaydı başarısız oldu veya token alınamadı.")
            return None
        except Exception as e:
            self.log(f"[API] İstemci kaydı sırasında hata: {e}")
            return None

    def update_client_ip(self, token: str, new_ip: str) -> bool:
        """İstemcinin genel IP adresini API'de günceller."""
        try:
            payload = {"token": token, "ip": new_ip}
            response = self.api_request("POST", "update-ip", data=payload)
            if response:
                self.log(f"IP adresi başarıyla güncellendi: {new_ip}")
                return True
            self.log(f"IP adresi güncellemesi başarısız oldu.")
            return False
        except Exception as e:
            self.log(f"[API] IP güncelleme hatası: {e}")
            return False

    def send_heartbeat(self, token: str, ip: str, hostname: str, running: bool, status: str,
                        system_context: dict = None) -> bool:
        """API'ye zengin heartbeat sinyali gönderir.
        
        Args:
            token: Client authentication token
            ip: Public IP address
            hostname: Server hostname
            running: Whether the client is running
            status: Status string (online/idle/offline)
            system_context: Optional dict with rich system info:
                agent_version, os_info, uptime_hours, cpu_percent, memory_percent,
                active_services, threat_level, blocked_ips, total_attacks, etc.
        """
        try:
            payload = {
                "token": token, "ip": ip, "hostname": hostname,
                "running": running, "status": status
            }
            # Merge rich system context if provided
            if system_context:
                payload["system_context"] = system_context
            response = self.api_request("POST", "heartbeat", data=payload)
            return response is not None
        except Exception as e:
            self.log(f"[API] Heartbeat gönderme hatası: {e}")
            return False

    def report_open_ports(self, token: str, ports: list) -> bool:
        """İstemcideki açık portları API'ye raporlar."""
        try:
            payload = {"token": token, "ports": ports}
            response = self.api_request("POST", "agent/open-ports", data=payload)
            return response is not None
        except Exception as e:
            self.log(f"[API] Açık portları raporlama hatası: {e}")
            return False

    def report_service_action(self, token: str, service: str, action: str, port: Optional[int] = None) -> bool:
        """Bir servis eylemini (başlatma/durdurma) API'ye bildirir."""
        try:
            payload = {
                "token": token,
                "service": str(service or "").upper(),
                "action": "start" if action == "start" else "stop",
            }
            if port and str(port) != '-':
                payload["port"] = int(str(port))

            response = self.api_request("POST", "premium/tunnel-set", data=payload)
            if isinstance(response, dict) and response.get("status") in ("queued", "ok", "success"):
                self.log(f"Servis eylemi bildirildi: {payload}")
                return True
            
            self.log(f"Servis eylemi bildirimi başarısız: {response}")
            return False
        except Exception as e:
            self.log(f"Servis eylemi raporlama hatası: {e}")
            return False
    
    def check_connection(self, max_attempts: int = 5, delay: int = 5) -> bool:
        """API bağlantısını kontrol et - orijinal try_api_connection mantığına uygun"""
        for attempt in range(1, max_attempts + 1):
            self.log(f"[API] Bağlantı kontrol denemesi {attempt}/{max_attempts}")
            
            try:
                # Strip any trailing slash from base_url (orijinal koddan)
                base_url = self.base_url.rstrip('/')
                health_url = f"{base_url.rsplit('/api', 1)[0]}/healthz"
                self.log(f"Checking API health at {health_url}...")
                
                response = self.session.get(
                    health_url,
                    timeout=15,  # Orijinal kodda 15 saniye
                    verify=False
                )
                
                if response.status_code == 200:
                    try:
                        health_data = response.json()
                        if health_data.get("status") == "ok":
                            client_count = health_data.get("clients", 0)
                            self.log(f"API connection successful - {client_count} clients registered")
                            return True
                    except ValueError:
                        self.log("API health check succeeded but returned invalid JSON")
                
                if response.status_code in [401, 403]:  # API çalışıyor ama token gerekiyor
                    self.log("API connection successful but requires authentication")
                    return True
                    
                self.log(f"API connection failed: HTTP {response.status_code}")
                    
            except Exception as e:
                self.log(f"[API] Bağlantı denemesi {attempt} başarısız: {e}")
            
            if attempt < max_attempts:
                self.log(f"[API] {delay} saniye bekleyip tekrar deneniyor...")
                time.sleep(delay)
        
        self.log("[API] Bağlantı kurulamadı!")
        return False
    
    def get_service_statuses(self, token: str) -> Optional[Dict]:
        """Servis durumlarını al"""
        try:
            params = {'token': token}
            return self.api_request('GET', 'premium/tunnel-status', params=params)
        except Exception as e:
            self.log(f"[API] Servis durumu alma hatası: {e}")
            return None
    
    def update_service_statuses(self, token: str, statuses: list) -> bool:
        """Servis durumlarını güncelle"""
        try:
            data = {
                'token': token,
                'statuses': statuses
            }
            result = self.api_request('POST', 'agent/tunnel-status', data=data)
            return result is not None
        except Exception as e:
            self.log(f"[API] Servis durumu güncelleme hatası: {e}")
            return False
    
    def report_attack(self, token: str, attacker_ip: str, target_ip: str,
                       username: str, password: str, service: str, port: int) -> bool:
        """Yakalanan saldırı (credential) bilgisini API'ye raporlar.
        
        Args:
            token: Client authentication token
            attacker_ip: Saldırganın IP adresi
            target_ip: Hedef (yerel) IP adresi
            username: Yakalanan kullanıcı adı
            password: Yakalanan şifre
            service: Servis türü (RDP, SSH, FTP, MYSQL, MSSQL)
            port: Hedef port numarası
            
        Returns:
            bool: Raporlama başarılı ise True
        """
        try:
            from client_constants import MAX_CREDENTIAL_LENGTH
            # Truncate credentials to max length
            username = str(username or "")[:MAX_CREDENTIAL_LENGTH]
            password = str(password or "")[:MAX_CREDENTIAL_LENGTH]
            
            payload = {
                "token": token,
                "attacker_ip": attacker_ip,
                "target_ip": target_ip,
                "username": username,
                "password": password,
                "service": str(service or "").upper(),
                "port": int(port),
            }
            response = self.api_request("POST", "attack", data=payload)
            if isinstance(response, dict) and response.get("status") in ("ok", "success", "created"):
                self.log(f"[API] Saldırı raporlandı: {service}:{port} <- {attacker_ip}")
                return True
            
            self.log(f"[API] Saldırı raporlama başarısız: {response}")
            return False
        except Exception as e:
            self.log(f"[API] Saldırı raporlama hatası: {e}")
            return False
    
    def report_attack_batch(self, token: str, attacks: list) -> bool:
        """Birden fazla saldırıyı toplu olarak raporlar.
        
        Args:
            token: Client authentication token
            attacks: Liste of attack dicts with keys:
                     attacker_ip, target_ip, username, password, service, port
        Returns:
            bool: Raporlama başarılı ise True
        """
        try:
            from client_constants import MAX_CREDENTIAL_LENGTH
            sanitized = []
            for atk in attacks:
                sanitized.append({
                    "attacker_ip": atk.get("attacker_ip", ""),
                    "target_ip": atk.get("target_ip", ""),
                    "username": str(atk.get("username", ""))[:MAX_CREDENTIAL_LENGTH],
                    "password": str(atk.get("password", ""))[:MAX_CREDENTIAL_LENGTH],
                    "service": str(atk.get("service", "")).upper(),
                    "port": int(atk.get("port", 0)),
                })
            
            payload = {"token": token, "attacks": sanitized}
            response = self.api_request("POST", "attacks/batch", data=payload)
            if isinstance(response, dict) and response.get("status") in ("ok", "success", "created"):
                self.log(f"[API] {len(sanitized)} saldırı toplu raporlandı")
                return True
            
            self.log(f"[API] Toplu saldırı raporlama başarısız: {response}")
            return False
        except Exception as e:
            self.log(f"[API] Toplu saldırı raporlama hatası: {e}")
            return False

    def get_attack_count(self, token: str) -> Optional[int]:
        """Saldırı sayısını al"""
        try:
            params = {'token': token}
            result = self.api_request('GET', 'attack-count', params=params, verbose_logging=False)
            
            if result and 'count' in result:
                count = int(result['count'])
                return count
            
            return None
        except Exception as e:
            self.log(f"[API] Saldırı sayısı alma hatası: {e}")
            return None

    # ===================== THREAT DETECTION v4.0 — Faz 2 ===================== #

    def report_auto_block(self, token: str, data: dict) -> bool:
        """POST /api/alerts/auto-block — Otomatik engelleme bildirimi"""
        try:
            payload = {"token": token, **data}
            resp = self.api_request("POST", "alerts/auto-block", data=payload)
            return isinstance(resp, dict) and resp.get("status") in ("ok", "success", "created")
        except Exception as e:
            self.log(f"[API] auto-block report error: {e}")
            return False

    def fetch_pending_commands(self, token: str) -> list:
        """GET /api/commands/pending — Bekleyen uzak komutları çek"""
        try:
            resp = self.api_request(
                "GET", "commands/pending",
                params={"token": token},
                timeout=8, verbose_logging=False,
            )
            if isinstance(resp, dict):
                return resp.get("commands", [])
            return []
        except Exception as e:
            self.log(f"[API] fetch pending commands error: {e}")
            return []

    def report_command_result(self, token: str, command_id: str, status: str,
                              result: dict) -> bool:
        """POST /api/commands/result — Komut sonucunu raporla"""
        try:
            from datetime import datetime, timezone
            payload = {
                "token": token,
                "command_id": command_id,
                "status": status,
                "result": result,
                "executed_at": datetime.now(timezone.utc).isoformat(),
            }
            resp = self.api_request("POST", "commands/result", data=payload)
            return isinstance(resp, dict) and resp.get("status") in ("ok", "success")
        except Exception as e:
            self.log(f"[API] command result report error: {e}")
            return False

    def fetch_threat_config(self, token: str) -> Optional[Dict]:
        """GET /api/threats/config — Tehdit algılama + sessiz saat konfigürasyonu"""
        try:
            resp = self.api_request(
                "GET", "threats/config",
                params={"token": token},
                timeout=8, verbose_logging=False,
            )
            if isinstance(resp, dict):
                return resp
            return None
        except Exception as e:
            self.log(f"[API] fetch threat config error: {e}")
            return None

    def report_silent_hours_event(self, token: str, data: dict) -> bool:
        """POST /api/alerts/silent-hours — Sessiz saat ihlali bildirimi"""
        try:
            payload = {"token": token, **data}
            resp = self.api_request("POST", "alerts/silent-hours", data=payload)
            return isinstance(resp, dict) and resp.get("status") in ("ok", "success", "created")
        except Exception as e:
            self.log(f"[API] silent hours event report error: {e}")
            return False

    # ───────── Faz 3  ─  System Health ─────────
    def report_health(self, token: str, snapshot: dict) -> bool:
        """POST /api/health/report — Sistem sağlık raporu gönder"""
        try:
            payload = {"token": token, **snapshot}
            resp = self.api_request("POST", "health/report", data=payload)
            return isinstance(resp, dict) and resp.get("status") in ("ok", "success", "created")
        except Exception as e:
            self.log(f"[API] health report error: {e}")
            return False

    def report_ransomware_event(self, token: str, data: dict) -> bool:
        """POST /api/alerts/ransomware — Ransomware algılama bildirimi"""
        try:
            payload = {"token": token, **data}
            resp = self.api_request("POST", "alerts/ransomware", data=payload)
            return isinstance(resp, dict) and resp.get("status") in ("ok", "success", "created")
        except Exception as e:
            self.log(f"[API] ransomware event report error: {e}")
            return False

    def report_self_protection_event(self, token: str, data: dict) -> bool:
        """POST /api/alerts/self-protection — Self-protection olay bildirimi"""
        try:
            payload = {"token": token, **data}
            resp = self.api_request("POST", "alerts/self-protection", data=payload)
            return isinstance(resp, dict) and resp.get("status") in ("ok", "success", "created")
        except Exception as e:
            self.log(f"[API] self-protection event report error: {e}")
            return False

    # ───────── Faz 4  ─  Threat Summary + Notification Preferences ─────────
    def fetch_threat_summary(self, token: str, period: str = "24h") -> Optional[Dict]:
        """GET /api/threats/summary — Tehdit özeti çek"""
        try:
            resp = self.api_request(
                "GET", "threats/summary",
                params={"token": token, "period": period},
            )
            return resp if isinstance(resp, dict) else None
        except Exception as e:
            self.log(f"[API] threat summary fetch error: {e}")
            return None

    def update_notification_preferences(self, token: str, prefs: dict) -> bool:
        """PUT /api/notifications/preferences — Bildirim tercihleri güncelle"""
        try:
            payload = {"token": token, **prefs}
            resp = self.api_request("PUT", "notifications/preferences", data=payload)
            return isinstance(resp, dict) and resp.get("status") in ("ok", "success", "updated")
        except Exception as e:
            self.log(f"[API] notification preferences update error: {e}")
            return False

    def report_events_batch(self, token: str, events: list) -> bool:
        """POST /api/events/batch — Toplu olay gönderimi (trend analizi için)"""
        try:
            payload = {"token": token, "events": events}
            resp = self.api_request("POST", "events/batch", data=payload)
            return isinstance(resp, dict) and resp.get("status") in ("ok", "success", "received")
        except Exception as e:
            self.log(f"[API] events batch report error: {e}")
            return False

# ===================== API WRAPPER FUNCTIONS ===================== #
# Purpose: High-level API request functions for client integration

def api_request_with_token(api_client, token: str, method: str, endpoint: str, 
                          data: Optional[Dict] = None, params: Optional[Dict] = None, timeout: int = API_REQUEST_TIMEOUT, 
                          json: Optional[Dict] = None) -> Optional[Dict]:
    """API request wrapper with token authentication"""
    try:
        if token:
            params = params or {}
            params['token'] = token
        
        return api_client.api_request(
            method=method, endpoint=endpoint,
            data=json if json else data, params=params, timeout=timeout
        )
    except Exception as e:
        if hasattr(api_client, 'log') and api_client.log:
            api_client.log(f"[API] Wrapper hatası: {e}")
        return None

# ===================== SERVICE ACTION REPORTING ===================== #
# Purpose: Report service state changes to honeypot server

def report_service_action_api(api_request_func, token: str, service: str, action: str,
                           port: Optional[Union[str, int]] = None, log_func=None) -> bool:
    """Report service action to API using provided api_request function"""
    try:
        if not token:
            if log_func: log_func("Token yok; eylem bildirilemedi")
            return False

        payload: Dict[str, Any] = {
            "token": token,
            "service": str(service or "").upper(),
            "action": action if action in ("start", "stop") else "stop",
        }
        if port and str(port) != '-':
            payload["port"] = int(str(port))

        resp = api_request_func("POST", "premium/tunnel-set", json=payload)
        if isinstance(resp, dict) and resp.get("status") in ("queued", "ok", "success"):
            if log_func: log_func(f"Servis eylemi bildirildi: {payload}")
            return True

        if log_func: log_func(f"Servis eylemi bildirimi başarısız: {resp}")
        return False
    except Exception as e:
        if log_func: log_func(f"Servis eylemi raporlanırken hata: {e}")
        return False

# ===================== CLIENT REGISTRATION ===================== #

def register_client_api(api_url: str, server_name: str, ip: str, token_save_func=None, log_func=None) -> Optional[str]:
    """Register client with API and get token"""
    import requests
    
    try:
        payload = {"server_name": f"{server_name} ({ip})", "ip": ip}
        response = requests.post(f"{api_url}/register", json=payload, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            token = data.get("token")
            if token:
                if token_save_func:
                    token_save_func(token)
                if log_func: log_func(f"Client registration successful: {server_name}")
                return token
        
        if log_func: log_func(f"Registration failed: HTTP {response.status_code}")
        return None
            
    except Exception as e:
        if log_func: log_func(f"Registration error: {e}")
        return None
