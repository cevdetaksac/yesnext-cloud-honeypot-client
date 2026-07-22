# P1 Security & Resilience — Client implementation record

> Date: 2026-07-22  
> Contract baseline: 1.4.6  
> Production floor: client 4.9.0 (unchanged)  
> Policy: observe-only/default-off until cloud enables dashboard consume + flags.

## Landed client surfaces

| Work item | Client surface | Default / invariant |
|---|---|---|
| RES-103 | `client_resilience_p1.make_heartbeat_proof` / `verify_heartbeat_proof` | Candidate HMAC heartbeat proof + local verify; default off, no Guardian reject-stale |
| RES-105/106 | `client_resilience_p1.acl_drift_status` | DACL fingerprint only; no ACL mutation, raw principals never uploaded |
| RANS-302/303 | `client_etw_shadow.sample().correlation` | Dropped/restart/buffer health + bounded fan-out/rename/write correlation; optional named `psutil` fallback (`etw_psutil_fallback`); shadow only |
| DEC-201/202 | `RansomwareShield.get_stats().canary_coverage` + health `canary_coverage` | Counts only; Desktop forbidden; on `health/report` |
| DEC-205/206/208/209 | `BaseHoneypot.get_health` → snapshot `deception_health[]` | Existing handler/rate/backlog budgets; static profile honestly reported |
| NET-501/502 | `plan_network_restore`, `load_baseline_version`, `dry_run`, `rollback_version` | Signed baseline required; destructive restore remains confirm-gated |
| OOB-501 | `client_offline_queue` + alert spool/drain | DPAPI + HMAC queue; `security.offline_urgent_queue` default **off**; drain via `alerts/urgent/batch` |
| ID-402/403 | `PasswordBurstCorrelator` | Aggregate health only; no password/raw event retention; auto lockout false |
| ZT-602/603 | `client_operator_keys.fetch_keyset` | Polls observe stub; `security.operator_keys_observe` default off; verify always false |
| ZT-605b | Test matrix below | No TLS bypass or covert fallback |
| DEV-601 | `client_device_identity.probe_tpm` | Read-only capability; no key generation/enrollment/hardware lock |

## Contract gates still required

Schemas for the observe blocks below are **promoted in contract 1.4.5+**
(additive; missing = legacy). These remain deliberately **not** production
enforcement:

1. heartbeat proof cloud verify / Guardian reject-stale / coverage metrics;
2. ACL auto-repair and SACL mutation;
3. ETW detection batch ingest beyond health aggregates + 4723/4724 burst
   **alert** payload (counts already on health);
4. Enable `security.offline_urgent_queue` only after normative `api/` promote
   + green ACK acceptance (wiring exists, flag default off);
5. Enable operator verify only after algorithm + test vectors (poll stub OK);
6. TPM enrollment/attestation/rotation.

## ZT-605b transport threat matrix

| Scenario | Expected client behavior | Acceptance evidence |
|---|---|---|
| Valid public CA + hostname | Connect | normal API/WS integration test |
| Expired/wrong-host cert | Reject | TLS unit/integration failure |
| Passive packet capture | No token/params plaintext | capture review |
| Enterprise TLS interception, untrusted CA | Reject | isolated trust-store test |
| Enterprise TLS interception, explicitly trusted system CA | Connect per OS policy; dashboard warns/policy records interception risk | managed lab test |
| Local trust-store compromise | Out of TLS-only scope; command signature/release trust still fail closed when enforced | threat-model exercise |
| Cloud compromise | v1 HMAC is insufficient (cloud knows token); v2 operator signature must reject unauthorized command | compromised-router simulation after ZT-603 |
| Certificate rotation | Current/next overlap, no validation disable switch | staged endpoint test |
| Network unavailable | Queue only approved minimal urgent payload locally; no DNS/ICMP covert channel | offline test |

## Safety rules

- No feature here automatically suspends/kills a process, locks an account,
  rewrites ACLs, restores network state or emits v2 production commands.
- Raw ACLs, usernames in burst summaries, file paths in ETW summaries, private
  keys and TPM secrets never leave the machine.
- Missing TPM/ETW/SACL privilege is `unsupported`/`unknown`, not failure.
- Every future enforcement step requires an explicit contract version,
  dashboard rollback control, pilot and fault-injection acceptance.
