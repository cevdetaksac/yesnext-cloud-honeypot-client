# P1 Security & Resilience — Client implementation record

> Date: 2026-07-22  
> Contract baseline: 1.4.2  
> Production floor: client 4.9.0 (unchanged)  
> Policy: observe-only/default-off until canonical schemas are promoted.

## Landed client surfaces

| Work item | Client surface | Default / invariant |
|---|---|---|
| RES-103 | `client_resilience_p1.make_heartbeat_proof` | Candidate HMAC heartbeat proof; default off, no cloud enforcement |
| RES-105/106 | `client_resilience_p1.acl_drift_status` | DACL fingerprint only; no ACL mutation, raw principals never uploaded |
| RANS-302/303 | `client_etw_shadow.sample().correlation` | Dropped/restart/buffer health + bounded fan-out/rename/write correlation; shadow only |
| DEC-201/202 | `RansomwareShield.get_stats().canary_coverage` | Counts only; no user paths |
| DEC-205/206/208/209 | `BaseHoneypot.get_health` | Existing handler/rate/backlog budgets exposed; static profile honestly reported |
| NET-501/502 | `plan_network_restore`, `load_baseline_version`, `dry_run`, `rollback_version` | Signed baseline required; destructive restore remains confirm-gated |
| OOB-501 | `client_offline_queue` | DPAPI + HMAC + bounded/idempotent queue; no ingest wiring before contract |
| ID-402/403 | `PasswordBurstCorrelator` | Aggregate health only; no password/raw event retention; auto lockout false |
| ZT-602/603 | `client_operator_keys.inspect_keyset` | Public metadata validation only; signature verify disabled |
| ZT-605b | Test matrix below | No TLS bypass or covert fallback |
| DEV-601 | `client_device_identity.probe_tpm` | Read-only capability; no key generation/enrollment/hardware lock |

## Contract gates still required

The following are deliberately **not** production behavior:

1. heartbeat proof wire/verification, replay window and cloud coverage metrics;
2. access-integrity/device-identity health schemas;
3. ETW detection batch ingest and 4723/4724 burst alert payload;
4. offline urgent-event ingest + ACK/idempotency schema;
5. operator public-key endpoint, algorithm, canonical serialization and
   asymmetric signature verification;
6. TPM enrollment/attestation/rotation/re-enrollment.

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
