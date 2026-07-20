# CLOUD — Threat Intel & Security Layers Feed

> **Audience:** Cloud / Dashboard API implementers  
> **Client:** Cloud Honeypot Client ≥ **4.5.61**  
> **API base:** `https://honeypot.yesnext.com.tr`  
> **Related client contract:** [`api/09-threat-intel.md`](api/09-threat-intel.md)

Bu doküman, **cloud tarafında** yapılması gereken işleri tarif eder.
Amaç: güncel tehditleri (ransomware IoC, KEV CVE, C2 IP, şüpheli process/cmdline, uzantılar)
cloud’un sürekli güncellemesi ve agent’lara yayınlaması; agent’ın savunma + uyarı
mekanizmalarını buna göre açması.

Client **kaynak çekmez** (Abuse.ch / CISA doğrudan değil). Client sadece cloud’a güvenir.

---

## 1. Hedef mimari

```
┌──────────────────────┐     schedule      ┌─────────────────────────┐
│ External intel       │ ───────────────►  │ Cloud Threat Ingest     │
│ CISA KEV, ThreatFox, │                   │ (normalize + score +    │
│ URLhaus, MSRC RSS…   │                   │  dedupe + expire)       │
└──────────────────────┘                   └───────────┬─────────────┘
                                                       │
                                                       ▼
                                           ┌─────────────────────────┐
                                           │ threat_intel_bundles    │
                                           │ version / etag / shard  │
                                           └───────────┬─────────────┘
                                                       │
                     GET /api/agent/threat-intel       │
                     (token + If-None-Match)           │
                                                       ▼
                                           ┌─────────────────────────┐
                                           │ Agent (SYSTEM daemon)   │
                                           │ apply → firewall /      │
                                           │ ransomware shield /     │
                                           │ process watch / alerts  │
                                           └─────────────────────────┘
```

**Kurallar:**
1. Cloud = tek SoT (source of truth) agent için.
2. Bundle **imzalı veya en azından HTTPS + token** ile gelir.
3. Her kuralın `id`, `expires_at`, `severity`, `action` alanı vardır.
4. Agent offline iken son başarılı bundle cache’ten çalışır (ProgramData).
5. False-positive kontrolü cloud’da: “capacity / IDE I/O” asla ransomware kuralı olmaz.

---

## 2. Cloud ingest (sürekli güncelleme)

### 2.1 Önerilen kaynaklar (MVP → genişletme)

| Öncelik | Kaynak | Ne alınır | Not |
|---------|--------|-----------|-----|
| P0 | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) JSON | CVE id, product, due date | Hardening / dashboard uyarı |
| P0 | [ThreatFox](https://threatfox.abuse.ch/) API | IP/domain/hash + malware family | Firewall block + alert |
| P1 | [URLhaus](https://urlhaus.abuse.ch/) | Kötü URL / host | Domain block list (opsiyonel) |
| P1 | İç liste (YesNext curated) | Ransomware uzantıları, LOLBin cmdline | Sizin editorial kontrol |
| P2 | MSRC / NVD özet | CVE açıklama | Dashboard bilgilendirme |
| P2 | MalwareBazaar | Hash | İleride hash scan |

**Lisans:** Her feed’in ToS’una uyun; rate-limit + User-Agent + cache zorunlu.
VirusTotal / Defender TI Enterprise ayrı sözleşme ister — MVP’ye koyma.

### 2.2 Ingest job (öneri)

- Worker: her **15–60 dk** (KEV günde 1–4 kez yeterli olabilir).
- Normalize → ortak schema (`ioc` / `process` / `extension` / `cve` / `hardening`).
- Dedupe by `(type, value)`.
- TTL: ThreatFox IP varsayılan **7–30 gün**; KEV CVE revoke edilene kadar.
- Score: `severity` = `info|low|medium|high|critical`.
- Family tag: `lockbit`, `blackcat`, `generic_ransomware`, `c2`, `exfil`, …
- **Allowlist:** Microsoft update, CDN, kendi API host’unuz asla block’a girmez.

### 2.3 Bundle üretimi

Her başarılı ingest sonrası (veya günde N kez) yeni bundle:

```text
bundle_version = "2026.07.21.003"   # veya monotonic integer
etag = sha256(canonical_json)
```

Agent sadece `etag` / `version` değişince indirir (`304 Not Modified`).

---

## 3. Agent API sözleşmesi

Auth: mevcut agent token (Bearer veya query — `01-auth.md` ile aynı).

### 3.1 GET /api/agent/threat-intel

**Query:**
| Param | Zorunlu | Açıklama |
|-------|---------|----------|
| `token` | * | Agent token (veya Authorization header) |
| `since_version` | | Agent’taki son `bundle_version` |
| `os` | | `windows` (ileride `linux`) |
| `client_version` | | örn. `4.5.61` — cloud min-version filtreleyebilir |

**Headers (öneri):**
```http
If-None-Match: "<etag>"
```

**Responses:**

| Kod | Anlam |
|-----|--------|
| `200` | Yeni/güncel bundle JSON |
| `304` | Değişiklik yok (body boş) |
| `401/403` | Token geçersiz |
| `503` | Ingest henüz hazır değil — agent cache kullanır |

**200 body (özet):**

```json
{
  "status": "ok",
  "bundle_version": "2026.07.21.003",
  "etag": "sha256:…",
  "generated_at": "2026-07-21T00:00:00Z",
  "ttl_sec": 3600,
  "min_client_version": "4.5.61",
  "layers": {
    "firewall_blocks": [
      {
        "id": "tf-ip-1",
        "action": "block_ip",
        "value": "203.0.113.10",
        "family": "lockbit_c2",
        "severity": "high",
        "expires_at": "2026-08-20T00:00:00Z",
        "source": "threatfox",
        "reason": "ThreatFox LockBit C2"
      }
    ],
    "ransomware": {
      "extensions": [".lockbit", ".zeno", ".blacksuit"],
      "process_names": ["vssadmin.exe", "wbadmin.exe", "bcdedit.exe"],
      "cmdline_patterns": [
        {"id": "rs-cmd-1", "pattern": "vssadmin.*delete\\s+shadows", "flags": "i", "severity": "critical", "action": "alert"},
        {"id": "rs-cmd-2", "pattern": "bcdedit.*/set\\s+\\{default\\}\\s+recoveryenabled\\s+no", "flags": "i", "severity": "critical", "action": "alert"}
      ],
      "notes": "Curated + intel merge; canary/VSS local layers remain authoritative for lockdown"
    },
    "process_watch": [
      {
        "id": "pw-1",
        "name_contains": "mimikatz",
        "severity": "critical",
        "action": "alert"
      }
    ],
    "kev_cves": [
      {
        "id": "CVE-2024-XXXX",
        "product": "Windows",
        "action": "dashboard_alert",
        "severity": "high",
        "required_action": "Apply vendor patch",
        "due_date": "2026-08-01"
      }
    ],
    "hardening": [
      {
        "id": "hd-rdp-nla",
        "check": "rdp_nla_enabled",
        "action": "warn_if_fail",
        "severity": "medium",
        "title": "RDP NLA önerilir"
      }
    ],
    "ui_banners": [
      {
        "id": "bn-1",
        "severity": "info",
        "title_tr": "Aktif kampanya",
        "body_tr": "LockBit varyantı yaygınlaşıyor — canary ve VSS koruması açık tutun.",
        "expires_at": "2026-07-28T00:00:00Z"
      }
    ]
  },
  "policy": {
    "auto_block_firewall": true,
    "auto_lockdown_on_canary": true,
    "intel_block_requires_severity_at_least": "high",
    "max_firewall_rules_from_intel": 500
  }
}
```

### 3.2 POST /api/agent/threat-intel/ack (opsiyonel ama önerilir)

Agent uyguladıktan sonra:

```json
{
  "token": "…",
  "bundle_version": "2026.07.21.003",
  "applied_at": "2026-07-21T01:00:00Z",
  "stats": {
    "firewall_added": 12,
    "firewall_skipped": 3,
    "ransomware_rules": 40,
    "errors": []
  }
}
```

Dashboard’da “son intel sync” kolonuna yazılır.

### 3.3 Dashboard (cloud UI) — öneri

- **Threat Intel** sayfası: son bundle version, kaynak sağlığı, kural sayıları.
- Manuel “Publish now” / “Pause auto-block”.
- Allowlist yönetimi (asla engellenmeyecek IP/domain).
- Tenant override: enterprise müşteri kendi ekstra IoC’sini ekleyebilir.

---

## 4. Action semantiği (cloud → agent)

| `action` | Agent davranışı |
|----------|-----------------|
| `block_ip` | Firewall agent kuralı (`HP-INTEL-<id>`), severity policy’ye bağlı |
| `alert` | Urgent/lifecycle alert + GUI threat feed |
| `dashboard_alert` | Sadece cloud/dashboard; agent log |
| `warn_if_fail` | Yerel hardening check başarısızsa uyarı |
| `extend_ransomware_watch` | Uzantı / process / cmdline listesine ekle (lockdown **yalnızca** canary/VSS/kritik local kanıtla) |

**Önemli:** Intel feed tek başına `emergency_lockdown` tetiklememeli.
Lockdown = canary hit / VSS wipe / kritik local process (mevcut shield).

---

## 5. Cloud implementasyon checklist

### MVP (1. sprint)

- [ ] Tablo: `threat_intel_sources`, `threat_intel_iocs`, `threat_intel_bundles`
- [ ] Ingest worker: CISA KEV + ThreatFox (IP) + curated ransomware extensions
- [ ] `GET /api/agent/threat-intel` + ETag / 304
- [ ] Allowlist (honeypot.yesnext.com.tr, GitHub releases, Windows Update ranges opsiyonel)
- [ ] Bundle `policy.auto_block_firewall` flag
- [ ] Admin UI: son sync zamanı + kural sayısı
- [ ] Metrik: ingest errors, bundle size, agent ack rate

### Sprint 2

- [ ] `POST .../ack`
- [ ] URLhaus host list (opsiyonel)
- [ ] Tenant-specific IoC upload
- [ ] Bundle signing (Ed25519) + agent verify (public key embedded)
- [ ] Hardening checks kataloğu (`rdp_nla_enabled`, `smb1_disabled`, …)

### Sprint 3

- [ ] Hash IoC (MalwareBazaar) — agent’ta opsiyonel hash scan
- [ ] WS push: `threat_intel_updated` (poll’a ek)
- [ ] A/B severity policies per plan (free/pro)

---

## 6. Güvenlik & abuse

- Rate-limit per token (örn. 1 req / 5 dk; 304 ucuz).
- Bundle max size (örn. 1–2 MB); aşarsa shard (`?layer=firewall`).
- IoC validation: IP parse, CIDR max /24 agent’ta parçala (mevcut firewall mantığı).
- ASKIYA AL: bir kaynak bozulursa bundle’a boş layer koy, tüm feed’i düşürme.
- Audit log: kim `auto_block` kapattı.

---

## 7. Agent tarafı (referans — client repo)

| Dosya | Rol |
|-------|-----|
| `client_threat_intel.py` | Poll, cache (`ProgramData\...\threat_intel_bundle.json`), apply |
| `client_api.py` → `fetch_threat_intel()` | HTTP GET |
| Daemon loop | ~15–30 dk + startup |
| Ransomware shield | extensions / cmdline merge from bundle |
| Firewall agent | `HP-INTEL-*` rules from `firewall_blocks` |

Detaylı client sözleşmesi: [`api/09-threat-intel.md`](api/09-threat-intel.md).

---

## 8. Örnek timeline

| T | Cloud | Agent |
|---|-------|-------|
| T0 | Ingest ThreatFox + KEV | — |
| T1 | Publish bundle `…003` | GET → 200, apply blocks, merge RS lists |
| T2 | — | ACK stats |
| T3 | Dashboard “12 hosts synced” | — |
| T+1h | Same etag | GET → 304 |

---

## 9. Acceptance (cloud)

1. Token ile `GET /api/agent/threat-intel` → geçerli JSON, `layers` dolu veya bilinçli boş.
2. Aynı etag ile tekrar → `304`.
3. Geçersiz token → `401/403`.
4. ThreatFox IP allowlist’te ise bundle’da **yok**.
5. Bundle içinde `disk_usage` / “disk full = ransomware” türü kural **yok**.
6. En az bir staging host ACK sonrası dashboard’da görünür.

---

## 10. İletişim

Client sürüm notları: `docs/CHANGELOG.md`  
Bu dosya cloud implementasyonu için **kaynak prompt** olarak kullanılabilir.
