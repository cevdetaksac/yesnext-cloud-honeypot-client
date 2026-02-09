# 🚀 Cloud Honeypot Client v4.0.0 — Advanced Threat Detection & Auto-Response

**Release Date:** February 9, 2026

## 🏗️ Architecture — 4-Fazlı Tehdit Algılama Sistemi

v4.0.0, honeypot istemcisine gerçek zamanlı tehdit algılama, otomatik yanıt, ransomware koruması ve performans optimizasyonu yetenekleri ekler. **10 yeni modül** ile toplam ~5.000+ satır yeni kod eklendi.

---

## ⚡ Faz 1 — Real-Time Threat Detection

### Windows Event Log Watcher (`client_eventlog.py`)
- **EvtSubscribe** push-based real-time event monitoring
- 5 kanal izleme: Security, System, Application, RDP (2 kanal)
- ~25 Event ID takibi (4624/4625/4648/4672/4688/4697/4720/4732/1102 vb.)
- XPath tabanlı verimli sunucu tarafı filtreleme
- Otomatik hesap/IP/logon-type filtreleme (SYSTEM, DWM-, machine accounts)

### Threat Detection Engine (`client_threat_engine.py`)
- IP bazlı bağlam havuzu (IPContext) — kümülatif tehdit skoru
- **THREAT_SCORES** sözlüğü ile 20+ olay tipi skorlaması
- 4 korelasyon kuralı:
  - 🔓 Brute Force → Successful Login
  - 🌙 RDP After Hours (00:00-06:00)
  - 🕸️ Lateral Movement (2+ servise erişim)
  - 💀 Post-Exploitation (login → service/user creation)
- Z-score decay ile otomatik skor azalması
- 24 saat inaktif IP cleanup

### Alert Pipeline (`client_alerts.py`)
- Severity tabanlı routing (critical → urgent API, high → normal, warning → batch)
- Cooldown sistemi ile alert flood önleme
- Deque tabanlı alert geçmişi (son 200)

---

## 🛡️ Faz 2 — Automated Response & Remote Commands

### Auto Response (`client_auto_response.py`)
- `block_ip` — netsh advfirewall ile IP engelleme (süreli/süresiz)
- `unblock_ip` — IP engeli kaldırma
- `logoff_user` — Aktif oturum sonlandırma
- `disable_account` / `enable_account` — Hesap yönetimi
- `emergency_lockdown` — Tüm trafiği engelle, sadece management IP'ye izin ver

### Remote Command Executor (`client_remote_commands.py`)
- Dashboard'dan 14 uzak komut desteği
- 5 saniyelik polling ile komut bekleme
- **ALLOWED_COMMANDS** whitelist güvenlik katmanı
- Korumalı hesaplar/süreçler/servisler (SYSTEM, lsass.exe vb.)
- 5 dakika komut expiry süresi
- Rate limiting (10 komut/dakika)

### Silent Hours Guard (`client_silent_hours.py`)
- 5 mod: Disabled, Night Only, Outside Working, Always, Custom
- Gece-yarısı geçen saat aralıkları desteği
- Hafta sonu tüm gün sessiz mod
- IP + Subnet whitelist
- Otomatik aksiyonlar: block_ip + logoff + disable_account

---

## 🧬 Faz 3 — Advanced Protection

### Ransomware Shield (`client_ransomware_shield.py`)
- **Katman 1 — Canary Files**: 45 tuzak dosya (3 klasör × 5 dosya × 3 konum), SHA-256 integrity check
- **Katman 2 — File System Watchdog**: Toplu rename/modify tespiti
- **Katman 3 — Suspicious Process Detector**: 9 regex pattern (vssadmin delete shadows, bcdedit, cipher /w vb.)
- **Katman 4 — VSS Monitor**: Shadow Copy sayısı izleme, silme tespiti
- Skor 100 → Emergency alert + süreç öldürme

### System Health Monitor (`client_system_health.py`)
- 9 sistem metriği izleme (CPU, RAM, Disk, I/O, Network, Process count, Connections)
- **AnomalyDetector**: Hareketli ortalama + z-score > 3.0 anomali tespiti
- Korelasyon: CPU + Disk I/O spike → kripto madenci şüphesi
- 5 dakikada bir API'ye health snapshot raporu

### Process Self-Protection (`client_self_protection.py`)
- **Katman 1 — Task Scheduler**: Süreç ölürse otomatik yeniden başlatma
- **Katman 2 — DACL Koruması**: `SetProcessShutdownParameters` + DACL ile taskkill engelleme
- **Katman 3 — Safe Last Breath**: Süreç sonlandırılırken güvenli aksiyon
  - Aktif tehdit varsa → sadece şüpheli IP engellenir
  - Tehdit yoksa → firewall'a dokunulmaz (sunucu brick olmaz)
  - ⚠️ Tasarım prensibi: "Primum non nocere"

---

## ⚙️ Faz 4 — Polish & Production

### Performance Optimizer (`client_performance.py`)
- Adaptif throttling: CPU ≥85% → 2x, ≥95% → 4x interval artışı
- Event rate limiting: 50/s max, queue overflow koruması
- Module interval adjuster callback sistemi
- ASCII sparkline trend verileri (deque maxlen=360, ~3 saat)

### False Positive Tuner (`client_performance.py`)
- Per-event-type cooldown sistemi (failed_logon: 60s, burst: 300s vb.)
- FP_SCORE_ADJUSTMENTS: Sık FP üreten olaylar için skor çarpanları
- Auto-whitelist learning: 50+ event + max_score<10 → güvenilir IP
- Stale cooldown entry cleanup

### GUI Enhancements
- 📊 **Threat Dashboard**: threat_level, events/hour, tracked IPs kartları
- 🧬 **Faz 3 Cards**: Ransomware Shield, CPU/RAM, Protection status
- 📜 **Live Threat Feed**: Son 200 satır, scrollable
- ⚡ **Quick Response Buttons**: Block IP, Logoff, Disable, Snapshot
- 🔇 **Silent Hours Indicator**: Aktif/pasif gösterge
- 📋 **Command History**: Son 50 komut, scrollable
- 👥 **Active Sessions**: `query session` + yenile butonu
- 📈 **Trend Mini-Charts**: ASCII sparklines (▁▂▃▄▅▆▇█)

---

## 🔌 API Endpoints (Backend Gerekli)

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| POST | `/api/alerts/urgent` | Kritik alert gönderimi |
| POST | `/api/events/batch` | Toplu event raporlama |
| POST | `/api/alerts/auto-block` | Otomatik IP block bildirimi |
| GET | `/api/commands/pending` | Bekleyen komutları çek |
| POST | `/api/commands/result` | Komut sonucu raporla |
| GET | `/api/threats/config` | Tehdit config çek |
| POST | `/api/alerts/silent-hours` | Sessiz saat ihlali bildirimi |
| POST | `/api/health/report` | Sistem sağlık raporu |
| GET | `/api/threats/summary` | Tehdit özeti çek |
| PUT | `/api/notifications/preferences` | Bildirim tercihleri güncelle |
| POST | `/api/alerts/ransomware` | Ransomware alert bildirimi |
| POST | `/api/alerts/self-protection` | Süreç koruma bildirimi |

---

## 📦 Yeni Dosyalar

| Dosya | Satır | Açıklama |
|-------|-------|----------|
| `client_eventlog.py` | ~442 | Windows Event Log Watcher |
| `client_threat_engine.py` | ~657 | Threat Detection Engine |
| `client_alerts.py` | ~402 | Alert Pipeline |
| `client_auto_response.py` | ~517 | Automated Response |
| `client_remote_commands.py` | ~579 | Remote Command Executor |
| `client_silent_hours.py` | ~401 | Silent Hours Guard |
| `client_ransomware_shield.py` | ~552 | Ransomware Shield |
| `client_system_health.py` | ~393 | System Health Monitor |
| `client_self_protection.py` | ~400 | Process Self-Protection |
| `client_performance.py` | ~419 | Performance Optimizer + FP Tuner |

---

## 🐛 Bug Fixes

| Sorun | Çözüm |
|-------|-------|
| ProcessProtection constructor TypeError | `alert_pipeline`, `api_client` parametreleri eklendi, `api_url` otomatik türetilir |
| RansomwareShield `threat_engine` kabul etmiyor | Constructor'a `threat_engine` kwarg eklendi |
| SystemHealthMonitor `threat_engine` kabul etmiyor | Constructor'a `threat_engine` kwarg eklendi |

---

## ⚠️ Notlar

- Tüm modüller backend API hazır olmadan da çalışır (graceful fallback)
- try/except ile API hataları sessizce yutulur — servis kesintisi olmaz
- SilentHoursGuard ve FalsePositiveTuner pasif bileşenlerdir (daemon thread yok)
- Minimum Python 3.9+, Önerilen: Python 3.12
- Gerekli paketler: `requirements.txt` dosyasına bakınız
