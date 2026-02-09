# 🔄 Honeypot Client v4.0 Güncelleme Prompt'u

## GÖREV ÖZETİ

Mevcut Honeypot Client'a **V4 Tehdit Algılama** modülleri eklenmeli. Backend (sunucu) tarafı bu endpoint'leri zaten implemente etti ve production'da çalışıyor. Client'ın bu yeni endpoint'leri kullanması gerekiyor.

> **ÖNEMLİ:** Mevcut client özellikleri (heartbeat, attack raporu, port raporu, blok yönetimi, servis/tunnel yönetimi) AYNEN korunacak. Bunlar çalışıyor. Sadece yeni V4 modülleri EKLENecek.

---

## 🏗️ EKLENMESİ GEREKEN 4 ANA MODÜL

### Modül 1: Tehdit Algılama Motoru (ThreatEngine)
### Modül 2: Sistem Sağlık İzleme (HealthMonitor)
### Modül 3: Uzaktan Komut Yürütme (CommandExecutor)
### Modül 4: Tehdit Config Senkronizasyonu (ConfigSync)

---

## 📡 V4 API ENDPOINTLERİ — TAM REFERANS

Base URL: `https://honeypot.yesnext.com.tr`
Auth: Tüm isteklerde `token` (string) body veya query param olarak gönderilir.

---

### EP1: `POST /api/alerts/urgent` — Kritik Tehdit Bildirimi

**Ne zaman çağrılır:** Client, yüksek tehdit skoru olan bir olay tespit ettiğinde ANINDA çağrılır. Batch'lenmez, kuyruklanmaz.

**Tetikleyici olaylar (client tespit etmeli):**
- ✅ Başarılı RDP/SSH/SQL oturum açma (Windows Event 4624 Type 10, Event 1149)
- ✅ Brute-force sonrası başarılı giriş (çok sayıda 4625 ardından 4624)
- ✅ Yeni admin/kullanıcı hesabı oluşturulması (Event 4720)
- ✅ Audit log temizlenmesi (Event 1102)
- ✅ Şüpheli süreç çalıştırma (vssadmin delete shadows, bcdedit, wbadmin delete, cipher /w)
- ✅ Canary dosyalarının değişmesi/silinmesi (ransomware göstergesi)
- ✅ VSS shadow copy silinmesi
- ✅ Sessiz saatlerde (gece/hafta sonu) oturum açma

**Request body:**

```json
{
    "token": "CLIENT_TOKEN",
    "alert": {
        "alert_id": "uuid-v4",
        "timestamp": "2026-02-08T23:15:42.123Z",
        "severity": "critical",       // "critical" | "high" | "warning" | "info"
        "threat_type": "brute_force_success",
        "title": "RDP Brute Force — Başarılı Giriş Tespit Edildi!",
        "description": "192.168.1.105 adresinden 47 başarısız denemenin ardından 'administrator' hesabıyla başarılı RDP girişi yapıldı.",
        "source_ip": "192.168.1.105",
        "source_country": "RU",
        "source_city": "Moscow",
        "target_service": "RDP",
        "target_port": 3389,
        "username": "administrator",
        "threat_score": 95,            // 0-100 arası, >= 80 kritik
        "correlation_rule": "brute_force_then_access",
        "recommended_action": "Hesap şifresini hemen değiştirin. Aktif oturumu kapatın.",
        "auto_response_taken": ["block_ip", "notify_urgent"],
        "raw_events": [
            {
                "event_id": 4624,
                "timestamp": "2026-02-08T23:15:42Z",
                "channel": "Security",
                "source_ip": "192.168.1.105",
                "username": "administrator",
                "logon_type": 10,
                "process_name": "svchost.exe"
            }
        ],
        "system_context": {
            "hostname": "WIN-SERVER01",
            "os_version": "Windows Server 2022",
            "cpu_percent": 45.2,
            "memory_percent": 68.1,
            "uptime_hours": 142.5,
            "active_honeypot_services": ["RDP", "SSH", "MSSQL"]
        }
    }
}
```

**Response (200):**

```json
{
    "status": "received",
    "alert_id": "uuid",
    "notification_sent": true,
    "notification_channels": ["email", "dashboard"],
    "actions_requested": []
}
```

**Client davranışı:**
- `actions_requested` array'inde komut varsa hemen çalıştır (ör. `["disable_account"]`)
- Gönderim başarısızsa: local queue'da sakla, 30sn sonra retry (max 3 deneme)
- Rate limit: aynı `threat_type + source_ip` için 5 dakikada en fazla 1 alert

---

### EP2: `POST /api/events/batch` — Güvenlik Olayları Toplu Gönderim

**Ne zaman çağrılır:** Her **2 dakikada** bir, birikmiş güvenlik olayları toplu olarak gönderilir.

**Hangi olaylar gönderilir:**
- Başarısız oturum açma denemeleri (Event 4625)
- Başarılı oturum açmaları (Event 4624) — honeypot servislerinden gelen
- Servis başlat/durdur olayları (Event 7036)
- Yeni süreç oluşturma (Event 4688) — sadece şüpheli olanlar
- Firewall kural değişiklikleri (Event 4946, 4947)
- Honeypot servislerine gelen bağlantı denemeleri

**Request body:**

```json
{
    "token": "CLIENT_TOKEN",
    "batch_id": "uuid-v4",
    "events": [
        {
            "event_id": "uuid-v4",
            "timestamp": "2026-02-08T23:10:05Z",
            "category": "failed_logon",
            "severity": "info",
            "source_ip": "185.220.101.34",
            "source_country": "DE",
            "target_service": "SSH",
            "target_port": 22,
            "username": "root",
            "windows_event_id": 4625,
            "logon_type": 3,
            "threat_score": 5
        }
    ],
    "summary": {
        "period_start": "2026-02-08T23:05:00Z",
        "period_end": "2026-02-08T23:10:00Z",
        "total_events": 156,
        "by_severity": {"info": 140, "warning": 12, "high": 3, "critical": 1},
        "unique_source_ips": 23
    }
}
```

**Response (200):**

```json
{
    "status": "received",
    "batch_id": "uuid-v4",
    "events_processed": 156
}
```

**Client davranışı:**
- Olayları memory buffer'da biriktir (max 500 olay veya 2 dakika)
- Buffer dolduğunda veya 2dk geçtiğinde flush → POST
- Her olaya `threat_score` ata (basit skorlama: failed_logon=5, successful_logon=40, vb.)
- `category` değerleri: `failed_logon`, `successful_logon`, `account_created`, `account_modified`, `log_cleared`, `service_state_change`, `firewall_change`, `suspicious_process`, `honeypot_connection`
- Gönderim başarısızsa: buffer'ı koru, sonraki cycle'da tekrar dene

---

### EP3: `POST /api/health/report` — Sistem Sağlık Raporu

**Ne zaman çağrılır:** Her **60 saniyede** bir (heartbeat ile aynı döngüde gönderilebilir).

**Request body:**

```json
{
    "token": "CLIENT_TOKEN",
    "snapshot": {
        "timestamp": "2026-02-08T23:15:00Z",
        "cpu_percent": 45.2,
        "memory_percent": 68.1,
        "memory_total_gb": 32.0,
        "memory_used_gb": 21.8,
        "disk_usage_percent": 76.0,
        "disk_total_gb": 500,
        "disk_free_gb": 120,
        "disk_io_read_bytes_sec": 15000000,
        "disk_io_write_bytes_sec": 25000000,
        "network_bytes_sent_sec": 500000,
        "network_bytes_recv_sec": 120000,
        "process_count": 245,
        "open_connections": 89,
        "top_cpu_processes": [
            {"name": "sqlservr.exe", "pid": 1234, "cpu_percent": 35.2, "memory_mb": 4096},
            {"name": "svchost.exe", "pid": 5678, "cpu_percent": 12.1, "memory_mb": 256}
        ],
        "anomalies_detected": [],
        "vss_shadow_count": 5,
        "ransomware_shield_status": "active",
        "canary_files_intact": true
    }
}
```

**Response (200):**

```json
{
    "status": "received"
}
```

**Client'ın toplaması gereken metrikler:**
- `psutil.cpu_percent(interval=1)`
- `psutil.virtual_memory()` → percent, total, used
- `psutil.disk_usage('/')` → percent, total, free
- `psutil.disk_io_counters()` → diff ile bytes/sec hesapla
- `psutil.net_io_counters()` → diff ile bytes/sec hesapla
- `len(psutil.pids())` → process_count
- `len(psutil.net_connections())` → open_connections
- İlk 5 CPU-yoğun süreç: `sorted(psutil.process_iter(['name','pid','cpu_percent','memory_info']), key=...)`
- VSS shadow count: `vssadmin list shadows | grep "Shadow Copy ID"` çıktısını say
- Canary dosya kontrolü: Önceden oluşturulan sentinel dosyaların hash'i değişti mi?
- `anomalies_detected`: CPU > 90% → `["cpu_spike"]`, Disk I/O > threshold → `["disk_io_spike"]`, vb.

**`ransomware_shield_status` değerleri:** `"active"`, `"disabled"`, `"error"`
**`canary_files_intact`:** `true` → dosyalar sağlam, `false` → dosyalar değişmiş/silinmiş (RANSOMWARE ALARMI!)

> ⚠️ **KRİTİK:** Sunucu `canary_files_intact = false` aldığında otomatik olarak severity=critical bir ThreatAlert oluşturup e-posta gönderiyor. Client'ın bunu doğru raporlaması hayati önem taşıyor.

---

### EP4: `POST /api/alerts/auto-block` — Otomatik IP Engelleme Bildirimi

**Ne zaman çağrılır:** Client bir IP'yi otomatik engellediğinde (firewall kuralı eklediğinde) ANINDA çağrılır.

**Request body:**

```json
{
    "token": "CLIENT_TOKEN",
    "blocked_ip": "192.168.1.105",
    "reason": "brute_force_success",
    "threat_score": 95,
    "related_alert_id": "uuid-of-related-alert",
    "duration_hours": 24,
    "blocked_at": "2026-02-08T23:15:43Z",
    "firewall_rule_name": "HONEYPOT_AUTOBLOCK_192.168.1.105",
    "events_summary": {
        "failed_attempts": 47,
        "successful_logins": 1,
        "services_targeted": ["RDP"],
        "usernames_used": ["administrator", "admin", "root"]
    }
}
```

**Response (200):**

```json
{
    "status": "confirmed",
    "block_id": "123",
    "extend_duration": false,
    "permanent_block": false
}
```

**Client davranışı:**
- `extend_duration: true` dönerse → mevcut firewall kuralının süresini uzat
- `permanent_block: true` dönerse → kuralı kalıcı yap (expire kaldır)
- Sunucu ayrıca `block_rules` tablosuna da otomatik kayıt ekliyor, çift engelleme olmaz

---

### EP5: `GET /api/threats/config` — Tehdit Yapılandırmasını Çek

**Ne zaman çağrılır:**
1. Client başlangıcında (startup) bir kez
2. Sonra her **5 dakikada** bir (config değişikliği kontrolü)

**Request:** `GET /api/threats/config?token=CLIENT_TOKEN`

**Response (200):**

```json
{
    "auto_block_enabled": true,
    "auto_block_threshold": 80,
    "auto_block_duration_hours": 24,
    "max_auto_blocks_per_hour": 50,
    "max_auto_blocks_per_day": 200,
    "whitelist_ips": ["10.0.0.1", "192.168.1.100"],
    "whitelist_subnets": ["192.168.1.0/24", "10.0.0.0/8"],
    "alert_email_enabled": true,
    "alert_email": "admin@company.com",
    "min_severity_for_email": "high",
    "instant_email_for_critical": true,
    "daily_digest_enabled": true,
    "daily_digest_time": "09:00",
    "webhook_enabled": false,
    "webhook_url": "",
    "ransomware_protection_enabled": true,
    "canary_files_enabled": true,
    "working_hours": {
        "enabled": false,
        "start": "08:00",
        "end": "18:00",
        "timezone": "Europe/Istanbul"
    },
    "silent_hours": {
        "enabled": true,
        "mode": "night_only",
        "night_start": "00:00",
        "night_end": "07:00",
        "weekend_all_day_silent": true,
        "auto_block_ip": true,
        "auto_logoff": true,
        "auto_disable_account": true,
        "block_duration_hours": 0,
        "whitelist_ips": ["85.107.45.12"],
        "whitelist_subnets": ["10.0.0.0/8"],
        "timezone": "Europe/Istanbul"
    },
    "monitored_event_channels": {
        "security": true,
        "system": true,
        "application": true,
        "rdp": true
    },
    "emergency_lockdown_enabled": false,
    "lockdown_management_ip": ""
}
```

**Client bu config'i şu şekilde kullanır:**

| Alan | Kullanım |
|------|----------|
| `auto_block_enabled` | IP otomatik engelleme özelliği açık mı? |
| `auto_block_threshold` | Threat score bu eşiğin üstündeyse otomatik engelle |
| `auto_block_duration_hours` | Engel süresi (0 = kalıcı) |
| `max_auto_blocks_per_hour` | Saatte max kaç IP engellenebilir |
| `max_auto_blocks_per_day` | Günde max kaç IP engellenebilir |
| `whitelist_ips` | Bu IP'ler ASLA engellenmez |
| `whitelist_subnets` | Bu subnet'teki IP'ler ASLA engellenmez |
| `ransomware_protection_enabled` | Canary dosya izleme + VSS koruma aktif mi? |
| `canary_files_enabled` | Canary sentinel dosyaları oluştur/izle |
| `silent_hours.*` | Sessiz saatlerde otomatik aksiyon kuralları |
| `monitored_event_channels.*` | Hangi Windows Event Log kanalları izlenecek |
| `emergency_lockdown_enabled` | Acil kilitleme modu aktif mi? |
| `lockdown_management_ip` | Kilitleme modunda sadece bu IP'ye izin ver |

**Sessiz Saatler Mantığı (Client'ta implemente edilmeli):**

```python
def is_silent_hour(config):
    """Şu an sessiz saat mi kontrol et."""
    sh = config.get('silent_hours', {})
    if not sh.get('enabled'):
        return False
    
    tz = pytz.timezone(sh.get('timezone', 'Europe/Istanbul'))
    now = datetime.now(tz)
    current_time = now.strftime('%H:%M')
    
    mode = sh.get('mode', 'night_only')
    
    if mode == 'night_only':
        night_start = sh.get('night_start', '00:00')
        night_end = sh.get('night_end', '07:00')
        if night_start <= current_time or current_time < night_end:
            return True
    
    if sh.get('weekend_all_day_silent') and now.weekday() >= 5:  # Cumartesi=5, Pazar=6
        return True
    
    if mode == 'outside_working':
        wh = config.get('working_hours', {})
        if wh.get('enabled'):
            if current_time < wh.get('start', '08:00') or current_time > wh.get('end', '18:00'):
                return True
    
    return False
```

Sessiz saatlerde başarılı oturum açma tespit edildiğinde:
1. `sh.auto_block_ip == true` → saldırgan IP'yi engelle
2. `sh.auto_logoff == true` → oturumu kapat (logoff_user komutu)
3. `sh.auto_disable_account == true` → hesabı devre dışı bırak
4. `sh.whitelist_ips` / `sh.whitelist_subnets` → bu IP'ler/subnetler muaf

---

### EP6: `GET /api/commands/pending` — Bekleyen Uzak Komutları Al

**Ne zaman çağrılır:** Her **10 saniyede** bir poll edilir.

**Request:** `GET /api/commands/pending?token=CLIENT_TOKEN`

**Response (komut var):**

```json
{
    "commands": [
        {
            "command_id": "cmd-uuid-1",
            "command_type": "block_ip",
            "params": {
                "ip": "203.0.113.50",
                "duration_hours": 0,
                "reason": "Dashboard: Manuel engelleme"
            },
            "requested_by": "admin@company.com",
            "requested_at": "2026-02-08T03:12:45Z",
            "expires_at": "2026-02-08T03:17:45Z",
            "priority": "high"
        }
    ]
}
```

**Response (komut yok):**

```json
{
    "commands": []
}
```

> ⚠️ **ÖNEMLİ:** Sunucu komutu döndürdüğünde otomatik olarak `status = 'dispatched'` yapar. Yani aynı komut bir daha dönmez. Client komutu aldığında MUTLAKA çalıştırıp sonucu bildirmeli.

**Desteklenen `command_type` değerleri ve client'ın yapması gereken:**

| command_type | Client'ın yapacağı işlem | params |
|---|---|---|
| `block_ip` | Windows Firewall'da inbound kuralı ekle: `netsh advfirewall firewall add rule name="HONEYPOT_BLOCK_REMOTE_{ip}" dir=in action=block remoteip={ip}` | `ip`, `duration_hours` (0=kalıcı), `reason` |
| `unblock_ip` | Firewall kuralını kaldır: `netsh advfirewall firewall delete rule name="HONEYPOT_BLOCK_REMOTE_{ip}"` | `ip` |
| `logoff_user` | Kullanıcı oturumunu kapat: `logoff {session_id}` veya WMI ile | `username`, `session_id` (opsiyonel) |
| `disable_account` | Hesabı devre dışı bırak: `net user {username} /active:no` | `username` |
| `enable_account` | Hesabı etkinleştir: `net user {username} /active:yes` | `username` |
| `reset_password` | Şifre sıfırla: `net user {username} {new_password}` | `username`, `new_password` |
| `kill_process` | Süreci öldür: `taskkill /PID {pid} /F` veya `taskkill /IM {process_name} /F` | `pid` veya `process_name` |
| `stop_service` | Servisi durdur: `net stop {service_name}` | `service_name` |
| `start_service` | Servisi başlat: `net start {service_name}` | `service_name` |
| `restart_service` | Servisi yeniden başlat: stop + start | `service_name` |
| `enable_lockdown` | Acil kilitleme: tüm inbound bağlantıları engelle, sadece management_ip'ye izin ver | `management_ip`, `duration_minutes` |
| `disable_lockdown` | Kilitlemeyi kaldır: lockdown kurallarını sil | — |
| `collect_diagnostics` | Sistem bilgilerini topla ve result olarak gönder | — |
| `list_sessions` | Aktif oturumları listele: `query user` çıktısını parse et | — |

**Güvenlik korumaları (client tarafında kontrol):**

```python
PROTECTED_ACCOUNTS = {'administrator', 'system', 'networkservice', 'localservice', 'defaultaccount'}

def execute_command(cmd):
    cmd_type = cmd['command_type']
    params = cmd['params']
    
    # Korumalı hesap kontrolü
    if cmd_type in ('disable_account', 'reset_password'):
        username = (params.get('username') or '').lower()
        if username in PROTECTED_ACCOUNTS:
            return {
                'status': 'rejected',
                'result': {
                    'success': False,
                    'message': f"'{username}' hesabı koruma altındadır",
                    'error_code': 'SECURITY_POLICY_VIOLATION'
                }
            }
    
    # Komutu çalıştır...
```

---

### EP7: `POST /api/commands/result` — Komut Sonucu Bildir

**Ne zaman çağrılır:** Her komut çalıştırıldıktan hemen sonra.

**Başarılı sonuç:**

```json
{
    "token": "CLIENT_TOKEN",
    "command_id": "cmd-uuid-1",
    "status": "completed",
    "result": {
        "success": true,
        "message": "IP 203.0.113.50 başarıyla engellendi",
        "details": {
            "rule_name": "HONEYPOT_BLOCK_REMOTE_203.0.113.50",
            "applied_at": "2026-02-08T03:12:52Z"
        }
    },
    "executed_at": "2026-02-08T03:12:52Z",
    "execution_time_ms": 1250
}
```

**Başarısız sonuç:**

```json
{
    "token": "CLIENT_TOKEN",
    "command_id": "cmd-uuid-2",
    "status": "failed",
    "result": {
        "success": false,
        "message": "Kullanıcı oturumu kapatılamadı",
        "error_code": "SESSION_NOT_FOUND",
        "details": { "reason": "Belirtilen session_id aktif değil" }
    },
    "executed_at": "2026-02-08T03:12:55Z",
    "execution_time_ms": 350
}
```

**Güvenlik nedeniyle reddedilme:**

```json
{
    "token": "CLIENT_TOKEN",
    "command_id": "cmd-uuid-3",
    "status": "rejected",
    "result": {
        "success": false,
        "message": "Komut güvenlik politikası tarafından reddedildi",
        "error_code": "SECURITY_POLICY_VIOLATION",
        "details": {
            "reason": "Administrator hesabı devre dışı bırakılamaz",
            "policy": "protected_accounts"
        }
    },
    "executed_at": "2026-02-08T03:13:01Z",
    "execution_time_ms": 5
}
```

**Response (200):**

```json
{
    "status": "received",
    "command_id": "cmd-uuid-1"
}
```

---

## 🔄 GÜNCELLENMİŞ CLIENT DÖNGÜ ZAMANLAMA

Mevcut döngülere ek olarak:

```
MEVCUT (DEĞİŞMEZ):
  Her 60 saniye  → POST /api/heartbeat
  Her 2 dakika   → GET /api/premium/tunnel-status → POST /api/agent/tunnel-status
  Her 5 dakika   → Port scan → POST /api/agent/open-ports
  Her 30 saniye  → GET /api/agent/pending-blocks + /pending-unblocks

YENİ (EKLENMESİ GEREKEN):
  Her 10 saniye  → GET /api/commands/pending (komut gelirse hemen çalıştır → POST /api/commands/result)
  Her 60 saniye  → POST /api/health/report (sistem metrikleri — heartbeat ile birleştirilebilir)
  Her 2 dakika   → POST /api/events/batch (birikmiş güvenlik olayları)
  Her 5 dakika   → GET /api/threats/config (config sync)
  Anlık (olay)   → POST /api/alerts/urgent (yüksek threat_score olayda HEMEN)
  Anlık (olay)   → POST /api/alerts/auto-block (IP engellendiğinde HEMEN)
```

---

## 🧠 THREAT SCORING LOGİĞİ (Client'ta implemente edilmeli)

Her güvenlik olayına bir `threat_score` (0-100) atanmalı:

```python
THREAT_SCORES = {
    # Düşük (info seviyesi)
    'failed_logon': 5,
    'service_state_change': 3,
    'firewall_change': 10,
    'honeypot_connection': 5,
    
    # Orta (warning seviyesi)
    'multiple_failed_logon_same_ip': 25,    # 5+ aynı IP'den başarısız
    'account_modified': 20,
    'new_service_installed': 15,
    
    # Yüksek (high seviyesi)
    'successful_logon_from_new_ip': 40,
    'brute_force_detected': 50,             # 10+ başarısız deneme
    'suspicious_process': 45,
    'logon_outside_working_hours': 35,
    
    # Kritik (critical seviyesi) → Anlık alert tetikler
    'brute_force_then_success': 95,         # Brute force + başarılı giriş
    'new_admin_account': 85,
    'audit_log_cleared': 90,
    'canary_file_modified': 100,            # Ransomware!
    'vss_shadow_deleted': 95,               # Ransomware!
    'successful_logon_silent_hours': 80,    # Sessiz saatlerde giriş
    'rdp_logon_from_external': 75,          # Dış IP'den RDP
}
```

**Auto-block karar mantığı:**

```python
def should_auto_block(ip, threat_score, config):
    """IP otomatik engellenecek mi?"""
    if not config.get('auto_block_enabled'):
        return False
    if threat_score < config.get('auto_block_threshold', 80):
        return False
    # Whitelist kontrolü
    if ip in config.get('whitelist_ips', []):
        return False
    for subnet in config.get('whitelist_subnets', []):
        if ip_in_subnet(ip, subnet):
            return False
    # Rate limit kontrolü
    if hourly_block_count >= config.get('max_auto_blocks_per_hour', 50):
        return False
    if daily_block_count >= config.get('max_auto_blocks_per_day', 200):
        return False
    return True
```

---

## 🛡️ RANSOMWARE KORUMASI (Client'ta implemente edilmeli)

### Canary Dosyaları

Config'de `canary_files_enabled: true` ise:

1. **Başlangıçta:** Birkaç sentinel dosyayı stratejik konumlara oluştur:
   ```
   C:\Users\Public\Documents\.FinancialReport2024.xlsx.canary
   C:\Users\Public\Desktop\.ImportantNotes.docx.canary
   C:\ProgramData\.SystemConfig.dat.canary
   ```
2. Her dosyanın SHA256 hash'ini sakla
3. **Her 30 saniyede** dosyaların varlığını ve hash'ini kontrol et
4. Hash değiştiyse veya dosya silindiyse → `canary_files_intact = false`
5. Aynı anda `POST /api/alerts/urgent` ile severity=critical ransomware alert gönder

### VSS Shadow Koruma

1. `vssadmin list shadows` ile mevcut shadow sayısını periyodik kontrol et
2. Shadow sayısı azaldıysa → `vss_shadow_count` değeri düşer → anomali
3. `vssadmin delete shadows` komutu tespit edilirse → anlık critical alert

---

## 📋 WINDOWS EVENT LOG İZLEME

Client şu Windows Event Log'ları izlemeli (config'den hangi kanalların aktif olduğu kontrol edilir):

### Security Channel (`monitored_event_channels.security`)
| Event ID | Anlamı | Threat Score |
|----------|--------|-------------|
| 4624 | Başarılı logon | 40 (dış IP ise 75) |
| 4625 | Başarısız logon | 5 |
| 4720 | Yeni hesap oluşturuldu | 85 |
| 4722 | Hesap etkinleştirildi | 20 |
| 4725 | Hesap devre dışı | 20 |
| 4726 | Hesap silindi | 70 |
| 4672 | Özel yetkiler atandı | 30 |
| 4648 | Explicit credentials ile logon | 50 |
| 1102 | Audit log temizlendi | 90 |

### System Channel (`monitored_event_channels.system`)
| Event ID | Anlamı | Threat Score |
|----------|--------|-------------|
| 7036 | Servis başlatıldı/durduruldu | 3 |
| 7045 | Yeni servis yüklendi | 15 |

### RDP Channel (`monitored_event_channels.rdp`)
Kanal adı: `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational`
| Event ID | Anlamı | Threat Score |
|----------|--------|-------------|
| 1149 | RDP bağlantısı başarılı | 40 (dış IP ise 75) |

### Application Channel (`monitored_event_channels.application`)
Genel uygulama hatalarını izle, özellikle güvenlik yazılımı logları.

**Event Log okuma (Python — pywin32):**

```python
import win32evtlog
import win32evtlogutil

def watch_security_events(callback):
    """Security event log'u izle, her yeni olay için callback çağır."""
    server = 'localhost'
    log_type = 'Security'
    hand = win32evtlog.OpenEventLog(server, log_type)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    
    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        for event in events:
            callback(event)
        time.sleep(1)
```

---

## 🏗️ ÖNERİLEN DOSYA YAPISI

```
client/
├── config.json                 # API URL, token, servis ayarları
├── main.py                     # Ana giriş noktası, tüm modülleri başlatır
├── api_client.py               # API iletişim katmanı (mevcut — güncelle)
├── threat_engine.py            # YENİ: Tehdit algılama motoru
├── health_monitor.py           # YENİ: Sistem sağlık izleme
├── command_executor.py         # YENİ: Uzak komut yürütme
├── config_sync.py              # YENİ: Tehdit config senkronizasyonu
├── event_watcher.py            # YENİ: Windows Event Log izleme
├── ransomware_shield.py        # YENİ: Canary dosyalar + VSS koruma
├── silent_hours.py             # YENİ: Sessiz saat mantığı
├── services/                   # Honeypot servisleri (mevcut)
│   ├── fake_rdp.py
│   ├── fake_ssh.py
│   ├── fake_ftp.py
│   ├── fake_mysql.py
│   └── fake_mssql.py
├── firewall.py                 # Windows Firewall yönetimi (mevcut — güncelle)
├── rdp_manager.py              # RDP port taşıma (mevcut — koru)
└── utils/
    ├── logger.py
    └── crypto.py
```

---

## ⚙️ CONFIG.JSON GÜNCELLEMESİ

Mevcut config'e eklenmesi gereken yeni alanlar:

```json
{
    "api_url": "https://honeypot.yesnext.com.tr",
    "token": "0ea8836b-...",
    "log_level": "INFO",
    
    "// --- MEVCUT (DEĞİŞMEZ) ---": "",
    "heartbeat_interval": 60,
    "block_poll_interval": 30,
    "service_poll_interval": 120,
    "port_report_interval": 300,
    "services": {
        "rdp": {"enabled": true, "port": 3389},
        "ssh": {"enabled": false, "port": 22},
        "ftp": {"enabled": false, "port": 21},
        "mysql": {"enabled": false, "port": 3306},
        "mssql": {"enabled": false, "port": 1433}
    },
    "real_rdp_port": 53389,
    
    "// --- YENİ (EKLENMESİ GEREKEN) ---": "",
    "command_poll_interval": 10,
    "health_report_interval": 60,
    "event_batch_interval": 120,
    "config_sync_interval": 300,
    "event_buffer_max_size": 500,
    "canary_check_interval": 30,
    "canary_file_paths": [
        "C:\\Users\\Public\\Documents\\.FinancialReport2024.xlsx.canary",
        "C:\\Users\\Public\\Desktop\\.ImportantNotes.docx.canary",
        "C:\\ProgramData\\.SystemConfig.dat.canary"
    ]
}
```

---

## 📝 ÖZET: Yapılması Gerekenler Kontrol Listesi

### Yeni Modüller (oluşturulacak):

- [ ] `threat_engine.py` — Windows Event Log izleme, olay skorlama, alert tetikleme
- [ ] `health_monitor.py` — psutil ile sistem metrikleri toplama → POST /api/health/report
- [ ] `command_executor.py` — Komut polling (10sn), çalıştırma, sonuç bildirimi
- [ ] `config_sync.py` — Tehdit config çekme (5dk), local cache, silent hours kontrolü
- [ ] `event_watcher.py` — Windows Event Log subscription (Security, System, RDP, Application)
- [ ] `ransomware_shield.py` — Canary dosya oluşturma/izleme, VSS shadow takibi
- [ ] `silent_hours.py` — Zaman dilimi hesaplama, sessiz saat tespiti, otomatik aksiyon

### Mevcut Modüller (güncellenecek):

- [ ] `api_client.py` — Yeni 7 endpoint'i ekle (alerts/urgent, events/batch, health/report, alerts/auto-block, threats/config, commands/pending, commands/result)
- [ ] `firewall.py` — Auto-block sonrası `POST /api/alerts/auto-block` çağrısı ekle
- [ ] `main.py` — Yeni modüllerin başlatılması, zamanlama döngüleri eklenmesi
- [ ] `config.json` — Yeni yapılandırma alanları

### Mevcut Modüller (DEĞİŞMEYECEK):

- ✅ `rdp_manager.py` — RDP port taşıma aynen kalacak
- ✅ `services/fake_*.py` — Honeypot servisleri aynen kalacak
- ✅ Heartbeat, attack raporu, port raporu, blok yönetimi — aynen kalacak

---

## ⚠️ KRİTİK KURALLAR

1. **Platform:** Windows 10/11. PyInstaller ile tek .exe'ye derlenir.
2. **Kaynak tüketimi DÜŞÜK olmalı:** Idle durumda <50MB RAM, <1% CPU.
3. **Event Log izleme verimli olmalı:** Subscription tabanlı (push), polling değil.
4. **Config cache:** Sunucuya ulaşılamazsa son başarılı config ile çalışmaya devam et.
5. **Komut timeout:** Bir komut 30 saniyeden uzun sürerse `status: 'failed'` olarak bildir.
6. **Tüm API çağrıları try/except ile sarılmalı.** Ağ hatası client'ı ASLA çökertmemeli.
7. **Canary dosyalar gizli olmalı:** Hidden + System attribute, kullanıcı fark etmemeli.
8. **Auto-block rate limiting:** Saatte max 50, günde max 200 (config'den gelir).
9. **PROTECTED_ACCOUNTS listesi:** `administrator`, `system`, `networkservice`, `localservice`, `defaultaccount` — bu hesaplar disable/reset edilemez.
