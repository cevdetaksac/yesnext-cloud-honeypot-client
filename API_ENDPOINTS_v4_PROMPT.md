# 🔌 Cloud Honeypot API — v4.0 Tehdit Algılama Endpointleri

## Backend Geliştirme Prompt'u

Bu doküman, Cloud Honeypot Client v4.0'ın ihtiyaç duyduğu yeni API endpointlerini
backend geliştirici için hazırlanmış bir prompt/spec olarak tanımlar.

---

## Mevcut API Yapısı (Referans)

Base URL: `https://honeypot.yesnext.com.tr/api`

Mevcut endpointler:
- `POST /register` — Client kayıt
- `POST /heartbeat` — Periyodik heartbeat
- `POST /attack` — Tekil saldırı raporu
- `POST /attack/batch` — Toplu saldırı raporu
- `GET  /attack-count?token=X` — Saldırı sayısı
- `POST /update-ip` — IP güncelleme
- `POST /report-ports` — Açık port raporu
- `POST /report-action` — Servis aksiyonu raporu
- `GET  /service-status?token=X` — Dashboard desired state
- `POST /service-status/update` — Servis durumu güncelleme
- `GET  /agent/pending-blocks` — Bekleyen IP blokları
- `GET  /agent/pending-unblocks` — Kaldırılacak bloklar
- `POST /agent/block-applied` — Blok uygulandı onayı
- `POST /agent/block-removed` — Blok kaldırıldı onayı
- `POST /agent/sync-rules` — Client firewall kurallarını API ile senkronize et (v4.1.1)

Authentication: Tüm isteklerde `token` (string) body veya query param olarak gönderilir.

---

## YENİ ENDPOINTLERİN DETAYLI TANIMI

---

### 1. 🔴 POST /api/alerts/urgent

**Amaç:** Kritik güvenlik tehdidi anlık bildirimi. Client, tehdit skoru yüksek bir olay tespit ettiğinde bu endpoint'e anında istek atar.

**Tetikleyici durumlar:**
- Başarılı RDP/SSH/SQL logon tespiti (Event 4624 Type 10, 1149)
- Brute force sonrası başarılı giriş
- Yeni admin hesabı oluşturulması
- Audit log temizlenmesi
- Ransomware göstergeleri (canary file değişimi, VSS silme)
- Şüpheli süreç çalıştırma (vssadmin delete shadows vb.)

**Request:**

```json
POST /api/alerts/urgent
Content-Type: application/json

{
    "token": "client-registration-token",
    "alert": {
        "alert_id": "550e8400-e29b-41d4-a716-446655440000",
        "timestamp": "2026-02-08T23:15:42.123Z",
        "severity": "critical",
        "threat_type": "brute_force_success",
        "title": "RDP Brute Force — Başarılı Giriş Tespit Edildi!",
        "description": "192.168.1.105 adresinden 47 başarısız denemenin ardından 'administrator' hesabıyla başarılı RDP girişi yapıldı. Logon Type: 10 (RemoteInteractive). Hesap ele geçirilmiş olabilir!",
        "source_ip": "192.168.1.105",
        "source_country": "RU",
        "source_city": "Moscow",
        "target_service": "RDP",
        "target_port": 3389,
        "username": "administrator",
        "threat_score": 95,
        "windows_event_ids": [4625, 4625, 4625, 4624, 4672],
        "correlation_rule": "brute_force_then_access",
        "recommended_action": "Hesap şifresini hemen değiştirin. Aktif oturumu kapatın. Sunucuyu zararlı süreçler için kontrol edin.",
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
            "os_version": "Windows Server 2022 Datacenter",
            "cpu_percent": 45.2,
            "memory_percent": 68.1,
            "uptime_hours": 142.5,
            "active_honeypot_services": ["RDP", "SSH", "MSSQL"]
        }
    }
}
```

**Response (200 OK):**

```json
{
    "status": "received",
    "alert_id": "550e8400-e29b-41d4-a716-446655440000",
    "notification_sent": true,
    "notification_channels": ["email", "dashboard"],
    "actions_requested": []
}
```

**Backend davranışı:**
1. Alert'i veritabanına kaydet (alerts tablosu)
2. Token'a bağlı kullanıcıyı bul
3. **severity = critical** ise → **anlık e-posta** gönder
4. **severity = high** ise → kullanıcı tercihine göre e-posta
5. Dashboard'da real-time göster (WebSocket varsa push, yoksa poll edilecek)
6. Opsiyonel: Webhook URL tanımlıysa, webhook gönder (Slack, Teams vb.)
7. `actions_requested` ile client'a ek talimat gönderebilir (ör. "disable_account")

**E-posta şablonu önerisi:**

```
Konu: ⚠️ KRİTİK: RDP Brute Force — Başarılı Giriş! [WIN-SERVER01]

Sayın Kullanıcı,

Sunucunuz WIN-SERVER01'de kritik bir güvenlik tehdidi tespit edildi:

🔴 Tehdit: RDP Brute Force — Başarılı Giriş
📍 Saldırgan IP: 192.168.1.105 (Rusya, Moskova)
👤 Kullanılan Hesap: administrator
🕐 Zaman: 08.02.2026 23:15:42
📊 Tehdit Skoru: 95/100

⚡ Otomatik Alınan Önlemler:
  • Saldırgan IP engellendi (24 saat)
  
🛠️ Önerilen Aksiyonlar:
  1. 'administrator' hesap şifresini hemen değiştirin
  2. Aktif oturumları kontrol edin
  3. Sunucuda şüpheli süreçleri kontrol edin

📊 Dashboard: https://honeypot.yesnext.com.tr/dashboard?token=XXX

Cloud Honeypot Client v4.0
```

---

### 2. 🟡 POST /api/events/batch

**Amaç:** Düşük-orta öncelikli güvenlik olaylarının toplu raporu. Client her 1-5 dakikada bir birikmiş olayları gönderir.

**Request:**

```json
POST /api/events/batch
Content-Type: application/json

{
    "token": "client-registration-token",
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
        },
        {
            "event_id": "uuid-v4",
            "timestamp": "2026-02-08T23:10:06Z",
            "category": "failed_logon",
            "severity": "info",
            "source_ip": "185.220.101.34",
            "source_country": "DE",
            "target_service": "SSH",
            "target_port": 22,
            "username": "admin",
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
        "unique_source_ips": 23,
        "top_source_ips": [
            {"ip": "185.220.101.34", "country": "DE", "count": 45},
            {"ip": "91.240.118.12", "country": "RU", "count": 38}
        ],
        "top_targeted_services": {"SSH": 89, "RDP": 45, "MSSQL": 22},
        "top_usernames": {"root": 34, "admin": 28, "sa": 15}
    }
}
```

**Response (200 OK):**

```json
{
    "status": "received",
    "batch_id": "uuid-v4",
    "events_processed": 156
}
```

**Backend davranışı:**
1. Events'leri bulk insert (time-series tablo veya InfluxDB/TimescaleDB)
2. Summary verilerini aggregate tablolarına yaz
3. Dashboard istatistiklerini güncelle
4. Trend analizi / anomali tespiti için kullan (backend tarafı)

---

### 3. 💚 POST /api/health/report

**Amaç:** Sunucu sistem sağlık metrikleri. Periyodik olarak (her 60sn) gönderilir.

**Request:**

```json
POST /api/health/report
Content-Type: application/json

{
    "token": "client-registration-token",
    "snapshot": {
        "timestamp": "2026-02-08T23:15:00Z",
        "cpu_percent": 92.5,
        "memory_percent": 88.3,
        "memory_total_gb": 32.0,
        "memory_used_gb": 28.2,
        "disk_usage_percent": 76.0,
        "disk_total_gb": 500,
        "disk_free_gb": 120,
        "disk_io_read_bytes_sec": 150000000,
        "disk_io_write_bytes_sec": 250000000,
        "network_bytes_sent_sec": 5000000,
        "network_bytes_recv_sec": 1200000,
        "process_count": 245,
        "open_connections": 89,
        "top_cpu_processes": [
            {"name": "sqlservr.exe", "pid": 1234, "cpu_percent": 35.2, "memory_mb": 4096},
            {"name": "svchost.exe", "pid": 5678, "cpu_percent": 12.1, "memory_mb": 256}
        ],
        "anomalies_detected": ["cpu_spike", "disk_io_spike"],
        "vss_shadow_count": 5,
        "ransomware_shield_status": "active",
        "canary_files_intact": true
    }
}
```

**Response (200 OK):**

```json
{
    "status": "received"
}
```

**Backend davranışı:**
1. Metrikleri zaman serisi olarak sakla
2. Dashboard'da grafiksel gösterim için hazırla
3. CPU > 90% veya RAM > 95% gibi eşiklerde dashboard uyarısı
4. `anomalies_detected` boş değilse kullanıcıya bilgi ver
5. `canary_files_intact = false` → Ransomware uyarısı tetikle

---

### 4. 🔐 POST /api/alerts/auto-block

**Amaç:** Client'ın otomatik olarak engellediği IP'lerin backend'e bildirilmesi. Senkronizasyon ve audit trail için.

**Request:**

```json
POST /api/alerts/auto-block
Content-Type: application/json

{
    "token": "client-registration-token",
    "blocked_ip": "192.168.1.105",
    "reason": "brute_force_success",
    "threat_score": 95,
    "related_alert_id": "550e8400-e29b-41d4-a716-446655440000",
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

**Response (200 OK):**

```json
{
    "status": "confirmed",
    "block_id": "uuid-v4",
    "extend_duration": false,
    "permanent_block": false
}
```

**Backend davranışı:**
1. Blocked IP'yi veritabanına kaydet
2. Dashboard'da "Otomatik Engellenen IP'ler" listesinde göster
3. Mevcut `pending-blocks` sistemiyle senkronize et (çift engellemeyi önle)
4. `extend_duration: true` dönerse client süreyi uzatır
5. `permanent_block: true` dönerse client kalıcı kural oluşturur

---

### 4b. 🔄 POST /api/agent/sync-rules (v4.1.1)

**Amaç:** Client başlatıldığında mevcut firewall kurallarını backend ile senkronize eder. Dashboard ve client aynı blok listesini gösterir.

**Ne zaman çağrılır:** Client her başlatıldığında (FirewallAgent.run_forever() başlangıcında) otomatik olarak bir kez çağrılır.

**Request:**

```json
POST /api/agent/sync-rules
Content-Type: application/json

{
    "token": "client-registration-token",
    "blocks": [
        {
            "ip": "45.132.181.87",
            "rule_name": "HP-BLOCK-45.132.181.87",
            "source": "auto_response",
            "reason": "brute_force",
            "blocked_at": 1739145600.0
        },
        {
            "ip": "103.54.59.128",
            "rule_name": "HP-BLOCK-42",
            "source": "dashboard",
            "reason": "",
            "blocked_at": ""
        }
    ],
    "total_rules": 2,
    "synced_at": "2026-02-09T17:30:00Z"
}
```

**Response (200 OK):**

```json
{
    "status": "synced",
    "accepted": 2,
    "removed_stale": 0
}
```

**Backend davranışı:**
1. Token'a ait mevcut "aktif blok" listesini bu payload ile güncelle
2. Client'ta var ama backend'te yok olan blokları ekle
3. Backend'te var ama client'ta yok olan blokları "stale" olarak işaretle
4. Dashboard "Uygulanan Bloklar" panelini senkronize et
5. `source` alanı blokun kaynağını belirtir: `auto_response` veya `dashboard`

**Fallback:** Eğer backend bu endpoint'i henüz desteklemiyorsa (HTTP != 200), client mevcut `POST /api/alerts/auto-block` endpoint'ine tek tek blok bildirimi yapar.

---

### 5. 📊 GET /api/threats/summary

**Amaç:** Belirli bir dönem için tehdit özet istatistikleri. Dashboard ve rapor için.

**Request:**

```
GET /api/threats/summary?token=abc-123&period=24h
```

**Query parametreleri:**
- `token` (required) — Client token
- `period` (optional) — `1h`, `6h`, `24h`, `7d`, `30d` (default: `24h`)

**Response (200 OK):**

```json
{
    "period": "24h",
    "period_start": "2026-02-07T23:15:00Z",
    "period_end": "2026-02-08T23:15:00Z",
    "total_events": 1523,
    "alerts": {
        "critical": 3,
        "high": 12,
        "warning": 45,
        "info": 1463
    },
    "unique_attackers": 45,
    "top_attackers": [
        {
            "ip": "185.220.101.34",
            "country": "DE",
            "city": "Frankfurt",
            "total_events": 234,
            "max_threat_score": 95,
            "services_targeted": ["SSH", "RDP"],
            "is_blocked": true
        },
        {
            "ip": "91.240.118.12",
            "country": "RU",
            "city": "St Petersburg",
            "total_events": 189,
            "max_threat_score": 80,
            "services_targeted": ["MSSQL"],
            "is_blocked": true
        }
    ],
    "top_targeted_services": {
        "RDP": 456,
        "SSH": 312,
        "MSSQL": 189,
        "FTP": 45,
        "MySQL": 12
    },
    "successful_logons_detected": 2,
    "auto_blocks_applied": 8,
    "system_health": "warning",
    "system_health_details": "CPU usage elevated (avg 78%)",
    "ransomware_shield": "active",
    "canary_files_status": "intact"
}
```

---

### 6. ⚙️ GET /api/threats/config

**Amaç:** Client'ın tehdit algılama konfigürasyonunu backend'den çekmesi. Dashboard üzerinden kullanıcı bu ayarları değiştirebilir.

**Request:**

```
GET /api/threats/config?token=abc-123
```

**Response (200 OK):**

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

**Backend davranışı:**
- Client bu config'i başlangıçta ve her 5 dakikada bir çeker
- Dashboard'dan kullanıcı ayarları değiştirdiğinde güncellenir
- İlk kayıtta varsayılan değerler atanır

---

### 7. 🔔 PUT /api/notifications/preferences

**Amaç:** Kullanıcının bildirim tercihlerini güncellemesi.

**Request:**

```json
PUT /api/notifications/preferences
Content-Type: application/json

{
    "token": "client-registration-token",
    "email_alerts": true,
    "alert_email": "admin@company.com",
    "min_severity_for_email": "high",
    "daily_digest": true,
    "digest_time": "09:00",
    "instant_for_critical": true,
    "webhook_url": "https://hooks.slack.com/services/...",
    "webhook_enabled": true
}
```

**Response (200 OK):**

```json
{
    "status": "updated",
    "preferences": { ... }
}
```

---

### 8. 🎮 GET /api/commands/pending

**Amaç:** Client'ın dashboard'dan gönderilen uzaktan müdahale komutlarını alması. Mevcut `pending-blocks` pattern'inin genelleştirilmiş hali.

**Request:**

```
GET /api/commands/pending?token=client-registration-token
```

**Response (200 OK — Bekleyen komutlar var):**

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
            "requested_at": "2024-01-15T03:12:45Z",
            "expires_at": "2024-01-15T03:17:45Z",
            "priority": "high"
        },
        {
            "command_id": "cmd-uuid-2",
            "command_type": "logoff_user",
            "params": {
                "username": "attacker",
                "session_id": 3
            },
            "requested_by": "admin@company.com",
            "requested_at": "2024-01-15T03:12:50Z",
            "expires_at": "2024-01-15T03:17:50Z",
            "priority": "high"
        }
    ]
}
```

**Response (200 OK — Bekleyen komut yok):**

```json
{
    "commands": []
}
```

**Desteklenen `command_type` değerleri:**

| command_type | Açıklama | params |
|---|---|---|
| `block_ip` | IP adresini firewall'da engelle | `ip`, `duration_hours` (0=kalıcı), `reason` |
| `unblock_ip` | IP engelini kaldır | `ip` |
| `logoff_user` | Kullanıcı oturumunu kapat | `username`, `session_id` (opsiyonel) |
| `disable_account` | Kullanıcı hesabını devre dışı bırak | `username` |
| `enable_account` | Hesabı yeniden etkinleştir | `username` |
| `reset_password` | Kullanıcı şifresini sıfırla | `username`, `new_password` |
| `kill_process` | Süreç sonlandır | `pid` veya `process_name` |
| `stop_service` | Windows servisini durdur | `service_name` |
| `start_service` | Windows servisini başlat | `service_name` |
| `restart_service` | Windows servisini yeniden başlat | `service_name` |
| `enable_lockdown` | Acil durum kilidi aktifleştir | `management_ip`, `duration_minutes` |
| `disable_lockdown` | Acil durum kilidini kaldır | — |
| `collect_diagnostics` | Sistem teşhis bilgisi topla | — |
| `list_sessions` | Aktif oturumları listele | — |

**Backend Davranışı:**

1. Sadece `expires_at > NOW()` ve `status = 'pending'` komutları döndür
2. Döndürülen komutların durumunu `'dispatched'` yap (tekrar gönderilmemesi için)
3. Komut yaşam süresi: 5 dakika (sonra expire)
4. Priority sıralaması: `critical > high > normal`

**Güvenlik:**

- Token bazlı authentication (mevcut sistem)
- Komutları sadece ilgili token'ın sahibi (dashboard admin) oluşturabilir
- Koruma listesi: `Administrator`, `SYSTEM`, `NetworkService` hesapları disable/reset edilemez
- Tüm komutlar audit log'a yazılır

---

### 9. 📤 POST /api/commands/result

**Amaç:** Client'ın komut yürütme sonucunu API'ye bildirmesi.

**Request:**

```json
POST /api/commands/result
Content-Type: application/json

{
    "token": "client-registration-token",
    "command_id": "cmd-uuid-1",
    "status": "completed",
    "result": {
        "success": true,
        "message": "IP 203.0.113.50 başarıyla engellendi",
        "details": {
            "rule_name": "HONEYPOT_BLOCK_REMOTE_203.0.113.50",
            "applied_at": "2024-01-15T03:12:52Z"
        }
    },
    "executed_at": "2024-01-15T03:12:52Z",
    "execution_time_ms": 1250
}
```

**Başarısız sonuç örneği:**

```json
{
    "token": "client-registration-token",
    "command_id": "cmd-uuid-2",
    "status": "failed",
    "result": {
        "success": false,
        "message": "Kullanıcı oturumu kapatılamadı",
        "error_code": "SESSION_NOT_FOUND",
        "details": {
            "reason": "Belirtilen session_id aktif değil"
        }
    },
    "executed_at": "2024-01-15T03:12:55Z",
    "execution_time_ms": 350
}
```

**Güvenlik ihlali nedeniyle reddedilme:**

```json
{
    "token": "client-registration-token",
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
    "executed_at": "2024-01-15T03:13:01Z",
    "execution_time_ms": 5
}
```

**Response (200 OK):**

```json
{
    "status": "received",
    "command_id": "cmd-uuid-1"
}
```

**Backend Davranışı:**

1. `pending_commands` tablosunda komutu güncelle: `status`, `result`, `executed_at`, `execution_time_ms`
2. Dashboard'a WebSocket push (varsa): komut durumu güncellendi
3. Başarısız komutlar için dashboard'da uyarı göster
4. Audit log'a yaz: kim istedi, ne oldu, sonuç ne
5. `rejected` komutlar güvenlik alarmı tetikleyebilir (yetkisiz erişim girişimi olabilir)

---

## VERİTABANI ŞEMA ÖNERİSİ

### Yeni Tablolar

```sql
-- Tehdit alertleri
CREATE TABLE threat_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token VARCHAR(255) NOT NULL REFERENCES clients(token),
    alert_id UUID NOT NULL UNIQUE,
    timestamp TIMESTAMPTZ NOT NULL,
    severity VARCHAR(20) NOT NULL,  -- info, warning, high, critical
    threat_type VARCHAR(100) NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    source_ip INET,
    source_country VARCHAR(2),
    source_city VARCHAR(100),
    target_service VARCHAR(20),
    target_port INTEGER,
    username VARCHAR(256),
    threat_score INTEGER,
    correlation_rule VARCHAR(100),
    auto_response_taken JSONB,
    raw_events JSONB,
    system_context JSONB,
    notification_sent BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    
    INDEX idx_alerts_token_time (token, timestamp DESC),
    INDEX idx_alerts_severity (severity),
    INDEX idx_alerts_source_ip (source_ip)
);

-- Güvenlik olayları (time-series)
CREATE TABLE security_events (
    id BIGSERIAL PRIMARY KEY,
    token VARCHAR(255) NOT NULL,
    event_id UUID,
    timestamp TIMESTAMPTZ NOT NULL,
    category VARCHAR(50),           -- failed_logon, successful_logon, new_service, etc.
    severity VARCHAR(20),
    source_ip INET,
    source_country VARCHAR(2),
    target_service VARCHAR(20),
    target_port INTEGER,
    username VARCHAR(256),
    windows_event_id INTEGER,
    logon_type INTEGER,
    threat_score INTEGER,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    
    INDEX idx_events_token_time (token, timestamp DESC),
    INDEX idx_events_category (category),
    INDEX idx_events_source_ip (source_ip)
);
-- TimescaleDB varsa: SELECT create_hypertable('security_events', 'timestamp');

-- Otomatik engellenen IP'ler
CREATE TABLE auto_blocks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token VARCHAR(255) NOT NULL,
    blocked_ip INET NOT NULL,
    reason VARCHAR(100),
    threat_score INTEGER,
    related_alert_id UUID REFERENCES threat_alerts(alert_id),
    duration_hours INTEGER DEFAULT 24,
    blocked_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    is_permanent BOOLEAN DEFAULT false,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    
    INDEX idx_blocks_token (token),
    INDEX idx_blocks_active (is_active, expires_at)
);

-- Sistem sağlık metrikleri
CREATE TABLE system_health (
    id BIGSERIAL PRIMARY KEY,
    token VARCHAR(255) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    cpu_percent REAL,
    memory_percent REAL,
    disk_usage_percent REAL,
    disk_io_read_bytes_sec BIGINT,
    disk_io_write_bytes_sec BIGINT,
    network_bytes_sent_sec BIGINT,
    network_bytes_recv_sec BIGINT,
    process_count INTEGER,
    open_connections INTEGER,
    anomalies JSONB,
    top_processes JSONB,
    ransomware_status VARCHAR(20),
    canary_intact BOOLEAN,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    
    INDEX idx_health_token_time (token, timestamp DESC)
);
-- TimescaleDB varsa: SELECT create_hypertable('system_health', 'timestamp');

-- Tehdit konfigürasyonu
CREATE TABLE threat_config (
    token VARCHAR(255) PRIMARY KEY REFERENCES clients(token),
    auto_block_enabled BOOLEAN DEFAULT true,
    auto_block_threshold INTEGER DEFAULT 80,
    auto_block_duration_hours INTEGER DEFAULT 24,
    whitelist_ips JSONB DEFAULT '[]',
    whitelist_subnets JSONB DEFAULT '[]',
    alert_email VARCHAR(255),
    alert_email_enabled BOOLEAN DEFAULT true,
    min_severity_for_email VARCHAR(20) DEFAULT 'high',
    daily_digest_enabled BOOLEAN DEFAULT true,
    daily_digest_time TIME DEFAULT '09:00',
    webhook_url TEXT,
    webhook_enabled BOOLEAN DEFAULT false,
    ransomware_protection BOOLEAN DEFAULT true,
    canary_files_enabled BOOLEAN DEFAULT true,
    working_hours JSONB,
    
    -- Sessiz saatler (otomatik engelleme)
    silent_hours_enabled BOOLEAN DEFAULT true,
    silent_hours_mode VARCHAR(20) DEFAULT 'night_only',  -- disabled, night_only, outside_working, always, custom
    silent_hours_night_start TIME DEFAULT '00:00',
    silent_hours_night_end TIME DEFAULT '07:00',
    silent_hours_weekend_all_day BOOLEAN DEFAULT true,
    silent_hours_auto_block_ip BOOLEAN DEFAULT true,
    silent_hours_auto_logoff BOOLEAN DEFAULT true,
    silent_hours_auto_disable_account BOOLEAN DEFAULT true,
    silent_hours_block_duration_hours INTEGER DEFAULT 0,  -- 0 = kalıcı
    silent_hours_whitelist_ips JSONB DEFAULT '[]',
    silent_hours_whitelist_subnets JSONB DEFAULT '[]',
    
    emergency_lockdown_enabled BOOLEAN DEFAULT false,
    lockdown_management_ip INET,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Bildirim log
CREATE TABLE notification_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token VARCHAR(255) NOT NULL,
    alert_id UUID REFERENCES threat_alerts(alert_id),
    channel VARCHAR(20) NOT NULL,   -- email, webhook, push, dashboard
    recipient VARCHAR(255),
    status VARCHAR(20),             -- sent, failed, queued
    sent_at TIMESTAMPTZ,
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Uzaktan müdahale komutları
CREATE TABLE pending_commands (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    command_id UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    token VARCHAR(255) NOT NULL REFERENCES clients(token),
    command_type VARCHAR(50) NOT NULL,  -- block_ip, logoff_user, kill_process, etc.
    params JSONB NOT NULL DEFAULT '{}',
    priority VARCHAR(20) DEFAULT 'high',  -- critical, high, normal
    status VARCHAR(20) DEFAULT 'pending', -- pending, dispatched, completed, failed, rejected, expired
    requested_by VARCHAR(255),            -- Dashboard kullanıcı email'i
    requested_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ DEFAULT NOW() + INTERVAL '5 minutes',
    dispatched_at TIMESTAMPTZ,            -- Client'a gönderilme zamanı
    executed_at TIMESTAMPTZ,              -- Client'ta çalıştırılma zamanı
    execution_time_ms INTEGER,
    result JSONB,                         -- Yürütme sonucu (success/error detayları)
    related_alert_id UUID REFERENCES threat_alerts(alert_id),  -- İlişkili tehdit alert'i
    created_at TIMESTAMPTZ DEFAULT NOW(),
    
    INDEX idx_commands_token_pending (token, status, expires_at),
    INDEX idx_commands_status (status),
    INDEX idx_commands_requested_by (requested_by)
);

-- Komut denetim logu (audit trail — hiçbir zaman silinmez)
CREATE TABLE command_audit_log (
    id BIGSERIAL PRIMARY KEY,
    command_id UUID NOT NULL,
    token VARCHAR(255) NOT NULL,
    command_type VARCHAR(50) NOT NULL,
    params JSONB,
    requested_by VARCHAR(255),
    status VARCHAR(20) NOT NULL,
    result JSONB,
    executed_at TIMESTAMPTZ,
    client_ip INET,                      -- Client'ın API'ye bağlandığı IP
    created_at TIMESTAMPTZ DEFAULT NOW(),
    
    INDEX idx_audit_token (token),
    INDEX idx_audit_command_id (command_id)
);
```

---

## ENTEGRASYON NOTLARI

### E-posta Servisi
- Backend'de mevcut e-posta altyapısı varsa kullanılabilir (SendGrid, SES, SMTP)
- `threat_alerts` tablosuna insert sonrası trigger veya uygulama katmanında async gönderim
- Rate limiting: Aynı token'a saatte max 10 critical e-posta

### Webhook Entegrasyonu
- `threat_config.webhook_url` doluysa, urgent alert'lerde POST isteği at
- Slack/Teams format uyumlu JSON payload
- Retry: 3 deneme, exponential backoff

### Dashboard WebSocket (Opsiyonel)
- `/ws/alerts?token=X` — Gerçek zamanlı alert akışı
- Urgent alert geldiğinde tüm bağlı dashboard'lara push
- Yoksa client polling ile dashboard'u güncelleyebilir

### Data Retention
- `security_events`: 90 gün (sonra aggregate'e taşı)
- `threat_alerts`: 1 yıl
- `system_health`: 30 gün
- `auto_blocks`: 1 yıl
- `notification_log`: 90 gün
- `pending_commands`: 90 gün (tamamlanan/expired komutlar temizlenir)
- `command_audit_log`: Süresiz (güvenlik denetimi — hiçbir zaman silinmez)

---

## ÖZET: Endpoint Listesi

| # | Method | Endpoint | Öncelik | Faz |
|---|--------|----------|---------|-----|
| 1 | POST | `/api/alerts/urgent` | 🔴 Kritik | Faz 1 |
| 2 | POST | `/api/events/batch` | 🟡 Yüksek | Faz 1 |
| 3 | POST | `/api/health/report` | 🟢 Normal | Faz 3 |
| 4 | POST | `/api/alerts/auto-block` | 🟠 Yüksek | Faz 2 |
| 5 | GET  | `/api/threats/summary` | 🟢 Normal | Faz 4 |
| 6 | GET  | `/api/threats/config` | 🟠 Yüksek | Faz 2 |
| 7 | PUT  | `/api/notifications/preferences` | 🟢 Normal | Faz 4 |
| 8 | GET  | `/api/commands/pending` | 🔴 Kritik | Faz 2 |
| 9 | POST | `/api/commands/result` | 🔴 Kritik | Faz 2 |

**Faz 1'de minimum açılması gereken:** `POST /api/alerts/urgent` + `POST /api/events/batch` + E-posta gönderim mekanizması.

**Faz 2'de uzaktan müdahale için:** `GET /api/commands/pending` + `POST /api/commands/result` + Dashboard komut UI.
