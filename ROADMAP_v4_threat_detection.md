# 🛡️ Cloud Honeypot Client v4.0 — Gelişmiş Tehdit Algılama Sistemi

## Yol Haritası & Mimari Tasarım

**Tarih:** 8 Şubat 2026  
**Mevcut Versiyon:** v3.1.0  
**Hedef Versiyon:** v4.0.0  
**Yazar:** Geliştirme Ekibi

---

## 📋 İçindekiler

1. [Mevcut Durum Analizi](#1-mevcut-durum-analizi)
2. [Tehdit Modeli — Neden Gerekli?](#2-tehdit-modeli--neden-gerekli)
3. [Mimari Genel Bakış](#3-mimari-genel-bakış)
4. [Modül 1 — Windows Event Log İzleyici](#4-modül-1--windows-event-log-i̇zleyici)
5. [Modül 2 — Gerçek Zamanlı Tehdit Motoru](#5-modül-2--gerçek-zamanlı-tehdit-motoru)
6. [Modül 3 — Anlık Bildirim Sistemi (Alert Pipeline)](#6-modül-3--anlık-bildirim-sistemi-alert-pipeline)
7. [Modül 4 — Otomatik Savunma (Auto-Response)](#7-modül-4--otomatik-savunma-auto-response)
8. [Modül 5 — Sistem Sağlık İzleme (System Health)](#8-modül-5--sistem-sağlık-i̇zleme-system-health)
9. [Modül 6 — Kripto Virüs / Ransomware Koruması](#9-modül-6--kripto-virüs--ransomware-koruması)
10. [Modül 7 — Uzaktan Müdahale (Remote Incident Response)](#10-modül-7--uzaktan-müdahale-remote-incident-response)
11. [Modül 8 — Sessiz Saatler & Süreç Koruma](#11-modül-8--sessiz-saatler--süreç-koruma-silent-hours--self-protection)
12. [GUI Güncellemeleri](#12-gui-güncellemeleri)
13. [Veri Yapıları & Formatlar](#13-veri-yapıları--formatlar)
14. [API Endpoint Gereksinimleri](#14-api-endpoint-gereksinimleri)
15. [Uygulama Fazları](#15-uygulama-fazları)
16. [Teknik Riskler & Çözümler](#16-teknik-riskler--çözümler)

---

## 1. Mevcut Durum Analizi

### ✅ Var Olan Yetenekler

| Alan | Durum | Detay |
|------|-------|-------|
| Honeypot Credential Capture | ✅ Çalışıyor | RDP, SSH, FTP, MSSQL, MySQL — kullanıcı/şifre/IP yakalama |
| API Raporlama | ✅ Çalışıyor | Tekil + batch attack reporting |
| Firewall Yönetimi | ✅ Çalışıyor | Backend-driven netsh kuralları |
| Heartbeat | ✅ Çalışıyor | 60sn aralıkla dosya + API heartbeat |
| Dashboard GUI | ✅ Çalışıyor | CustomTkinter, dark mode, 5sn refresh |

### 🔴 Kritik Eksiklikler

| Alan | Durum | Risk |
|------|-------|------|
| Windows Event Log İzleme | ❌ Yok | Gerçek sızmaları göremiyoruz |
| Başarılı Logon Tespiti | ❌ Yok | Saldırgan girdiyse bile haberimiz yok |
| Kripto/Ransomware Algılama | ❌ Yok | Dosya şifreleme başlayınca çok geç |
| Sistem Kaynak İzleme | ❌ Yok | Anormal CPU/RAM spike tespiti yok |
| Lokal Otomatik Engelleme | ❌ Yok | Firewall sadece backend talimatıyla çalışıyor |
| Anomali Tespiti | ❌ Yok | Davranış bazlı analiz yok |
| Uzaktan Müdahale | ❌ Yok | Dashboard'dan saldırı durdurma imkânı yok |
| Oturum Yönetimi | ❌ Yok | Şüpheli kullanıcıyı uzaktan logout yapamıyoruz |
| Süreç Kontrolü | ❌ Yok | Şüpheli exe/servis uzaktan durdurulamıyor |
| Sessiz Saatler Koruması | ❌ Yok | Mesai dışı girişler sorgulanmadan kabul ediliyor |
| Süreç Kendini Koruma | ❌ Yok | Saldırgan client.exe'yi durdurabilir, izleme devre dışı kalır |
| Anlık E-posta/Push Bildirimi | ❌ Yok | Kritik olaylarda kullanıcı habersiz |

---

## 2. Tehdit Modeli — Neden Gerekli?

### Gerçek Dünya Senaryosu (Kullanıcının Yaşadığı)

```
Saldırgan → Kullanılmayan MSSQL (1433) üzerinden giriş
         → xp_cmdshell veya linked server ile komut çalıştırma
         → Sunucuyu restart ettirme
         → Potansiyel ransomware/kripto virüs yükleme
```

### Saldırı Zinciri (Kill Chain)

```
┌─────────────┐   ┌──────────────┐   ┌─────────────┐   ┌──────────────┐
│ Keşif       │──▶│ Sızma        │──▶│ Yayılma     │──▶│ Hasar        │
│ Port scan   │   │ Brute force  │   │ Lateral     │   │ Ransomware   │
│ Banner grab │   │ Exploit      │   │ Priv. esc   │   │ Crypto miner │
│ Vuln scan   │   │ Default cred │   │ Persistence │   │ Data exfil   │
└─────────────┘   └──────────────┘   └─────────────┘   └──────────────┘
     ▲ Honeypot          ▲ YENİ              ▲ YENİ           ▲ YENİ
     tespit ediyor       Modül 1+2           Modül 4+6        Modül 6
```

**Mevcut sistem sadece "Keşif" aşamasını yakalıyor.** v4.0 ile tüm zinciri kapsayacağız.

---

## 3. Mimari Genel Bakış

```
                    ┌─────────────────────────────────┐
                    │       YesNext Cloud API          │
                    │  /alerts  /threats  /events      │
                    └──────────┬──────────────────────┘
                               │ HTTPS (batch + urgent)
                               │
    ┌──────────────────────────┴──────────────────────────┐
    │              Cloud Honeypot Client v4.0              │
    │                                                      │
    │  ┌──────────────┐  ┌──────────────┐  ┌────────────┐ │
    │  │ EventLog     │  │ Threat       │  │ Alert      │ │
    │  │ Watcher      │──▶ Engine       │──▶ Pipeline   │ │
    │  │ (win32evtlog)│  │ (scoring +   │  │ (API +     │ │
    │  └──────────────┘  │  correlation)│  │  local)    │ │
    │                     └──────┬───────┘  └─────┬──────┘ │
    │  ┌──────────────┐         │                 │        │
    │  │ System       │─────────┘                 │        │
    │  │ Health       │                           │        │
    │  │ (CPU/RAM/    │                    ┌──────┴──────┐ │
    │  │  Disk/Net)   │                    │ Auto        │ │
    │  └──────────────┘                    │ Response    │ │
    │                                      │ (firewall   │ │
    │  ┌──────────────┐                    │  + isolate) │ │
    │  │ Ransomware   │────────────────────┘             │ │
    │  │ Shield       │                                  │ │
    │  │ (file trap + │                                  │ │
    │  │  process     │                                  │ │
    │  │  monitor)    │                                  │ │
    │  └──────────────┘                                  │ │
    │                                                      │
    │  ┌──────────────────────────────────────────────┐   │
    │  │ 🎮 Remote Command Executor                    │   │
    │  │ Poll: /api/commands/pending                    │   │
    │  │ Actions: block_ip | logoff_user |              │   │
    │  │   kill_process | disable_account |             │   │
    │  │   change_password | emergency_lockdown         │   │
    │  │ Report: /api/commands/result                   │   │
    │  └──────────────────────────────────────────────┘   │
    │                                                      │
    │  ┌──────────────────────────────────────────────┐   │
    │  │ 🔇 Silent Hours Guard                         │   │
    │  │ Sessiz saatlerde başarılı giriş →             │   │
    │  │   Whitelist kontrolü → BLOCK + LOGOFF +       │   │
    │  │   DISABLE + ALERT (admin müdahalesiz)         │   │
    │  └──────────────────────────────────────────────┘   │
    │                                                      │
    │  ┌──────────────────────────────────────────────┐   │
    │  │ 🛡️ Process Self-Protection                    │   │
    │  │ Katman 1: Zamanlanmış Görev (auto-restart)  │   │
    │  │ Katman 2: Process DACL koruması               │   │
    │  │ Katman 3: Güvenli Son Nefes (sadece          │   │
    │  │   şüpheli IP block + alert — nuke yok!)       │   │
    │  └──────────────────────────────────────────────┘   │
    │                        ▲                             │
    │                        │ Dashboard'dan               │
    │                        │ kullanıcı komutu            │
    │                                                      │
    │  ┌──────────────────────────────────────────────┐   │
    │  │  Mevcut Sistemler (v3.1.0)                    │   │
    │  │  Honeypot Services │ Firewall │ GUI │ Tray    │   │
    │  └──────────────────────────────────────────────┘   │
    └──────────────────────────────────────────────────────┘
```

### Yeni Dosya Yapısı

```
cloud-client/
├── client.py                    # Ana orchestrator (mevcut)
├── client_api.py                # API iletişimi (mevcut — genişletilecek)
├── client_gui.py                # GUI (mevcut — genişletilecek)
├── client_firewall.py           # Firewall (mevcut)
├── client_monitoring.py         # Heartbeat (mevcut)
│
├── client_eventlog.py           # 🆕 Windows Event Log Watcher
├── client_threat_engine.py      # 🆕 Tehdit Skorlama & Korelasyon Motoru
├── client_alerts.py             # 🆕 Bildirim Pipeline (urgent + batch)
├── client_auto_response.py      # 🆕 Otomatik Savunma Aksiyonları
├── client_system_health.py      # 🆕 Sistem Kaynak İzleme
├── client_ransomware_shield.py  # 🆕 Kripto Virüs / Ransomware Koruması
├── client_remote_commands.py    # 🆕 Uzaktan Müdahale Komut Yürütücü
├── client_silent_hours.py       # 🆕 Sessiz Saatler Güvenlik Modülü
│
├── threat_rules.json            # 🆕 Tehdit kuralları konfigürasyonu
└── canary_tokens/               # 🆕 Ransomware tuzak dosyaları
```

---

## 4. Modül 1 — Windows Event Log İzleyici

**Dosya:** `client_eventlog.py`

### İzlenecek Event Kanalları & ID'ler

#### 🔐 Kimlik Doğrulama Olayları (Security Log)

| Event ID | Açıklama | Önem | Aksiyon |
|----------|----------|------|---------|
| **4624** | Başarılı logon | 🔴 Kritik | Anlık API bildirimi + e-posta |
| **4625** | Başarısız logon | 🟡 Orta | Sayaç tut, eşik aşımında alert |
| **4648** | Explicit credential logon | 🔴 Kritik | Lateral movement göstergesi |
| **4672** | Özel ayrıcalık atandı | 🔴 Kritik | Admin logon tespiti |
| **4720** | Yeni kullanıcı hesabı oluşturuldu | 🔴 Kritik | Persistence göstergesi |
| **4732** | Kullanıcı admin grubuna eklendi | 🔴 Kritik | Privilege escalation |
| **4735** | Güvenlik grubu değiştirildi | 🟠 Yüksek | Group policy manipulation |
| **4688** | Yeni süreç oluşturuldu | 🟡 Orta | Şüpheli süreç tespiti |
| **4697** | Yeni servis yüklendi | 🔴 Kritik | Malware persistence |
| **1102** | Audit log temizlendi | 🔴 Kritik | Anti-forensics! |

#### 🖥️ RDP Olayları (TerminalServices)

| Event ID | Kanal | Açıklama |
|----------|-------|----------|
| **1149** | TerminalServices-RemoteConnectionManager/Operational | RDP bağlantısı başarılı |
| **21** | TerminalServices-LocalSessionManager/Operational | RDP oturum başlangıcı |
| **24** | TerminalServices-LocalSessionManager/Operational | RDP oturum kapanışı |
| **25** | TerminalServices-LocalSessionManager/Operational | RDP yeniden bağlanma |

#### 💽 MSSQL Olayları (Application Log)

| Event ID | Kaynak | Açıklama |
|----------|--------|----------|
| **18453** | MSSQLSERVER | Başarılı SQL logon |
| **18456** | MSSQLSERVER | Başarısız SQL logon |
| **15457** | MSSQLSERVER | xp_cmdshell çalıştırıldı |
| **17135** | MSSQLSERVER | SQL Server başlatıldı (restart tespiti) |

#### ⚙️ Sistem Olayları (System Log)

| Event ID | Açıklama |
|----------|----------|
| **1074** | Sistem restart/shutdown |
| **6005** | Event Log servisi başlatıldı (= sistem açıldı) |
| **6006** | Event Log servisi durdu (= sistem kapandı) |
| **7045** | Yeni servis kuruldu |
| **7040** | Servis başlangıç tipi değiştirildi |

### Teknik Implementasyon

```python
class EventLogWatcher:
    """
    Windows Event Log'u gerçek zamanlı izler.
    win32evtlog.EvtSubscribe kullanarak push-based event alır.
    """
    
    WATCHED_CHANNELS = {
        "Security": [4624, 4625, 4648, 4672, 4720, 4732, 4688, 4697, 1102],
        "System": [1074, 6005, 6006, 7045, 7040],
        "Application": [18453, 18456, 15457, 17135],
        "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational": [1149],
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational": [21, 24, 25],
    }
    
    def __init__(self, threat_engine, config):
        self.threat_engine = threat_engine
        self.config = config
        self._subscriptions = []
        self._running = False
    
    def start(self):
        """Her kanal için EvtSubscribe ile abonelik oluştur."""
        # win32evtlog.EvtSubscribe(
        #     Path=channel,
        #     Flags=win32evtlog.EvtSubscribeToFutureEvents,
        #     Query=xpath_query,
        #     Callback=self._on_event
        # )
    
    def _on_event(self, reason, context, event_handle):
        """Event geldiğinde ThreatEngine'e ilet."""
        event_data = self._parse_event(event_handle)
        self.threat_engine.process_event(event_data)
    
    def _parse_event(self, handle):
        """Event XML'ini parse ederek yapılandırılmış dict döndürür."""
        # EvtRender ile XML al, ElementTree ile parse et
        return {
            "event_id": ...,
            "channel": ...,
            "timestamp": ...,
            "source_ip": ...,
            "username": ...,
            "logon_type": ...,  # 2=Interactive, 3=Network, 10=RemoteInteractive
            "process_name": ...,
            "raw_xml": ...,
        }
```

### Logon Type Haritası (Event 4624)

| Logon Type | Açıklama | Tehdit Seviyesi |
|-----------|----------|-----------------|
| 2 | Interactive (konsol) | Normal (filtre: yerel kullanıcı) |
| 3 | Network (SMB, SQL) | 🟠 Yüksek — uzak ağ erişimi |
| 4 | Batch (zamanlanmış görev) | 🟡 Orta |
| 5 | Service | Normal (bilinen servisler hariç) |
| 7 | Unlock (ekran kilidi) | Normal |
| 10 | RemoteInteractive (RDP) | 🔴 Kritik — uzak masaüstü |
| 11 | CachedInteractive | 🟡 Orta |

### Filtre Mantığı (False Positive Azaltma)

```python
IGNORED_ACCOUNTS = {
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
    "DWM-*", "UMFD-*",  # Desktop Window Manager
    "ANONYMOUS LOGON",
    "$"  # Machine accounts (ends with $)
}

IGNORED_LOGON_TYPES = {5, 7}  # Service logon, Screen unlock

WHITELISTED_IPS = set()  # Kullanıcı konfigüre edebilir
```

---

## 5. Modül 2 — Gerçek Zamanlı Tehdit Motoru

**Dosya:** `client_threat_engine.py`

### Mimari

```
Events ──▶ [Enrichment] ──▶ [Rule Matching] ──▶ [Scoring] ──▶ [Correlation] ──▶ [Alert Decision]
              │                    │                │               │                   │
         GeoIP lookup        threat_rules.json   0-100 skor     Zaman penceresi    Threshold check
         Reputation DB       Pattern matching    Ağırlıklı      Cross-event        → AlertPipeline
         Context add         Regex/YARA-like     toplam          link               → AutoResponse
```

### Tehdit Skorlama Sistemi

Her olay bir skor alır (0-100). Skorlar birikimli olarak IP bazında toplanır.

```python
THREAT_SCORES = {
    # Kimlik doğrulama
    "successful_logon_rdp":          85,   # RDP başarılı giriş
    "successful_logon_network":      70,   # Ağ üzerinden başarılı giriş
    "successful_logon_sql":          80,   # SQL başarılı giriş
    "failed_logon_single":            5,   # Tek başarısız deneme
    "failed_logon_burst":            40,   # 5dk'da 10+ başarısız (brute force)
    "failed_then_success":           95,   # Başarısız denemelerin ardından başarılı! 
    
    # Privilege escalation
    "new_admin_user":                90,   # Yeni admin hesabı
    "privilege_assigned":            75,   # Özel ayrıcalık
    "group_membership_change":       70,   # Grup değişikliği
    
    # Persistence
    "new_service_installed":         65,   # Yeni servis
    "new_scheduled_task":            60,   # Yeni zamanlanmış görev
    "suspicious_process":            55,   # Şüpheli süreç
    
    # Anti-forensics
    "audit_log_cleared":            100,   # Log temizleme = kesin saldırı
    "unexpected_restart":            50,   # Beklenmeyen restart
    
    # Ransomware indicators
    "canary_file_modified":         100,   # Tuzak dosya değişti
    "mass_file_rename":              95,   # Toplu dosya yeniden adlandırma
    "shadow_copy_deleted":          100,   # VSS silindi = ransomware!
    "suspicious_encryption_process": 90,   # Yoğun disk I/O + şüpheli süreç
}
```

### Korelasyon Kuralları

```python
CORRELATION_RULES = [
    {
        "name": "brute_force_then_access",
        "description": "Brute force ardından başarılı giriş — hesap ele geçirilmiş!",
        "conditions": [
            {"event": "failed_logon", "count": ">=5", "window": "10m"},
            {"event": "successful_logon", "from_same_ip": True, "window": "30m"},
        ],
        "score": 95,
        "severity": "critical",
        "auto_response": ["block_ip", "notify_urgent"],
    },
    {
        "name": "rdp_after_hours",
        "description": "Mesai dışı RDP erişimi",
        "conditions": [
            {"event": "successful_logon_rdp", "time_range": "00:00-06:00"},
        ],
        "score": 60,
        "severity": "high",
        "auto_response": ["notify_urgent"],
    },
    {
        "name": "lateral_movement",
        "description": "Bir IP'den birden fazla servise başarılı giriş",
        "conditions": [
            {"event": "successful_logon", "distinct_services": ">=2", "window": "1h"},
        ],
        "score": 85,
        "severity": "critical",
        "auto_response": ["block_ip", "notify_urgent"],
    },
    {
        "name": "post_exploitation",
        "description": "Başarılı giriş sonrası yeni servis/kullanıcı oluşturma",
        "conditions": [
            {"event": "successful_logon", "window": "1h"},
            {"event": "new_service_installed|new_admin_user", "window": "1h"},
        ],
        "score": 95,
        "severity": "critical",
        "auto_response": ["block_ip", "isolate_session", "notify_urgent"],
    },
    {
        "name": "ransomware_indicators",
        "description": "Ransomware aktivite zinciri",
        "conditions": [
            {"event": "shadow_copy_deleted|canary_file_modified|mass_file_rename", "count": ">=1"},
        ],
        "score": 100,
        "severity": "critical",
        "auto_response": ["emergency_lockdown", "notify_urgent"],
    },
]
```

### IP Bağlam Havuzu (Context Pool)

Her IP için tutulan durum:

```python
@dataclass
class IPContext:
    ip: str
    first_seen: float               # İlk görülme zamanı
    last_seen: float                # Son görülme
    failed_attempts: int = 0        # Toplam başarısız deneme
    successful_logins: int = 0      # Toplam başarılı giriş
    services_targeted: set = field(default_factory=set)  # Hedef servisler
    usernames_tried: set = field(default_factory=set)     # Denenen kullanıcılar
    threat_score: float = 0         # Birikimli tehdit skoru
    events: deque = field(default_factory=lambda: deque(maxlen=100))  # Son 100 event
    geo_country: str = ""           # GeoIP ülke kodu
    geo_city: str = ""              # GeoIP şehir
    is_blocked: bool = False        # Engellenmiş mi?
    alerts_sent: int = 0            # Gönderilen alert sayısı
```

---

## 6. Modül 3 — Anlık Bildirim Sistemi (Alert Pipeline)

**Dosya:** `client_alerts.py`

### Bildirim Seviyeleri

| Seviye | Skor Aralığı | Aksiyon | Gecikme |
|--------|-------------|---------|---------|
| 🔵 **info** | 0-30 | Sadece log + dashboard | Batch (5dk) |
| 🟡 **warning** | 31-60 | API batch + GUI toast | Batch (1dk) |
| 🟠 **high** | 61-80 | API anında + GUI popup | < 5sn |
| 🔴 **critical** | 81-100 | API anında + E-posta + SMS(?) + GUI popup | < 2sn |

### Alert Veri Yapısı

```python
@dataclass
class ThreatAlert:
    alert_id: str                    # UUID
    timestamp: float                 # Unix timestamp
    severity: str                    # info | warning | high | critical
    threat_type: str                 # brute_force | successful_logon | ransomware | ...
    title: str                       # Kısa açıklama
    description: str                 # Detaylı açıklama
    source_ip: str                   # Saldırgan IP
    source_country: str              # GeoIP ülke
    target_service: str              # RDP | SSH | MSSQL | ...
    target_port: int                 # Hedef port
    username: str                    # Kullanılan kullanıcı adı
    threat_score: int                # 0-100
    event_ids: List[int]             # İlişkili Windows Event ID'leri
    correlation_rule: str            # Tetikleyen kural adı (varsa)
    recommended_action: str          # Önerilen aksiyon
    auto_response_taken: List[str]   # Otomatik alınan aksiyonlar
    raw_events: List[dict]           # Ham event verileri
    machine_name: str                # Sunucu adı
    client_token: str                # Client token
```

### Bildirim Kanalları

```
Alert ──┬──▶ [API Urgent]  ──▶ Backend ──▶ E-posta / Push / Webhook
        │                                  (Backend tarafında)
        │
        ├──▶ [API Batch]   ──▶ Backend DB (düşük öncelikli olaylar)
        │
        ├──▶ [GUI Toast]   ──▶ Kullanıcı masaüstünde bildirim
        │
        ├──▶ [Tray Popup]  ──▶ Windows balloon notification
        │
        └──▶ [Local Log]   ──▶ threats.log (lokal dosya)
```

### Deduplikasyon & Rate Limiting

```python
# Aynı IP + aynı threat_type için:
ALERT_COOLDOWN = {
    "critical": 60,     # 1dk — kritik olaylar sık bildirilebilir
    "high": 300,        # 5dk
    "warning": 900,     # 15dk
    "info": 3600,       # 1 saat
}
```

---

## 7. Modül 4 — Otomatik Savunma (Auto-Response)

**Dosya:** `client_auto_response.py`

### Aksiyon Kataloğu

| Aksiyon | Tetikleyici | Açıklama |
|---------|-------------|----------|
| `block_ip` | Skor ≥ 80 | IP'yi Windows Firewall'a anlık ekle |
| `notify_urgent` | Skor ≥ 70 | API'ye acil alert gönder |
| `isolate_session` | Post-exploitation | Aktif RDP oturumunu kapat (logoff) |
| `disable_account` | Brute force success | Ele geçirilen hesabı devre dışı bırak |
| `emergency_lockdown` | Ransomware tespiti | Tüm inbound trafiği engelle (RDP hariç yönetim IP'si) |
| `snapshot_state` | Herhangi kritik | CPU/RAM/process listesi snapshot'ı al |

### Güvenlik Katmanları (Yanlışlıkla Kilitleme Önleme)

```python
SAFETY_GUARDS = {
    "max_blocks_per_hour": 50,          # Saatte max 50 IP engeli
    "max_blocks_per_day": 200,          # Günde max 200
    "whitelist_ips": ["127.0.0.1"],     # Asla engellenmeyecek IP'ler
    "whitelist_subnets": [],            # Kullanıcı tanımlı güvenli subnetler
    "require_confirmation_for": [       # Bu aksiyonlar için backend onayı gerekli
        "disable_account",
        "emergency_lockdown",
    ],
    "lockdown_management_ip": None,     # Lockdown sırasında erişime açık IP
    "auto_unblock_after_hours": 24,     # Otomatik engel kaldırma süresi
}
```

### Lokal Firewall Bloklama (Hızlı Yol)

```python
async def block_ip_immediately(self, ip: str, reason: str, duration_hours: int = 24):
    """
    Mevcut client_firewall.py'deki WindowsFirewall.add_rules() kullanılır.
    Backend'e de bildirilir (senkronizasyon için).
    
    1. netsh advfirewall firewall add rule ...
    2. API POST /api/alerts/auto-block { ip, reason, duration }
    3. Zamanlayıcıya unblock ekle
    """
```

---

## 8. Modül 5 — Sistem Sağlık İzleme (System Health)

**Dosya:** `client_system_health.py`

### İzlenecek Metrikler

```python
class SystemHealthMonitor:
    """
    psutil kullanarak sistem metriklerini toplar.
    Anomali tespiti için baseline oluşturur.
    """
    
    METRICS = {
        "cpu_percent":        {"interval": 10, "anomaly_threshold": 90},
        "memory_percent":     {"interval": 10, "anomaly_threshold": 90},
        "disk_usage_percent": {"interval": 60, "anomaly_threshold": 95},
        "disk_io_bytes":      {"interval": 10, "anomaly_threshold": "3x_baseline"},
        "network_bytes_sent": {"interval": 10, "anomaly_threshold": "5x_baseline"},
        "network_bytes_recv": {"interval": 10, "anomaly_threshold": "5x_baseline"},
        "process_count":      {"interval": 30, "anomaly_threshold": "2x_baseline"},
        "open_connections":   {"interval": 30, "anomaly_threshold": "3x_baseline"},
    }
```

### Anomali Tespiti (Basit Hareketli Ortalama)

```python
class AnomalyDetector:
    """
    Son N ölçümün ortalaması ve standart sapmasını tutarak
    anomali tespiti yapar. (Z-score > 3 = anomali)
    """
    
    def __init__(self, window_size=60):  # Son 60 ölçüm
        self.values = deque(maxlen=window_size)
    
    def add(self, value: float) -> bool:
        """Değer ekle, anomali varsa True döndür."""
        self.values.append(value)
        if len(self.values) < 10:
            return False  # Yeterli veri yok
        mean = statistics.mean(self.values)
        stdev = statistics.stdev(self.values)
        if stdev == 0:
            return False
        z_score = (value - mean) / stdev
        return z_score > 3.0
```

### Tehdit Motoruna Besleme

```
CPU %90+ sürekli ──▶ Kripto madenci şüphesi ──▶ Skor: 60
Disk I/O 5x spike ──▶ Ransomware şüphesi   ──▶ Skor: 70
Network 10x spike ──▶ Data exfiltration     ──▶ Skor: 65
```

---

## 9. Modül 6 — Kripto Virüs / Ransomware Koruması

**Dosya:** `client_ransomware_shield.py`

### Strateji: Çok Katmanlı Algılama

```
Katman 1: Canary Files (Tuzak Dosyalar)
         ↓
Katman 2: File System Watchdog (Toplu Değişiklik Tespiti)
         ↓
Katman 3: Process Behavior Analysis (Şüpheli Süreç Tespiti)
         ↓
Katman 4: Shadow Copy Monitor (VSS Silme Tespiti)
```

### Katman 1: Canary Files (Tuzak Dosyalar)

```python
CANARY_LOCATIONS = [
    r"C:\Users\{user}\Desktop\IMPORTANT_DOCUMENTS",
    r"C:\Users\{user}\Documents\Financial_Reports",
    r"C:\Users\Public\Documents\Company_Data",
    r"C:\Shares",  # Paylaşılan klasörler
]

CANARY_FILES = [
    "Q4_Financial_Report_2025.xlsx",
    "Employee_Database.csv", 
    "Client_Contracts.pdf",
    "Server_Passwords.docx",   # Saldırganı cezbedecek isimler
    "Backup_Keys.txt",
]
```

**Çalışma prensibi:**
1. Her konuma sahte dosyalar oluşturulur (gerçek boyut, gerçek uzantı)
2. `ReadDirectoryChangesW` ile izlenir (dosya değişikliği, silme, yeniden adlandırma)
3. Herhangi bir değişiklik → **Skor: 100** → Anlık alert + acil durum

### Katman 2: File System Watchdog

```python
class FileSystemWatchdog:
    """
    Belirli klasörlerdeki toplu dosya operasyonlarını izler.
    Kısa sürede çok fazla dosya değişikliği = ransomware göstergesi.
    """
    
    THRESHOLDS = {
        "file_renames_per_minute": 20,      # 1dk'da 20+ dosya rename
        "file_modifications_per_minute": 50, # 1dk'da 50+ dosya değişikliği
        "new_extension_ratio": 0.3,          # Dosyaların %30'u yeni uzantı aldıysa
    }
    
    SUSPICIOUS_EXTENSIONS = {
        ".encrypted", ".locked", ".crypted", ".crypt",
        ".crypto", ".enc", ".locky", ".cerber", ".zepto",
        ".thor", ".aaa", ".abc", ".xyz", ".zzz",
        ".micro", ".fun", ".gws", ".btc", ".gryphon",
        ".pay", ".ransom", ".WNCRY", ".wcry",
    }
```

### Katman 3: Şüpheli Süreç Tespiti

```python
SUSPICIOUS_PROCESSES = {
    # Ransomware'ların sık kullandığı araçlar
    "vssadmin.exe": "Shadow copy manipulation",
    "wmic.exe": "WMI command execution",
    "bcdedit.exe": "Boot config manipulation",
    "wbadmin.exe": "Backup deletion",
    "cipher.exe": "File encryption utility",
    "powershell.exe": "Script execution (context-dependent)",
    "cmd.exe": "Command execution (context-dependent)",
    "certutil.exe": "Certificate utility (download abuse)",
    "bitsadmin.exe": "BITS transfer (download abuse)",
    "mshta.exe": "HTML Application execution",
    "regsvr32.exe": "DLL registration (LOLBin)",
    "rundll32.exe": "DLL execution (LOLBin)",
}

SUSPICIOUS_COMMAND_PATTERNS = [
    r"vssadmin\s+delete\s+shadows",        # VSS silme
    r"wmic\s+shadowcopy\s+delete",          # VSS silme (WMIC)
    r"bcdedit\s+/set\s+.*recoveryenabled\s+no",  # Recovery devre dışı
    r"wbadmin\s+delete\s+catalog",          # Backup kataloğu silme
    r"cipher\s+/w:",                         # Disk wipe
    r"net\s+stop\s+\".*sql.*\"",            # SQL servisini durdurma
    r"net\s+stop\s+\".*backup.*\"",         # Backup servisini durdurma
    r"icacls\s+.*/grant\s+Everyone",        # İzin genişletme
    r"attrib\s+\+h\s+\+s",                 # Dosya gizleme
]
```

### Katman 4: Shadow Copy (VSS) İzleme

```python
class VSSMonitor:
    """
    Volume Shadow Copy sayısını periyodik kontrol eder.
    Azalma = silme girişimi = ransomware.
    """
    
    def check(self):
        """vssadmin list shadows çıktısını parse et."""
        # Önceki sayı ile karşılaştır
        # Azaldıysa → Skor: 100 → Emergency
```

---

## 10. Modül 7 — Uzaktan Müdahale (Remote Incident Response)

**Dosya:** `client_remote_commands.py`

### Neden Gerekli?

```
Senaryo: Gece 03:00'te e-posta geldi — "Başarılı RDP giriş, administrator hesabı!"

❌ OLMADAN: Sunucuya bağlanmaya çalışırsın. VPN yok. RDP açılmıyor. 
           Saldırgan zaten şifre değiştirdi. Geçmiş olsun.

✅ İLE:    Telefondan dashboard'a giriyorsun.
           "IP Engelle" → 2 saniye → saldırgan dışarıda.
           "Oturumu Kapat" → 3 saniye → aktif session sonlandırıldı.
           "Hesabı Kilitle" → 1 saniye → bir daha giremez.
           Sabah sakin sakin temizlik yaparsın.
```

### Mimari: Komut Akışı

```
  Dashboard (Web UI)                  YesNext API                    Client (Sunucu)
  ══════════════════                  ═══════════                    ════════════════
       │                                   │                              │
       │ "Block IP 1.2.3.4"               │                              │
       │──────────────────────────────────▶│                              │
       │                                   │ INSERT pending_commands      │
       │                                   │──────────┐                   │
       │                                   │◀─────────┘                   │
       │                                   │                              │
       │                                   │   GET /api/commands/pending  │
       │                                   │◀─────────────────────────────│ (her 5sn poll)
       │                                   │                              │
       │                                   │   [{command: "block_ip",     │
       │                                   │     target: "1.2.3.4"}]      │
       │                                   │─────────────────────────────▶│
       │                                   │                              │
       │                                   │                              │ netsh firewall
       │                                   │                              │ add rule ...
       │                                   │                              │
       │                                   │  POST /api/commands/result   │
       │                                   │◀─────────────────────────────│
       │                                   │  {status: "completed"}       │
       │                                   │                              │
       │         "✅ IP engellendi!"       │                              │
       │◀──────────────────────────────────│                              │
```

> **Not:** Bu, mevcut `GET /api/agent/pending-blocks` pattern'inin genelleştirilmiş halidir.
> Firewall agent zaten bu mantıkla çalışıyor — sadece komut tiplerini genişletiyoruz.

### Desteklenen Komutlar

#### 🔥 Acil Müdahale Komutları

| Komut | Dashboard Butonu | Client Aksiyonu | Windows Komutu |
|-------|-----------------|-----------------|----------------|
| `block_ip` | 🚫 IP Engelle | Firewall kuralı ekle | `netsh advfirewall firewall add rule name="HONEYPOT_BLOCK_{ip}" dir=in action=block remoteip={ip}` |
| `unblock_ip` | ✅ IP Engeli Kaldır | Firewall kuralı sil | `netsh advfirewall firewall delete rule name="HONEYPOT_BLOCK_{ip}"` |
| `logoff_user` | 🚪 Oturumu Kapat | Aktif oturumu sonlandır | `query session {user}` → `logoff {session_id}` |
| `disable_account` | 🔒 Hesabı Kilitle | Kullanıcıyı devre dışı bırak | `net user {username} /active:no` |
| `enable_account` | 🔓 Hesabı Aç | Kullanıcıyı aktifleştir | `net user {username} /active:yes` |
| `reset_password` | 🔑 Şifre Sıfırla | Rastgele güçlü şifre ata | `net user {username} {new_pass}` |
| `kill_process` | ☠️ Süreci Durdur | Süreç sonlandır | `taskkill /F /PID {pid}` veya `/IM {name}` |
| `stop_service` | ⏹️ Servisi Durdur | Windows servisini durdur | `sc stop {service_name}` |
| `disable_service` | 🚫 Servisi Devre Dışı Bırak | Servis başlangıcını devre dışı | `sc config {service_name} start=disabled` |
| `emergency_lockdown` | 🛑 Acil Kilit | Tüm inbound trafiği engelle | Tüm inbound block + whitelist IP hariç |
| `lift_lockdown` | ✅ Kilidi Kaldır | Lockdown kurallarını kaldır | Eklenen kuralları temizle |
| `list_sessions` | 👥 Aktif Oturumlar | Aktif RDP/konsol listesi | `query session` → parse |
| `list_processes` | 📋 Süreç Listesi | Çalışan süreçleri listele | `psutil.process_iter()` |
| `snapshot` | 📸 Anlık Görüntü | Sistem durumu snapshot | CPU + RAM + process list + netstat |

### Komut Veri Yapısı

```python
@dataclass
class RemoteCommand:
    command_id: str          # UUID — benzersiz komut ID
    command_type: str        # block_ip, logoff_user, kill_process, ...
    parameters: dict         # Komuta özel parametreler
    priority: str            # critical | high | normal
    issued_by: str           # Dashboard kullanıcısı (e-posta)
    issued_at: str           # ISO 8601 timestamp
    expires_at: str          # Komut son geçerlilik süresi (5dk default)
    requires_confirmation: bool  # Bazı komutlar onay gerektirir
```

### Parametre Formatları (Her Komut İçin)

```python
COMMAND_PARAMETERS = {
    "block_ip": {
        "ip": "1.2.3.4",                    # Engellenecek IP
        "duration_hours": 24,                # Süre (0 = kalıcı)
        "reason": "Brute force success"      # Neden
    },
    "unblock_ip": {
        "ip": "1.2.3.4"
    },
    "logoff_user": {
        "username": "administrator",         # Kapatılacak oturum
        "force": True                        # Zorla kapat
    },
    "disable_account": {
        "username": "administrator"
    },
    "enable_account": {
        "username": "administrator"
    },
    "reset_password": {
        "username": "administrator",
        "new_password": None                 # None = otomatik güçlü şifre üret
    },
    "kill_process": {
        "pid": 1234,                         # PID ile
        "process_name": "malware.exe",       # veya isim ile
        "force": True
    },
    "stop_service": {
        "service_name": "SuspiciousService"
    },
    "disable_service": {
        "service_name": "SuspiciousService"
    },
    "emergency_lockdown": {
        "management_ip": "10.0.0.1",         # Bu IP erişime açık kalır
        "duration_minutes": 60               # Otomatik kaldırma süresi
    },
    "lift_lockdown": {},
    "list_sessions": {},                     # Parametre yok — bilgi komutları
    "list_processes": {
        "filter": "suspicious"               # Opsiyonel: sadece şüpheliler
    },
    "snapshot": {}
}
```

### Güvenlik Katmanları

```python
class CommandSecurityPolicy:
    """
    Uzaktan komutların güvenliğini sağlar.
    Yanlış veya kötü niyetli komutlara karşı koruma.
    """
    
    # ─── 1. Komut Doğrulama ─── #
    ALLOWED_COMMANDS = {
        "block_ip", "unblock_ip", 
        "logoff_user", "disable_account", "enable_account", "reset_password",
        "kill_process", "stop_service", "disable_service",
        "emergency_lockdown", "lift_lockdown",
        "list_sessions", "list_processes", "snapshot",
    }
    
    # ─── 2. Koruma Altındaki Hesaplar ─── #
    # Bu hesaplar disable/logoff edilemez (kendi kendini kilitlemeyi önle)
    PROTECTED_ACCOUNTS = {
        "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
    }
    
    # ─── 3. Koruma Altındaki Süreçler ─── #
    PROTECTED_PROCESSES = {
        "system", "smss.exe", "csrss.exe", "wininit.exe",
        "services.exe", "lsass.exe", "svchost.exe",
        "honeypot-client.exe",  # Kendimizi öldürmeyelim!
    }
    
    # ─── 4. Koruma Altındaki Servisler ─── #
    PROTECTED_SERVICES = {
        "wuauserv",     # Windows Update
        "windefend",    # Windows Defender
        "eventlog",     # Event Log (bunu kapatsak izleyemeyiz)
        "mpssvc",       # Windows Firewall
    }
    
    # ─── 5. Süre Sınırları ─── #
    COMMAND_EXPIRY_SECONDS = 300    # 5dk'dan eski komutları çalıştırma
    MAX_COMMANDS_PER_MINUTE = 10    # DDoS koruması
    
    # ─── 6. Onay Gerektiren Komutlar ─── #
    REQUIRES_CONFIRMATION = {
        "emergency_lockdown",   # Çok agresif — emin misiniz?
        "reset_password",       # Şifre değişince kullanıcı da etkilenir
        "disable_account",      # Meşru kullanıcıyı kilitleyebilir
    }
```

### Teknik Implementasyon

```python
class RemoteCommandExecutor:
    """
    Dashboard'dan gelen komutları alıp güvenli şekilde çalıştırır.
    Mevcut firewall agent'ın pending-blocks pattern'ini genişletir.
    """
    
    POLL_INTERVAL = 5  # Her 5 saniyede bir API'ye sor
    
    def __init__(self, token: str, api_url: str, security_policy: CommandSecurityPolicy):
        self.token = token
        self.api_url = api_url
        self.policy = security_policy
        self._running = False
    
    def start(self):
        """Arka plan thread'i olarak başlat."""
        self._running = True
        threading.Thread(target=self._poll_loop, daemon=True).start()
    
    def _poll_loop(self):
        """Ana polling döngüsü — her 5sn'de komut var mı kontrol et."""
        while self._running:
            try:
                commands = self._fetch_pending_commands()
                for cmd in commands:
                    if self._validate_command(cmd):
                        result = self._execute_command(cmd)
                        self._report_result(cmd, result)
            except Exception as e:
                log(f"[CMD] Poll error: {e}")
            time.sleep(self.POLL_INTERVAL)
    
    def _fetch_pending_commands(self) -> list:
        """GET /api/commands/pending?token=X"""
        resp = requests.get(f"{self.api_url}/commands/pending",
                           params={"token": self.token}, timeout=5)
        if resp.status_code == 200:
            return resp.json().get("commands", [])
        return []
    
    def _validate_command(self, cmd: dict) -> bool:
        """Güvenlik kontrollerini uygula."""
        # 1. Komut tipi geçerli mi?
        if cmd["command_type"] not in self.policy.ALLOWED_COMMANDS:
            return False
        # 2. Süresi dolmuş mu?
        issued = datetime.fromisoformat(cmd["issued_at"])
        if (datetime.utcnow() - issued).seconds > self.policy.COMMAND_EXPIRY_SECONDS:
            return False
        # 3. Koruma altındaki hedef mi?
        params = cmd.get("parameters", {})
        if cmd["command_type"] in ("logoff_user", "disable_account"):
            if params.get("username", "").upper() in self.policy.PROTECTED_ACCOUNTS:
                return False
        if cmd["command_type"] == "kill_process":
            if params.get("process_name", "").lower() in self.policy.PROTECTED_PROCESSES:
                return False
        return True
    
    def _execute_command(self, cmd: dict) -> dict:
        """Komutu çalıştır ve sonucu döndür."""
        handler = getattr(self, f"_cmd_{cmd['command_type']}", None)
        if handler:
            return handler(cmd["parameters"])
        return {"success": False, "error": "Unknown command"}
    
    def _report_result(self, cmd: dict, result: dict):
        """POST /api/commands/result — sonucu backend'e bildir."""
        requests.post(f"{self.api_url}/commands/result", json={
            "token": self.token,
            "command_id": cmd["command_id"],
            "status": "completed" if result["success"] else "failed",
            "result": result,
            "executed_at": datetime.utcnow().isoformat(),
        }, timeout=5)
    
    # ─── Komut Handler'ları ─── #
    
    def _cmd_block_ip(self, params: dict) -> dict:
        """Windows Firewall'a IP engelleme kuralı ekle."""
        ip = params["ip"]
        duration = params.get("duration_hours", 24)
        rule_name = f"HONEYPOT_REMOTE_BLOCK_{ip}"
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "add", "rule",
             f"name={rule_name}", "dir=in", "action=block",
             f"remoteip={ip}", "enable=yes"],
            capture_output=True, text=True
        )
        return {
            "success": result.returncode == 0,
            "message": f"IP {ip} blocked for {duration}h",
            "rule_name": rule_name,
        }
    
    def _cmd_logoff_user(self, params: dict) -> dict:
        """Aktif kullanıcı oturumunu kapat."""
        username = params["username"]
        # Önce session ID'yi bul
        query = subprocess.run(
            ["query", "session"], capture_output=True, text=True
        )
        for line in query.stdout.splitlines():
            if username.lower() in line.lower():
                parts = line.split()
                session_id = parts[2] if len(parts) > 2 else parts[1]
                logoff = subprocess.run(
                    ["logoff", session_id, "/v"],
                    capture_output=True, text=True
                )
                return {
                    "success": logoff.returncode == 0,
                    "message": f"Session {session_id} for {username} terminated",
                }
        return {"success": False, "error": f"No active session for {username}"}
    
    def _cmd_disable_account(self, params: dict) -> dict:
        """Kullanıcı hesabını devre dışı bırak."""
        username = params["username"]
        result = subprocess.run(
            ["net", "user", username, "/active:no"],
            capture_output=True, text=True
        )
        return {
            "success": result.returncode == 0,
            "message": f"Account '{username}' disabled",
        }
    
    def _cmd_reset_password(self, params: dict) -> dict:
        """Kullanıcı şifresini sıfırla. Yeni şifreyi API'ye bildir."""
        username = params["username"]
        new_pass = params.get("new_password") or self._generate_strong_password()
        result = subprocess.run(
            ["net", "user", username, new_pass],
            capture_output=True, text=True
        )
        return {
            "success": result.returncode == 0,
            "message": f"Password reset for '{username}'",
            "new_password": new_pass,  # API üzerinden güvenli iletilir
        }
    
    def _cmd_kill_process(self, params: dict) -> dict:
        """Süreci sonlandır."""
        if "pid" in params:
            result = subprocess.run(
                ["taskkill", "/F", "/PID", str(params["pid"])],
                capture_output=True, text=True
            )
        else:
            result = subprocess.run(
                ["taskkill", "/F", "/IM", params["process_name"]],
                capture_output=True, text=True
            )
        return {
            "success": result.returncode == 0,
            "message": result.stdout.strip(),
        }
    
    def _cmd_list_sessions(self, params: dict) -> dict:
        """Aktif oturumları listele."""
        result = subprocess.run(
            ["query", "session"], capture_output=True, text=True
        )
        sessions = []
        for line in result.stdout.splitlines()[1:]:  # Header'ı atla
            parts = line.split()
            if len(parts) >= 4:
                sessions.append({
                    "username": parts[0],
                    "session_id": parts[1],
                    "state": parts[2],
                })
        return {"success": True, "sessions": sessions}
    
    def _cmd_snapshot(self, params: dict) -> dict:
        """Anlık sistem durumu snapshot'ı al."""
        import psutil
        return {
            "success": True,
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory": dict(psutil.virtual_memory()._asdict()),
            "disk": dict(psutil.disk_usage('/')._asdict()),
            "processes": [
                {"pid": p.pid, "name": p.name(), "cpu": p.cpu_percent(),
                 "memory_mb": p.memory_info().rss / 1024 / 1024}
                for p in sorted(psutil.process_iter(['pid', 'name', 'cpu_percent']),
                               key=lambda p: p.cpu_percent(), reverse=True)[:20]
            ],
            "connections": len(psutil.net_connections()),
        }
    
    @staticmethod
    def _generate_strong_password(length=16) -> str:
        """Güçlü rastgele şifre üret."""
        import secrets, string
        chars = string.ascii_letters + string.digits + "!@#$%&*"
        while True:
            pwd = ''.join(secrets.choice(chars) for _ in range(length))
            # En az 1 büyük, 1 küçük, 1 rakam, 1 özel karakter
            if (any(c.isupper() for c in pwd) and any(c.islower() for c in pwd)
                and any(c.isdigit() for c in pwd) and any(c in "!@#$%&*" for c in pwd)):
                return pwd
```

### Dashboard Kullanıcı Arayüzü Akışı

```
┌─────────────────────────────────────────────────────────────────┐
│ 🚨 KRİTİK ALERT: RDP Başarılı Giriş                           │
│                                                                 │
│ 📍 IP: 192.168.1.105 (Rusya, Moskova)                          │
│ 👤 Hesap: administrator                                         │
│ 🕐 Zaman: 08.02.2026 23:15:42                                  │
│ 📊 Tehdit Skoru: 95/100                                         │
│                                                                 │
│ ⚡ Otomatik Aksiyonlar:                                         │
│   ✅ IP 192.168.1.105 otomatik engellendi (24 saat)             │
│                                                                 │
│ ┌──────────────────────────────────────────────────────────────┐│
│ │                    🎯 ANINDA MÜDAHALE                        ││
│ ├──────────────────────────────────────────────────────────────┤│
│ │                                                              ││
│ │  [🚫 IP Engelle]  [🚪 Oturumu Kapat]  [🔒 Hesabı Kilitle]  ││
│ │                                                              ││
│ │  [🔑 Şifre Sıfırla]  [☠️ Süreci Durdur]  [📸 Snapshot]     ││
│ │                                                              ││
│ │  [🛑 ACİL KİLİT — Tüm Trafiği Engelle]                     ││
│ │                                                              ││
│ ├──────────────────────────────────────────────────────────────┤│
│ │ ℹ️ Komutlar 5 saniye içinde sunucuya iletilir               ││
│ │ 📋 Komut geçmişi:                                           ││
│ │   23:15:43 — IP 192.168.1.105 engellendi ✅                  ││
│ │   23:15:45 — administrator oturumu kapatıldı ✅               ││
│ │   23:15:46 — administrator hesabı kilitlendi ✅               ││
│ └──────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### Tipik Müdahale Senaryoları

#### Senaryo 1: Brute Force → Başarılı Giriş (RDP)

```
Mail geldi → Dashboard'a gir →
  1. "IP Engelle" → ✅ (zaten otomatik engellendi)
  2. "Oturumu Kapat" → ✅ administrator oturumu sonlandı
  3. "Şifre Sıfırla" → ✅ yeni şifre: Xk9#mP2$qR5vN8wL
  Toplam süre: 15 saniye
```

#### Senaryo 2: SQL Injection → xp_cmdshell → Şüpheli Süreç

```
Mail geldi → Dashboard'a gir →
  1. "Süreci Durdur" (malware.exe, PID: 5678) → ✅
  2. "IP Engelle" (saldırgan IP) → ✅
  3. "Servisi Devre Dışı Bırak" (MSSQLSERVER) → ✅ sorunu kaynağında durdur
  4. "Snapshot" → 📸 mevcut durumun kaydı alındı
  Toplam süre: 20 saniye
```

#### Senaryo 3: Ransomware Tespiti

```
Mail geldi → Dashboard'a gir →
  1. "Acil Kilit" (management IP: kendi IP'n) → ✅ tüm inbound engellendi
     → Sunucuya sadece sen erişebilirsin
  2. "Snapshot" → 📸 şüpheli süreçlerin listesi
  3. "Süreci Durdur" (şüpheli her biri tek tek) → ✅
  4. "Kilidi Kaldır" → ✅ normal trafiğe geri dön
  Toplam süre: 30 saniye — ransomware birkaç dosya şifrelemişken durduruldu
```

---

## 11. Modül 8 — Sessiz Saatler & Süreç Koruma (Silent Hours & Self-Protection)

Bu modül iki kritik boşluğu kapatır:

1. **Sessiz Saatler:** Mesai dışı saatlerde tüm başarılı girişleri otomatik engelle
2. **Süreç Kendini Koruma:** Client process'inin saldırgan tarafından kapatılmasını engelle

### Problem Senaryosu

```
🕐 Gece 03:14 — Admin uyuyor
    ↓
Saldırgan brute-force ile RDP şifresini buldu
    ↓
Başarılı giriş → Bildirim e-postası gönderildi
    ↓ ❌ Ama admin uyuyor, bildirimi görmedi
    ↓
Saldırgan Task Manager → honeypot-client.exe → "End Task"
    ↓ ❌ Client durdu, artık izleme/koruma yok
    ↓
Saldırgan serbestçe hareket eder → veri çalınır / ransomware yüklenir
```

**Sessiz Saatler ile:**

```
🕐 Gece 03:14 — Admin uyuyor ama Sessiz Saatler AKTİF
    ↓
Saldırgan başarılı giriş yaptı
    ↓
Client anında kontrol eder: "Bu IP whitelist'te mi?" → ❌ HAYIR
    ↓
🚫 Otomatik aksiyonlar (saniyeler içinde):
    1. IP → Firewall BLOCK (kalıcı, admin onaylayana kadar)
    2. Oturum → LOGOFF (aktif session kapatılır)
    3. Hesap → DEVRE DIŞI (tekrar denenemez)
    4. Alert → API + E-posta (kritik bildirim)
    ↓
Saldırgan dışarıda. Admin sabah dashboard'a bakar:
    "Gece 03:14'te giriş denemesi engellendi ✅"
    → İsterse IP'yi beyaz listeye ekler, hesabı aktifleştirir
```

### Dosya: `client_silent_hours.py`

```python
"""
Sessiz Saatler Güvenlik Modülü

Mesai dışı saatlerde tüm başarılı girişleri (RDP, SSH, MSSQL, FTP vb.)
beyaz listedeki IP'ler hariç otomatik engeller.

Mantık:
    1. EventLog Watcher başarılı logon tespit eder
    2. SilentHoursGuard.check() çağrılır
    3. Şu anki saat sessiz saat aralığında mı? → Evet
    4. Giriş yapan IP beyaz listede mi? → Hayır
    5. → BLOCK + LOGOFF + DISABLE + ALERT

Dashboard Entegrasyonu:
    - Sessiz saatleri aç/kapa
    - Saat aralığı ayarla (varsayılan: 00:00 - 07:00)
    - Hafta sonu tüm gün sessiz modu
    - IP beyaz listesi yönetimi (tek tıkla "bu IP benim")
"""

import datetime
from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum


class SilentHoursMode(Enum):
    DISABLED = "disabled"           # Sessiz saatler kapalı
    NIGHT_ONLY = "night_only"       # Sadece gece saatleri (ör. 00:00-07:00)
    OUTSIDE_WORKING = "outside_working"  # Mesai dışı tüm saatler
    ALWAYS = "always"               # Her zaman (sadece whitelist erişebilir)
    CUSTOM = "custom"               # Özel gün/saat tanımı


@dataclass
class SilentHoursConfig:
    """Dashboard'dan ayarlanabilir konfigürasyon."""
    
    enabled: bool = True
    mode: SilentHoursMode = SilentHoursMode.NIGHT_ONLY
    
    # Gece modu ayarları
    night_start: str = "00:00"      # Varsayılan: gece yarısı
    night_end: str = "07:00"        # Varsayılan: sabah 7
    
    # Mesai saatleri (outside_working modu için)
    work_start: str = "08:00"
    work_end: str = "18:00"
    work_days: List[int] = field(default_factory=lambda: [0, 1, 2, 3, 4])  # Pzt-Cum
    
    # Özel takvim (custom modu için)
    custom_schedule: dict = field(default_factory=dict)
    # Örnek: {"monday": [{"start": "00:00", "end": "08:00"}, {"start": "20:00", "end": "23:59"}]}
    
    # Hafta sonu politikası
    weekend_all_day_silent: bool = True  # Hafta sonu tüm gün sessiz
    
    # Aksiyonlar
    auto_block_ip: bool = True       # IP'yi firewall'da engelle
    auto_logoff: bool = True         # Oturumu kapat
    auto_disable_account: bool = True  # Hesabı devre dışı bırak
    block_duration_hours: int = 0    # 0 = kalıcı (admin onaylayana kadar)
    
    # Beyaz liste (Dashboard'dan yönetilir)
    whitelist_ips: List[str] = field(default_factory=list)
    whitelist_subnets: List[str] = field(default_factory=list)
    
    # Bildirim
    alert_on_block: bool = True      # Engelleme olduğunda alert gönder
    alert_severity: str = "critical"  # Sessiz saat ihlali her zaman kritik
    
    timezone: str = "Europe/Istanbul"


class SilentHoursGuard:
    """
    Sessiz saatlerde başarılı girişleri otomatik engeller.
    
    EventLog Watcher'ın successful_logon event'inde çağrılır:
        guard = SilentHoursGuard(config, auto_response, alerts)
        if guard.check(event):
            # Zaten engellendi, başka işlem gereksiz
    """
    
    def __init__(self, config: SilentHoursConfig, auto_response, alerts, firewall):
        self.config = config
        self.auto_response = auto_response
        self.alerts = alerts
        self.firewall = firewall
    
    def is_silent_now(self) -> bool:
        """Şu an sessiz saat aralığında mı?"""
        now = datetime.datetime.now()  # config.timezone ile
        
        if self.config.mode == SilentHoursMode.DISABLED:
            return False
        
        if self.config.mode == SilentHoursMode.ALWAYS:
            return True
        
        # Hafta sonu kontrolü
        if self.config.weekend_all_day_silent and now.weekday() >= 5:
            return True  # Cumartesi (5) veya Pazar (6)
        
        if self.config.mode == SilentHoursMode.NIGHT_ONLY:
            return self._in_time_range(now.time(), 
                                        self.config.night_start, 
                                        self.config.night_end)
        
        if self.config.mode == SilentHoursMode.OUTSIDE_WORKING:
            # Çalışma günü değilse → sessiz
            if now.weekday() not in self.config.work_days:
                return True
            # Çalışma saati dışındaysa → sessiz
            return not self._in_time_range(now.time(),
                                           self.config.work_start,
                                           self.config.work_end)
        
        if self.config.mode == SilentHoursMode.CUSTOM:
            return self._check_custom_schedule(now)
        
        return False
    
    def is_whitelisted(self, ip: str) -> bool:
        """IP beyaz listede mi veya güvenli subnet'te mi?"""
        if ip in self.config.whitelist_ips:
            return True
        # Subnet kontrolü
        import ipaddress
        try:
            addr = ipaddress.ip_address(ip)
            for subnet_str in self.config.whitelist_subnets:
                if addr in ipaddress.ip_network(subnet_str, strict=False):
                    return True
        except ValueError:
            pass
        return False
    
    def check(self, event: dict) -> bool:
        """
        Başarılı giriş event'ini kontrol et.
        Sessiz saatte ve whitelist dışındaysa → otomatik engelle.
        
        Returns: True if blocked, False if allowed
        """
        if not self.config.enabled:
            return False
        
        if not self.is_silent_now():
            return False
        
        ip = event.get("source_ip", "")
        if not ip or self.is_whitelisted(ip):
            return False
        
        # ⚡ ENGELLE — Sessiz saatte yetkisiz giriş!
        username = event.get("username", "unknown")
        service = event.get("target_service", "unknown")
        
        log.warning(
            f"🔇 SESSIZ SAAT İHLALİ: {ip} → {service} ({username}) — "
            f"OTOMATİK ENGELLEME BAŞLATIYOR"
        )
        
        actions_taken = []
        
        # 1. IP'yi firewall'da engelle (kalıcı)
        if self.config.auto_block_ip:
            self.firewall.block_ip(ip, 
                                   reason=f"Silent hours violation: {service}",
                                   duration_hours=self.config.block_duration_hours)
            actions_taken.append("block_ip")
        
        # 2. Aktif oturumu kapat
        if self.config.auto_logoff:
            self.auto_response.logoff_user(username)
            actions_taken.append("logoff_user")
        
        # 3. Hesabı devre dışı bırak
        if self.config.auto_disable_account:
            self.auto_response.disable_account(username)
            actions_taken.append("disable_account")
        
        # 4. Kritik alert gönder
        if self.config.alert_on_block:
            self.alerts.send_urgent({
                "severity": self.config.alert_severity,
                "threat_type": "silent_hours_violation",
                "title": f"🔇 Sessiz Saat İhlali — {service} girişi engellendi",
                "description": (
                    f"Sessiz saatlerde {ip} adresinden {service} servisine "
                    f"başarılı giriş tespit edildi. IP beyaz listede olmadığı için "
                    f"otomatik engelleme uygulandı.\n\n"
                    f"Kullanıcı: {username}\n"
                    f"Bu siz miydiniz? Dashboard'dan IP'nizi beyaz listeye ekleyin."
                ),
                "source_ip": ip,
                "target_service": service,
                "username": username,
                "threat_score": 95,  # Sessiz saat ihlali her zaman yüksek skor
                "auto_response_taken": actions_taken,
            })
        
        return True  # Engellendi
    
    @staticmethod
    def _in_time_range(current_time, start_str: str, end_str: str) -> bool:
        """Saat aralığı kontrolü (gece yarısını geçen aralıkları da destekler)."""
        start = datetime.time.fromisoformat(start_str)
        end = datetime.time.fromisoformat(end_str)
        
        if start <= end:
            # Normal aralık: 08:00 - 18:00
            return start <= current_time <= end
        else:
            # Gece yarısını geçen aralık: 22:00 - 06:00
            return current_time >= start or current_time <= end
```

### Dashboard Arayüzü — Sessiz Saatler Paneli

```
┌─────────────────────────────────────────────────────────────┐
│  🔇 Sessiz Saatler (Silent Hours)                    [AKTİF]│
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Mod: [🌙 Gece Modu ▾]                                     │
│       ○ Kapalı                                              │
│       ● Gece Modu (00:00 - 07:00)                          │
│       ○ Mesai Dışı (08:00-18:00 dışı)                      │
│       ○ Her Zaman (sadece whitelist erişir)                 │
│       ○ Özel Takvim                                         │
│                                                             │
│  Saat Aralığı: [00:00] — [07:00]                           │
│  Hafta sonu tüm gün sessiz: [✓]                            │
│                                                             │
│  ── Sessiz Saatte Otomatik Aksiyonlar ──                   │
│  [✓] IP'yi firewall'da engelle (kalıcı)                    │
│  [✓] Aktif oturumu kapat                                   │
│  [✓] Hesabı devre dışı bırak                               │
│                                                             │
│  ── Beyaz Liste (bu IP'ler her zaman girebilir) ──         │
│  ┌──────────────┬──────────────────┬─────────┐             │
│  │ IP Adresi     │ Not              │ İşlem   │             │
│  ├──────────────┼──────────────────┼─────────┤             │
│  │ 85.107.45.12 │ Ev IP'im         │ [🗑️]    │             │
│  │ 10.0.0.0/8   │ Ofis subnet      │ [🗑️]    │             │
│  └──────────────┴──────────────────┴─────────┘             │
│  [+ IP Ekle]  [+ Subnet Ekle]  [📍 Mevcut IP'mi Ekle]     │
│                                                             │
│  ── Son Engelleme Log ──                                    │
│  🔴 03:14 — 203.0.113.50 → RDP (blocked + logoff + disable)│
│  🔴 03:22 — 198.51.100.7 → SSH (blocked + logoff)          │
│  🟢 08:15 — 85.107.45.12 → RDP (whitelist — allowed)       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### "Bu Benim" Hızlı Aksiyon (Dashboard)

E-posta bildiriminde ve dashboard'da:

```
┌─────────────────────────────────────────────────────────┐
│  ⚠️ Sessiz Saat İhlali — 03:14                          │
│                                                         │
│  IP: 85.107.45.12 → RDP başarılı giriş                 │
│  Kullanıcı: admin                                       │
│  Aksiyonlar: IP engellendi, oturum kapatıldı, hesap     │
│  devre dışı bırakıldı                                   │
│                                                         │
│  Bu siz miydiniz?                                       │
│  [✅ Evet, bu benim]     [❌ Hayır, saldırı]            │
│                                                         │
│  "Evet" → IP beyaz listeye eklenir,                     │
│           IP engeli kaldırılır,                          │
│           hesap yeniden aktifleştirilir                  │
│                                                         │
│  "Hayır" → IP kalıcı engel, hesap kilitli kalır,       │
│            forensic snapshot alınır                      │
└─────────────────────────────────────────────────────────┘
```

### E-posta Şablonu — Sessiz Saat İhlali

```
Konu: 🔇 [KRİTİK] Sessiz Saat İhlali — {server_name}

{server_name} sunucunuzda sessiz saatlerde yetkisiz giriş tespit edildi
ve otomatik engelleme uygulandı.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Zaman:     {timestamp}
  IP Adresi: {source_ip} ({geo_country}, {geo_city})
  Servis:    {service} (Port: {port})
  Kullanıcı: {username}
  
  Otomatik Aksiyonlar:
    ✅ IP firewall'da engellendi (kalıcı)
    ✅ Aktif oturum kapatıldı
    ✅ Hesap devre dışı bırakıldı
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Bu siz miydiniz?
  
  [EVET, BENİM — IP'mi Beyaz Listeye Ekle]
  → {dashboard_url}/silent-hours/approve?token={token}&ip={ip}
  
  [HAYIR, SALDIRI — İncelemeye Al]
  → {dashboard_url}/alerts/{alert_id}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Sessiz Saat Ayarları: {mode} ({silent_start} - {silent_end})
Beyaz Liste: {whitelist_count} IP/subnet tanımlı
Değiştirmek için: {dashboard_url}/settings/silent-hours
```

---

### Süreç Kendini Koruma (Process Self-Protection)

**Problem:** Saldırgan sunucuya girdikten sonra `honeypot-client.exe` sürecini
Task Manager veya `taskkill` ile durdurabilir. Client durduğunda tüm izleme,
otomatik engelleme ve bildirim sistemi devre dışı kalır.

**Çözüm: Çok Katmanlı Süreç Koruma**

```python
"""
Süreç Kendini Koruma Stratejisi — 3 katmanlı savunma + Güvenli Son Nefes

Katman 1: Zamanlanmış Görev (mevcut)
    → Client zaten Task Scheduler'da kayıtlı (v3.1.0)
    → Süreç ölürse zamanlanmış görev bir sonraki tetiklemede yeniden başlatır
    → Ek olarak: "on failure" trigger'ı eklenir → anında restart

Katman 2: Kritik süreç olarak işaretle
    → SetProcessShutdownParameters ile kapatma sırasını en sona al
    → Process DACL: admin olmayan kullanıcılar süreci durduramaz

Katman 3: "Güvenli Son Nefes" mekanizması
    → Süreç sonlandırılırken (atexit/signal handler):
       - API'ye "client killed" acil alert gönder
       - SADECE o anda aktif tehdit varsa → şüpheli IP'yi engelle
       - TÜM PORTLARI KAPATMA — sunucu brick olabilir!
       - Zamanlanmış görev client'ı yeniden ayağa kaldıracak

⚠️ ÖNEMLİ TASARIM KARARI — "NÜKLEER BUTON" YOK:
    Eski tasarımda son nefeste "tüm inbound'u kapat" vardı.
    Bu ÇOK TEHLİKELİ çünkü:
    - Kod hatası/güncelleme sonrası crash → sunucu erişilemez (brick)
    - Datacenter'la iletişim gerekir → saatler/günler offline
    - Watchdog crash loop'a girerse her seferinde portları kapatır
    
    Güvenli alternatif:
    - Son nefeste SADECE aktif tehdit bağlamındaki IP'yi engelle
    - Tehdit bağlamı yoksa (normal çökme) → HİÇBİR ŞEY YAPMA
    - Zamanlanmış görev zaten client'ı yeniden başlatacak
    - Client ayağa kalkınca tüm koruma sistemleri tekrar devrede
"""

class ProcessProtection:
    """Client sürecinin saldırgan tarafından kapatılmasını zorlaştırır."""
    
    def __init__(self, threat_engine=None, firewall=None, token=None):
        self.threat_engine = threat_engine  # Aktif tehdit bağlamını sormak için
        self.firewall = firewall
        self.token = token
    
    # ── Katman 1: Zamanlanmış Görev Yapılandırması ──
    TASK_CONFIG = {
        "name": "HoneypotClientGuard",
        "description": "YesNext Honeypot Client — otomatik yeniden başlatma",
        "triggers": [
            "on_logon",        # Oturum açıldığında (mevcut, v3.1.0)
            "on_boot",         # Sistem başlangıcında
            "on_event",        # Event Log'da süreç sonlanma event'i geldiğinde
        ],
        # schtasks komutu:
        # schtasks /create /tn "HoneypotClientGuard" /tr "honeypot-client.exe --mode=tray"
        #   /sc ONEVENT /ec Application /mo "*[EventData[Data='honeypot-client.exe']]"
        #   /rl HIGHEST /f
    }
    
    # ── Katman 2: Süreç DACL Koruması ──
    
    def setup_protection(self):
        """Koruma katmanlarını etkinleştir."""
        self._register_signal_handlers()     # Katman 3: Güvenli son nefes
        self._set_shutdown_priority()        # Katman 2: Kapatma sırasını değiştir
        self._protect_process_dacl()         # Katman 2: Basit taskkill'i engelle
    
    def _set_shutdown_priority(self):
        """Windows kapatma sırasında en son kapanan süreç ol."""
        import ctypes
        # 0x100 = en düşük öncelik (en son kapanır)
        # Timeout: 20 saniye (son aksiyonlar için süre)
        ctypes.windll.kernel32.SetProcessShutdownParameters(0x100, 0)
    
    def _protect_process_dacl(self):
        """
        Sürecin güvenlik tanımlayıcısını değiştir.
        Admin olmayan kullanıcılar süreci durduramaz.
        Not: SYSTEM veya yükseltilmiş admin hâlâ durdurabilir.
        """
        import ctypes
        import ctypes.wintypes
        # DACL'den GENERIC_ALL'ı kaldırarak basit taskkill'i engelle
        # Bu tam bir koruma değil ama saldırganın işini zorlaştırır
    
    # ── Katman 3: Güvenli Son Nefes ──
    
    def _register_signal_handlers(self):
        """Süreç sonlandırılırken son aksiyonları al."""
        import signal
        import atexit
        
        def on_termination(signum=None, frame=None):
            """
            GÜVENLİ SON NEFES — Süreç kapanıyor.
            
            KURAL: Sadece aktif tehdit bağlamındaki IP'yi engelle.
            ASLA tüm portları kapatma — sunucu brick olabilir!
            
            Senaryo 1 (Saldırı): Threat engine'de aktif tehdit var
                → Şüpheli IP'yi firewall'da engelle
                → API'ye alert gönder
                
            Senaryo 2 (Normal çökme/güncelleme): Threat context boş
                → Sadece API'ye "process stopped" log gönder
                → Firewall'a DOKUNMA
                → Zamanlanmış görev client'ı yeniden başlatacak
            """
            try:
                threat_context = self._get_active_threat_context()
                
                if threat_context and threat_context.get("suspicious_ip"):
                    # SALDIRI SENARYOSU — Sadece şüpheli IP'yi engelle
                    suspicious_ip = threat_context["suspicious_ip"]
                    self._block_single_ip(suspicious_ip, 
                        reason="Son Nefes: Client sonlandırılırken aktif tehdit IP'si")
                    self._send_last_breath_alert(
                        alert_type="CLIENT_KILLED_DURING_ATTACK",
                        details={
                            "signal": signum,
                            "blocked_ip": suspicious_ip,
                            "threat_score": threat_context.get("threat_score", 0),
                            "message": (
                                f"Client süreci aktif saldırı sırasında sonlandırıldı. "
                                f"Şüpheli IP {suspicious_ip} engellendi. "
                                f"Zamanlanmış görev client'ı yeniden başlatacak."
                            ),
                        }
                    )
                else:
                    # NORMAL ÇÖKME/KAPATMA — Firewall'a dokunma!
                    self._send_last_breath_alert(
                        alert_type="CLIENT_PROCESS_STOPPED",
                        details={
                            "signal": signum,
                            "message": (
                                "Client süreci durdu (olası çökme veya güncelleme). "
                                "Tehdit bağlamı yok — firewall değiştirilmedi. "
                                "Zamanlanmış görev client'ı yeniden başlatacak."
                            ),
                        }
                    )
                
            except Exception:
                pass  # Son nefeste exception fırlatma
        
        signal.signal(signal.SIGTERM, on_termination)
        signal.signal(signal.SIGINT, on_termination)
        atexit.register(on_termination)
    
    def _get_active_threat_context(self) -> dict:
        """
        Threat engine'den son 60 saniyedeki aktif tehdit bilgisini al.
        
        Returns:
            {"suspicious_ip": "1.2.3.4", "threat_score": 85, ...} veya None
        
        Bu sayede crash vs saldırı ayrımı yapılır:
        - Son 60sn'de başarılı giriş + yüksek skor varsa → saldırı
        - Hiç tehdit yoksa → muhtemelen kod hatası veya güncelleme
        """
        if not self.threat_engine:
            return None
        
        try:
            # Son 60 saniyede skor >= 70 olan en yüksek skorlu IP
            recent_threats = self.threat_engine.get_recent_threats(
                max_age_seconds=60,
                min_score=70,
            )
            if recent_threats:
                top_threat = max(recent_threats, key=lambda t: t.get("threat_score", 0))
                return {
                    "suspicious_ip": top_threat.get("source_ip"),
                    "threat_score": top_threat.get("threat_score"),
                    "threat_type": top_threat.get("threat_type"),
                    "username": top_threat.get("username"),
                }
        except Exception:
            pass
        
        return None
    
    def _block_single_ip(self, ip: str, reason: str):
        """Tek bir IP'yi firewall'da engelle (güvenli — sunucu brick olmaz)."""
        import subprocess
        try:
            rule_name = f"HONEYPOT_LASTBREATH_{ip.replace('.', '_')}"
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in", "action=block",
                f"remoteip={ip}",
            ], timeout=5, capture_output=True)
        except Exception:
            pass
    
    def _send_last_breath_alert(self, alert_type: str, details: dict):
        """Son nefeste API'ye bildirim gönder (timeout: 3sn)."""
        import requests
        try:
            severity = "critical" if "ATTACK" in alert_type else "warning"
            requests.post(
                f"{API_URL}/alerts/urgent",
                json={
                    "token": self.token,
                    "severity": severity,
                    "threat_type": alert_type,
                    "title": (
                        "⚠️ Client Süreci Aktif Saldırı Sırasında Sonlandırıldı!"
                        if "ATTACK" in alert_type else
                        "ℹ️ Client Süreci Durdu — Yeniden Başlatılacak"
                    ),
                    "description": str(details),
                    "threat_score": 95 if "ATTACK" in alert_type else 30,
                    "auto_response_taken": (
                        [f"block_ip:{details.get('blocked_ip', '')}"]
                        if "ATTACK" in alert_type else []
                    ),
                },
                timeout=3
            )
        except Exception:
            pass
```

### Neden Watchdog Yok?

Önceki tasarımda ayrı bir `honeypot-watchdog.exe` vardı. Bunu **çıkardık** çünkü:

| Sorun | Açıklama |
|-------|----------|
| **Crash loop riski** | Kod hatası varsa watchdog sürekli yeniden başlatır → CPU %100 |
| **Nükleer buton** | Max restart aşılınca tüm portları kapatıyordu → sunucu brick |
| **Karmaşıklık** | İki ayrı .exe bakımı, PyInstaller build, iki süreç yönetimi |
| **Gereksiz** | Task Scheduler zaten aynı işi yapıyor (on-event trigger) |

**Zamanlanmış Görev yeterli çünkü:**
- `on_boot` + `on_logon` trigger'ları ile client her zaman ayağa kalkar
- `on_event` trigger'ı ile süreç sonlanma anında yeniden başlatılır
- Windows'un kendi mekanizması — crash loop koruması built-in
- Ek bakım yükü yok

### Koruma Katmanları Özet Tablosu

| Katman | Mekanizma | Saldırgan Senaryosu | Sonuç |
|--------|-----------|---------------------|-------|
| 1 | Zamanlanmış Görev (auto-restart) | Task Manager → End Task | ✅ Birkaç saniye içinde yeniden başlar |
| 2 | Süreç DACL koruması | Basit `taskkill` komutu | ✅ "Erişim reddedildi" hatası |
| 3 | Güvenli Son Nefes | Admin olarak kill | ⚡ Sadece saldırgan IP engellenir + alert |
| — | Kod hatası / güncelleme çökmesi | Client hata verip kapandı | ✅ Firewall'a dokunulmaz, task restarts |

> **Tasarım Felsefesi:** "Önce zarar verme" (Primum non nocere).
> Son nefes mekanizması asla sunucuyu erişilemez hale getirmemeli.
> En kötü senaryoda bile sadece saldırganın IP'si engellenir.
> Client zamanlanmış görevle yeniden ayağa kalkar ve tüm koruma devam eder.

---

## 12. GUI Güncellemeleri

### Sessiz Saatler Widget (GUI)

```
Ana dashboard'da mini widget:
  [🔇 Sessiz Saatler: AKTİF ⏱️ 00:00-07:00]  ← Yeşil/kırmızı durum

Ayarlar sekmesinde tam panel (yukarıdaki Dashboard Arayüzü)
```

### Yeni Dashboard Kartları

```
Mevcut:
  [Aktif Servisler] [Oturum Saldırıları] [Toplam Saldırılar]
  [Uptime]          [Son Saldırı]        [API Bağlantı]

Yeni (2. satır):
  [🔴 Tehdit Seviyesi] [📊 Olay/Saat]  [🛡️ Engellenen IP]
  [🔑 Başarılı Giriş]  [🧬 Ransomware] [💻 CPU/RAM]
```

### Tehdit Akışı (Live Threat Feed)

```
┌─────────────────────────────────────────────────────┐
│ 📋 Son Tehditler                                     │
├─────────────────────────────────────────────────────┤
│ 🔴 23:15:42  RDP Brute Force → Başarılı Giriş!      │
│              192.168.1.105 (Rusya) → admin           │
│              ⚡ Otomatik engellendi                   │
│                                                      │
│ 🟠 23:14:18  SQL Server — xp_cmdshell çalıştırıldı  │
│              10.0.0.50 → sa                          │
│                                                      │
│ 🟡 23:10:05  Yeni servis yüklendi: "WindowsUpdate"  │
│              Şüpheli isim — kontrol edilmeli         │
│                                                      │
│ 🔵 23:05:33  SSH brute force tespiti (45 deneme)     │
│              185.220.101.34 (Almanya)                │
│              ⚡ Otomatik engellendi                   │
└─────────────────────────────────────────────────────┘
```

### Toast Bildirimleri

Kritik olaylarda masaüstünde toast notification (pystray balloon veya `win10toast`):

```python
def show_threat_toast(self, alert: ThreatAlert):
    """Windows toast bildirimi göster."""
    if alert.severity in ("critical", "high"):
        # pystray.Icon.notify() veya win10toast
        title = f"⚠️ {alert.title}"
        message = f"{alert.source_ip} ({alert.source_country}) → {alert.target_service}"
```

---

## 13. Veri Yapıları & Formatlar

### Threat Event (Client → API)

```json
{
    "token": "abc-123",
    "event_type": "threat_alert",
    "alert": {
        "alert_id": "uuid-v4",
        "timestamp": "2026-02-08T23:15:42Z",
        "severity": "critical",
        "threat_type": "brute_force_success",
        "title": "RDP Brute Force — Başarılı Giriş Tespit Edildi!",
        "description": "192.168.1.105 adresinden 47 başarısız denemenin ardından 'administrator' hesabıyla başarılı RDP girişi yapıldı.",
        "source_ip": "192.168.1.105",
        "source_country": "RU",
        "source_city": "Moscow",
        "target_service": "RDP",
        "target_port": 3389,
        "username": "administrator",
        "threat_score": 95,
        "windows_event_ids": [4625, 4625, 4624, 4672],
        "correlation_rule": "brute_force_then_access",
        "recommended_action": "Hesap şifresini değiştirin, oturumu kapatın",
        "auto_response_taken": ["block_ip", "notify_urgent"],
        "system_context": {
            "hostname": "WIN-SERVER01",
            "os_version": "Windows Server 2022",
            "cpu_percent": 45.2,
            "memory_percent": 68.1,
            "uptime_hours": 142.5
        }
    }
}
```

### Batch Events (Client → API, düşük öncelikli)

```json
{
    "token": "abc-123",
    "event_type": "threat_events_batch",
    "events": [
        {
            "event_id": "uuid-v4",
            "timestamp": "...",
            "category": "failed_logon",
            "source_ip": "1.2.3.4",
            "service": "SSH",
            "username": "root",
            "windows_event_id": 4625,
            "threat_score": 5
        }
    ],
    "summary": {
        "period_start": "...",
        "period_end": "...",
        "total_events": 156,
        "unique_ips": 23,
        "top_targeted_services": {"SSH": 89, "RDP": 45, "MSSQL": 22}
    }
}
```

### System Health Snapshot (Client → API)

```json
{
    "token": "abc-123",
    "event_type": "system_health",
    "snapshot": {
        "timestamp": "...",
        "cpu_percent": 92.5,
        "memory_percent": 88.3,
        "disk_usage_percent": 76.0,
        "disk_io_read_bytes_sec": 150000000,
        "disk_io_write_bytes_sec": 250000000,
        "network_bytes_sent_sec": 5000000,
        "network_bytes_recv_sec": 1200000,
        "process_count": 245,
        "top_cpu_processes": [
            {"name": "suspicious.exe", "pid": 1234, "cpu": 85.2, "memory_mb": 500}
        ],
        "open_connections": 89,
        "anomalies_detected": ["cpu_spike", "disk_io_spike"]
    }
}
```

---

## 14. API Endpoint Gereksinimleri

### Yeni Endpointler (Backend'de açılması gereken)

#### 🔴 Acil Alert Bildirimi

```
POST /api/alerts/urgent
Authorization: Bearer {token}

Body: ThreatAlert JSON (yukarıdaki format)

Response 200:
{
    "status": "received",
    "alert_id": "uuid",
    "actions_requested": ["block_ip"]    // Backend'in client'a geri talimatı
}

Davranış:
  1. Alert'i DB'ye kaydet
  2. Kullanıcıya E-POSTA gönder (anlık)
  3. Push notification (varsa mobile app)
  4. Dashboard'da gerçek zamanlı göster (WebSocket)
```

#### 🟡 Batch Event Raporu

```
POST /api/events/batch
Authorization: Bearer {token}

Body: Batch Events JSON (yukarıdaki format)

Response 200:
{
    "status": "received",
    "events_processed": 156
}

Davranış:
  1. Events'leri time-series DB'ye yaz
  2. Dashboard istatistiklerini güncelle
  3. Trend analizi için kullan
```

#### 💚 Sistem Sağlık Raporu

```
POST /api/health/report
Authorization: Bearer {token}

Body: System Health Snapshot JSON

Response 200:
{
    "status": "received"
}

Davranış:
  1. Metrikleri zaman serisi olarak sakla
  2. Anomali varsa dashboard'da uyarı göster
```

#### 🔐 Otomatik Blok Bildirimi

```
POST /api/alerts/auto-block
Authorization: Bearer {token}

Body:
{
    "token": "abc-123",
    "blocked_ip": "1.2.3.4",
    "reason": "brute_force_success",
    "threat_score": 95,
    "duration_hours": 24,
    "alert_id": "uuid-ref",
    "blocked_at": "2026-02-08T23:15:42Z"
}

Response 200:
{
    "status": "confirmed",
    "extend_duration": false    // Backend uzatma isteyebilir
}
```

#### 📊 Tehdit Özeti Sorgulama

```
GET /api/threats/summary?token={token}&period=24h
Authorization: Bearer {token}

Response 200:
{
    "period": "24h",
    "total_events": 1523,
    "critical_alerts": 3,
    "high_alerts": 12,
    "unique_attackers": 45,
    "top_attackers": [
        {"ip": "1.2.3.4", "country": "CN", "events": 234, "score": 95}
    ],
    "top_targeted_services": {"RDP": 456, "SSH": 312},
    "auto_blocks_applied": 8,
    "system_health": "normal"
}
```

#### ⚙️ Tehdit Konfigürasyonu

```
GET /api/threats/config?token={token}
Authorization: Bearer {token}

Response 200:
{
    "whitelist_ips": ["10.0.0.1"],
    "whitelist_subnets": ["192.168.1.0/24"],
    "auto_block_enabled": true,
    "auto_block_threshold": 80,
    "alert_email_enabled": true,
    "alert_email": "admin@company.com",
    "working_hours": {"start": "08:00", "end": "18:00"},
    "ransomware_protection": true,
    "canary_files_enabled": true
}

Davranış:
  Client başlangıçta ve periyodik olarak bu config'i çeker.
  Dashboard'dan kullanıcı bu ayarları değiştirebilir.
```

#### 🔔 E-posta Bildirim Tercihleri

```
PUT /api/notifications/preferences
Authorization: Bearer {token}

Body:
{
    "token": "abc-123",
    "email_alerts": true,
    "alert_email": "admin@company.com",
    "min_severity_for_email": "high",
    "daily_digest": true,
    "digest_time": "09:00",
    "instant_for_critical": true,
    "webhook_url": "https://hooks.slack.com/...",
    "webhook_enabled": false
}
```

---

## 15. Uygulama Fazları

### Faz 1 — Temel Tehdit Algılama (v4.0-alpha) — ~2 hafta

```
☑️ client_eventlog.py      — Windows Event Log Watcher (Security + System + RDP)  ✔ DONE
☑️ client_threat_engine.py  — Basit skor sistemi (kurallar olmadan, direkt skor)   ✔ DONE
☑️ client_alerts.py         — API urgent + batch gönderimi                         ✔ DONE
✅ API: POST /api/alerts/urgent       (Backend tarafı — endpoint tanımı hazır)
✅ API: POST /api/events/batch        (Backend tarafı — endpoint tanımı hazır)
✅ API: E-posta gönderimi (critical alertler için) (Backend tarafı)
☑️ GUI: Tehdit seviyesi kart + toast bildirimi                                     ✔ DONE
```

**Client-side Faz 1 tamamlandı!** Backend API endpoints'i API_ENDPOINTS_v4_PROMPT.md'ye göre uygulanacak.

### Faz 2 — Akıllı Korelasyon + Uzaktan Müdahale (v4.0-beta) — ~2 hafta

```
☑️ Korelasyon kuralları motoru (zaman penceresi, çapraz servis)                     ✔ DONE
☑️ IP bağlam havuzu (IPContext)                                                     ✔ DONE
☑️ client_auto_response.py — Otomatik firewall engelleme + defensive actions        ✔ DONE
☑️ client_remote_commands.py — Uzaktan müdahale komut yürütücü (14 komut)           ✔ DONE
☑️ client_silent_hours.py — Sessiz saatler otomatik engelleme (5 mod)               ✔ DONE
☑️ API: POST /api/alerts/auto-block                                                 ✔ DONE
☑️ API: GET /api/commands/pending + POST /api/commands/result                       ✔ DONE
☑️ API: GET /api/threats/config + POST /api/alerts/silent-hours                     ✔ DONE
☑️ client_constants.py — 14 Faz 2 sabiti eklendi                                   ✔ DONE
☑️ client.py — Faz 2 modülleri entegre (init → start → stop → config sync)         ✔ DONE
☑️ Dashboard: Anında müdahale butonları (Block IP, Logoff, Disable, Snapshot)       ✔ DONE
☑️ Dashboard: Sessiz saatler durum göstergesi (🔇/🔊)                               ✔ DONE
☑️ GUI: Canlı Tehdit Akışı (Live Threat Feed — scrollable, last 200)               ✔ DONE
☑️ Whitelist/güvenli subnet konfigürasyonu (SilentHoursConfig)                      ✔ DONE
```

**Client-side Faz 2 tamamlandı!** Backend API endpoints'i API_ENDPOINTS_v4_PROMPT.md'ye göre uygulanacak.

### Faz 3 — Ransomware Kalkanı (v4.0-rc) — ~2 hafta

```
☑️ client_ransomware_shield.py — Canary files + FS watchdog ✔ DONE
☑️ VSS izleme ✔ DONE
☑️ Şüpheli süreç tespiti ✔ DONE
☑️ Emergency lockdown mekanizması ✔ DONE
☑️ client_system_health.py — CPU/RAM/Disk anomali tespiti ✔ DONE
☑️ Süreç kendini koruma (DACL + Güvenli Son Nefes + Task Scheduler restart) ✔ DONE
☑️ API: POST /api/health/report ✔ DONE
☑️ GUI: Dashboard Faz 3 kartları (Ransomware, CPU/RAM, Protection) ✔ DONE
☑️ client.py entegrasyonu (import, init, start, stop) ✔ DONE
☑️ client_constants.py — Faz 3 sabitleri ✔ DONE
```

**Client-side Faz 3 tamamlandı!** Backend API endpoints'i API_ENDPOINTS_v4_PROMPT.md'ye göre uygulanacak.

### Faz 4 — Cilalama & Production (v4.0.0) — ~1 hafta

```
☑️ API: GET /api/threats/summary ✔ DONE
☑️ API: PUT /api/notifications/preferences ✔ DONE
☑️ API: POST /api/events/batch ✔ DONE
☑️ Dashboard: Komut geçmişi + durum takibi ✔ DONE
☑️ Dashboard: Aktif oturum / süreç listesi görüntüleme ✔ DONE
☑️ GUI: Gelişmiş dashboard (ASCII sparkline trendler) ✔ DONE
☑️ Performans optimizasyonu (PerformanceOptimizer — adaptive throttling) ✔ DONE
☑️ False positive tuning (FalsePositiveTuner — cooldown, auto-whitelist) ✔ DONE
☑️ Installer güncellemesi (PyInstaller spec — tüm modüller) ✔ DONE
☑️ client_constants.py — Faz 4 sabitleri + VERSION 4.0.0 ✔ DONE
☑️ client.py entegrasyonu (import, init, start, stop) ✔ DONE
```

**Client-side Faz 4 tamamlandı!** 🎉 v4.0.0 production-ready.

---

## 16. Teknik Riskler & Çözümler

| Risk | Etki | Çözüm |
|------|------|-------|
| Event Log hacmi çok yüksek | CPU/RAM tüketimi | XPath filtresi ile sadece ilgili Event ID'leri al |
| False positive çokluğu | Kullanıcı alert yorgunluğu | Whitelist, cooldown, skor eşiği ayarlanabilir |
| win32evtlog erişim yetkisi | Admin gerektiriyor | Uygulama zaten admin çalışıyor ✅ |
| Ransomware canary dosya boyutu | Disk kullanımı | Her dosya 1-5KB, toplam < 1MB |
| Emergency lockdown → kendi kendini kilitleme | Sunucuya erişim kaybı | Management IP whitelist + timeout |
| GeoIP veritabanı güncelleme | Eski veri | MaxMind GeoLite2 — aylık güncelleme |
| Çok fazla firewall kuralı | Performans | Chunk bazlı kural, periyodik temizlik |
| Event Log servisi devre dışı | İzleme devre dışı | Başlangıçta kontrol + kullanıcı uyarısı |
| Uzaktan komut kötüye kullanımı | Yetkisiz aksiyon | Komut süresi dolumu (5dk) + koruma listeleri + audit log |
| Şifre sıfırlama sonrası erişim kaybı | Meşru kullanıcı kilitlenir | Yeni şifre e-posta ile bildirilir + onay mekanizması |
| API iletişim kesintisi | Komutlar ulaşmaz | Komut expire süresi + lokal otomatik savunma devrede |
| Sessiz saatte meşru kullanıcı engellenir | Admin dışarıda kalır | Dashboard "Bu Benim" butonu + e-posta onay linki |
| Yanlış saat dilimi ayarı | Sessiz saatler yanlış çalışır | Sunucu sistem saati + timezone config |
| Watchdog sonsuz restart döngüsü | — | Watchdog kaldırıldı — Task Scheduler yeterli, crash loop riski yok |
| Saldırgan client'ı öldürür | Kısa süre kör | Güvenli Son Nefes: sadece şüpheli IP engellenir + Task Scheduler restart |

---

## 🏁 Sonuç

Bu yol haritası ile Cloud Honeypot Client:

1. **Reaktif** olmaktan çıkıp **proaktif** bir güvenlik aracına dönüşecek
2. Sadece "kapıda bekleyen" değil, **kapıyı geçeni de yakalayan** bir sistem olacak
3. Ransomware'a karşı **çok katmanlı savunma** sunacak
4. **Anlık bildirim** ile kullanıcıyı saniyeler içinde haberdar edecek
5. **Otomatik savunma** ile saldırgana müdahale süresini saniyeye indirecek
6. **Dashboard'dan uzaktan müdahale** ile nerede olursanız olun saldırıyı anında durdurabileceksiniz
7. **Sessiz saatler** ile gece uyurken bile saldırganı kapıda durduracak — beyaz listede değilsen içeri adım atamazsın
8. **Süreç kendini koruma** ile saldırgan client'ı kapatsa bile şüpheli IP engellenir, zamanlanmış görev saniyeler içinde client'ı yeniden ayaklandırır

> *"Gece 3'te saldırgan şifreyi buldu ve girdi.*
> *Ama Sessiz Saatler aktif — IP engellendi, oturum kapatıldı, hesap kilitlendi.*
> *Saldırgan client.exe'yi durdurmaya çalıştı — Güvenli Son Nefes: saldırganın IP'si engellendi.*
> *Zamanlanmış görev client'ı yeniden başlattı.*
> *Admin sabah kahvesini içerken dashboard'a baktı: 'Gece 03:14 — saldırı engellendi ✅'*
> *Tek yapması gereken: hiçbir şey. Sistem zaten her şeyi halletmişti."*
