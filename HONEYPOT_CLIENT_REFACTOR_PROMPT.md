# Honeypot Client Refactoring — Comprehensive Prompt for Opus 4.6

## 🎯 GÖREV ÖZETİ

Windows üzerinde çalışan Python tabanlı bir honeypot client uygulamasını refactor etmen gerekiyor. Mevcut mimari şu şekilde çalışıyor:

**ESKİ MİMARİ (DEĞİŞTİRİLECEK):**
```
[Client/Windows] → TLS tunnel (port 4443) → [Relay Server] → [OpenCanary Docker] → log parse → POST /attacks/
```

**YENİ MİMARİ (HEDEF):**
```
[Client/Windows] — kendi içinde lightweight honeypot servisleri çalıştırır
                  — credential'ları yakalar
                  — doğrudan HTTPS POST → Server API (honeypot.yesnext.com.tr)
```

Yani artık tunnel/relay/OpenCanary yok. Client kendi içinde sahte RDP, SSH, FTP, MySQL, MSSQL servisleri çalıştıracak, gelen saldırganların credential bilgilerini (username + password) yakalayacak ve doğrudan sunucu API'sine POST edecek.

## ⚠️ KRİTİK KURALLAR

1. **Platform:** Windows 10/11. PyInstaller ile tek .exe'ye derlenir. Installer ile kurulur.
2. **Mevcut client zaten Python ile yazılmış.** Tamamen sıfırdan yazmıyorsun — refactor ediyorsun.
3. **Dashboard üzerinden yönetim özellikleri KESİNLİKLE çalışmaya devam etmeli:** blok kuralları, engellenen IP'leri görme, engeli uzaktan kaldırma, portlara müdahale, tunnel yönetimi vb.
4. **RDP port taşıma mekanizması korunmalı:** Client gerçek RDP portunu güvenli porta taşıyor, sonra kullanıcının yeni porttan bağlanıp onay vermesini bekliyor. Bu akış aynen kalmalı.
5. **Tunnel yönetimi kavramı değişiyor:** Artık tunnel yok, ama "honeypot servis yönetimi" olarak devam ediyor. Dashboard'dan servis başlat/durdur mantığı korunmalı.
6. **Kaynak tüketimi DÜŞÜK olmalı:** Bu bir Windows PC'de arka planda çalışacak. Her sahte servis hafif olmalı, gereksiz thread/memory kullanmamalı.
7. **Güvenlik:** Honeypot servisleri GERÇEK kimlik doğrulama YAPMAZ. Sadece protocol handshake'i taklit eder, credential yakalar, bağlantıyı düşürür.

---

## 📡 SUNUCU API TAM REFERANSI

**Base URL:** `https://honeypot.yesnext.com.tr`

### 1. Client Kayıt & Yaşam Döngüsü

#### `POST /api/register`
Yeni client kaydı. İlk çalıştırmada bir kez çağrılır, token alınır ve saklanır.
```json
// Request
{"server_name": "WIN-ABC123", "ip": "85.100.50.1"}

// Response
{"token": "0ea8836b-xxxx-xxxx-xxxx-xxxxxxxxxxxx", "dashboard_url": "https://honeypot.yesnext.com.tr/dashboard?token=0ea8836b..."}
```

#### `POST /api/update-ip`
Client IP değiştiğinde çağrılır.
```json
{"token": "xxx", "ip": "85.100.50.2"}
```

#### `POST /api/heartbeat`
Periyodik olarak (60 saniyede bir) çağrılır. Sunucu `last_seen` günceller, 2 dakika geçerse "offline" sayar.
```json
{"token": "xxx", "status": "online"}
```

#### `GET /api/client_status?token=xxx`
Client'ın canlı olup olmadığını kontrol eder. Response: `{"alive": true/false}`

---

### 2. Saldırı Raporlama (EN ÖNEMLİ)

#### `POST /api/attack` ← **CLIENT BU ENDPOINT'İ KULLANACAK**
Token bazlı saldırı raporlama. Her yakalanan credential için bu endpoint'e POST yapılır.
```json
{
  "token": "0ea8836b-...",
  "ip": "45.67.89.10",           // saldırgan IP (geriye uyumluluk)
  "attacker_ip": "45.67.89.10",  // saldırgan IP (tercih edilen)
  "target_ip": "85.100.50.1",    // client'ın kendi IP'si
  "username": "admin",
  "password": "P@ssw0rd123",
  "service": "RDP",              // RDP, SSH, FTP, MYSQL, MSSQL
  "port": 3389
}
```

**Response:** `{"status": "ok"}` veya hata durumunda HTTP error.

**Servis normalizasyon kuralları (sunucu tarafında uygulanır ama client da gönderirken uymalı):**
- Port 3389 → "RDP"
- Port 1433 → "MSSQL"  
- Port 3306 → "MYSQL"
- Port 22 → "SSH"
- Port 21 → "FTP"
- Port 23 → "TELNET"
- Port 445 → "SMB"

**ÖNEMLİ:** `username` ve `password` alanları artık CLIENT tarafından doldurulacak. Eski sistemde OpenCanary RDP modülü sadece `mstshash=` cookie'sinden username alabiliyordu, password yakalayamıyordu. Yeni sistemde client'ın kendi protocol parser'ları ile her iki bilgiyi de yakalaması gerekiyor.

---

### 3. Blok Yönetimi (Agent Polling)

Client periyodik olarak (30 saniyede bir) bu endpoint'leri poll eder:

#### `GET /api/agent/pending-blocks?token=xxx`
Dashboard'dan eklenen bekleyen blok kurallarını çeker.
```json
// Response
[
  {"id": 42, "ip_or_cidr": "45.67.89.0/24", "reason": "çoklu deneme", "expires_at": null},
  {"id": 43, "ip_or_cidr": "country:CN", "reason": "ülke bloğu", "expires_at": null}
]
```
**Önemli:** `ip_or_cidr` değeri şunlar olabilir:
- Tek IP: `"1.2.3.4"`
- CIDR: `"1.2.3.0/24"`
- Ülke kodu: `"country:CN"`, `"country:RU"` vb.

Client bunları Windows Firewall kurallarına çevirir.
- IP/CIDR → `netsh advfirewall firewall add rule` ile engeller
- `country:XX` → O ülkenin IP bloklarını (GeoIP lookup) indirir ve toplu kural ekler

#### `POST /api/agent/block-applied`
Bloklar başarıyla uygulandığında sunucuya bildirir.
```json
{"token": "xxx", "block_ids": [42, 43]}
```

#### `GET /api/agent/pending-unblocks?token=xxx`
Dashboard'dan kaldırılması istenen blokları çeker.
```json
// Response
[{"id": 42, "ip_or_cidr": "45.67.89.0/24"}]
```

#### `POST /api/agent/block-removed`
Engel kaldırıldıktan sonra bildirir.
```json
{"token": "xxx", "block_ids": [42]}
```

---

### 4. Port Raporlama

#### `POST /api/agent/open-ports`
Client'ın açık portlarını sunucuya raporlar (periyodik, 5 dakikada bir).
```json
{
  "token": "xxx",
  "ports": [
    {"port": 3389, "proto": "TCP", "addr": "0.0.0.0", "state": "LISTEN", "process": "svchost.exe", "pid": 1234},
    {"port": 22, "proto": "TCP", "addr": "0.0.0.0", "state": "LISTEN", "process": "honeypot.exe", "pid": 5678}
  ]
}
```
Dashboard'da "Portlar" sekmesinde gösterilir.

---

### 5. Tunnel/Servis Yönetimi

**Konsept değişikliği:** Eskiden "tunnel" kelimesi kullanılıyordu (TLS tunnel üzerinden relay'e bağlanma). Artık bu, "honeypot servis yönetimi" olacak. Dashboard'daki UI zaten tunnel-set/tunnel-status kullanıyor, client tarafında bu artık "honeypot servisini başlat/durdur" anlamına gelecek.

#### `GET /api/premium/tunnel-status?token=xxx`
Mevcut servis durumlarını çeker.
```json
{
  "RDP": {"listen_port": 3389, "new_port": null, "status": "started", "desired": "started"},
  "MSSQL": {"listen_port": 1433, "new_port": null, "status": "stopped", "desired": "stopped"},
  "MYSQL": {"listen_port": 3306, "new_port": null, "status": "stopped", "desired": "stopped"},
  "FTP": {"listen_port": 21, "new_port": null, "status": "stopped", "desired": "stopped"},
  "SSH": {"listen_port": 22, "new_port": null, "status": "started", "desired": "started"}
}
```

**`desired` alanı dashboard'dan kullanıcı tarafından değiştirilir.** Client bunu poll eder ve `desired` ile mevcut `status` farklıysa servisi başlatır/durdurur.

#### `POST /api/agent/tunnel-status`
Client, servis durumlarını günceller.
```json
{
  "token": "xxx",
  "statuses": [
    {"service": "RDP", "status": "started", "listen_port": 3389, "new_port": null},
    {"service": "SSH", "status": "started", "listen_port": 22, "new_port": null},
    {"service": "FTP", "status": "stopped", "listen_port": 21, "new_port": null}
  ]
}
```

**`status` değerleri:** `"started"` | `"stopped"` | `"unknown"` | `"error"`

#### Dashboard'dan servis kontrolü:
`POST /api/premium/tunnel-set` — Dashboard'dan yapılır, client poll eder.
```json
{"token": "xxx", "service": "SSH", "action": "start", "new_port": null}
```

Bu çağrı sunucu tarafında `tunnel_commands` kuyruğuna bir komut ekler. Client, `tunnel-status` endpoint'ini poll ederken `desired` alanını kontrol edip servisi başlatır/durdurur.

---

### 6. Premium Özellikler

#### `POST /api/premium/settings`
```json
{"token": "xxx", "notify_email": "admin@example.com", "first_name": "Ahmet", "last_name": "Yılmaz"}
```

#### Notification Rules CRUD:
- `GET /api/premium/rules?token=xxx` → Kural listesi
- `POST /api/premium/rules` → Yeni kural
  ```json
  {
    "token": "xxx", "name": "RDP Alert", "services": "RDP,SSH",
    "threshold_count": 10, "window_minutes": 10,
    "match_usernames": "admin\nroot\nsa",
    "actions": "email,block", "enabled": true
  }
  ```
- `PUT /api/premium/rules/{id}` → Güncelle
- `DELETE /api/premium/rules/{id}?token=xxx` → Sil

#### Export Endpoints:
- `GET /api/premium/attacks.csv?token=xxx&service=RDP&from=2025-01-01&to=2025-06-30`
- `GET /api/premium/attacks.json?token=xxx&...`
- `GET /api/premium/attacks.xls?token=xxx&...`

---

### 7. Dashboard Sayfaları (bilgi amaçlı)

Client'ın dashboard'la doğrudan ilişkisi yok (dashboard sunucu tarafında render ediliyor), ama yönetim özelliklerinin çalışması için client'ın agent API'lerini doğru kullanması gerekiyor.

| Sayfa | URL | Açıklama |
|-------|-----|----------|
| Ana Dashboard | `/dashboard?token=xxx` | İstatistik kartları, trend grafik, top servis/IP |
| Saldırı Geçmişi | `/dashboard/attacks?token=xxx` | Filtreleme, sayfalama, sıralama, IP gruplama |
| Blok Kuralları | `/dashboard/blocks?token=xxx` | Bekleyen/uygulanan bloklar, ülke bazlı blok, IP blok |
| Port Yönetimi | `/dashboard/ports?token=xxx` | Client'ın açık portları |
| Tünel/Servis Yönetimi | `/dashboard/tunnels?token=xxx` | Honeypot servisleri başlat/durdur |
| Ayarlar | `/dashboard/settings?token=xxx` | E-posta, bildirim kuralları |

---

## 🏗️ YENİ MİMARİ DETAYI

### Lightweight Honeypot Servisleri

Her servis aşağıdaki özelliklere sahip olmalı:

#### 1. Fake RDP Service (Port 3389)
**EN KRİTİK SERVİS — Credential capture zorunlu.**

RDP bağlantı akışı:
1. TCP bağlantısı gelir
2. X.224 Connection Request: `mstshash=<username>` cookie'si parse edilir (bu eski OpenCanary'nin yaptığı)
3. **ASIL HEDEF:** NLA (Network Level Authentication) / CredSSP handshake aşamasında username + password yakalanmalı

**RDP credential capture yaklaşımları (en kolaydan zora):**

**Yaklaşım A — Sadece NTLM'den username parse (orta zorluk):**
- TLS handshake yap (self-signed cert ile)
- CredSSP/TSRequest parse et
- NTLM AUTHENTICATE_MESSAGE'dan username, domain çıkar
- Password bu yöntemle ALINAMAZ ama username kesin alınır

**Yaklaşım B — Sahte NLA başarısız yanıt (kolay):**
- X.224 Connection Request'ten mstshash username'i al
- Server, RDP Negotiation Response'ta TLS olduğunu söyler
- TLS el sıkışma
- CredSSP akışında NTLM challenge gönder
- Client NTLM response gönderir → username + domain + NT hash (password değil ama hash alınır)
- CredSSP hata kodu ile bağlantıyı kapat

**Yaklaşım C — Downgrade to RDP Security (EN İYİ - password alınabilir):**
- X.224 Connection Request gelir
- Server, Negotiation Response'ta NLA yerine "RDP Security" seçer (protocol flag 0x00)
- Client NLA desteklemiyorsa düz RDP bağlantısına düşer
- MCS/GCC Conference Create'te client bilgileri gelir
- Client Info PDU'da username + password AÇIK METİN olarak gelir!
- ⚠️ Modern RDP client'lar NLA zorunlu kılıyorsa bu çalışmaz

**Önerilen:** Yaklaşım B + cookie parsing. Mümkünse Yaklaşım C'yi de dene, client destekliyorsa password yakala, desteklemiyorsa en azından NTLM username + domain yakala.

**Minimum kabul kriteri:** Her RDP denemesinde en az username yakalanmalı. Password yakalanamazsa boş gönderilebilir.

#### 2. Fake SSH Service (Port 22)
SSH protocol credential capture oldukça KOLAY:
1. Client bağlanır → Server SSH banner gönderir: `SSH-2.0-OpenSSH_8.9p1\r\n`
2. Key exchange: Diffie-Hellman veya curve25519
3. `SSH_MSG_USERAUTH_REQUEST` (type 50): username + password AÇIK METİN olarak gelir (password auth method için)

**Uygulama:**
- `paramiko` veya `asyncssh` kütüphanesi kullanılabilir
- Veya sıfırdan minimal SSH server yazılabilir
- `paramiko.ServerInterface` subclass'ı ile `check_auth_password(username, password)` override edilir → her zaman `AUTH_FAILED` döner ama credential kaydedilir

**Tercih edilen:** `paramiko` kullan, çok küçük footprint, Windows'ta sorunsuz çalışır.

#### 3. Fake FTP Service (Port 21)
FTP credential capture EN KOLAY olanı:
1. Bağlantı → `220 Microsoft FTP Service\r\n` banner gönder
2. Client: `USER admin\r\n` → `331 Password required\r\n`
3. Client: `PASS mypassword\r\n` → `530 Login incorrect\r\n`
4. Username + password kaydedildi! Bağlantıyı kapat.

**Uygulama:** Sadece TCP socket + readline. Kütüphane gerekmez.

#### 4. Fake MySQL Service (Port 3306)
MySQL protocol credential capture:
1. Client bağlanır → Server MySQL Greeting paketi gönderir (protocol version, server version, salt/challenge)
2. Client Login Request gönderir: username + auth response (password hash'i)
3. Server `ERR_PACKET` gönderir (Access denied)

**Uygulama:**
- MySQL wire protocol implementasyonu gerekir (basit)
- Server greeting: `\x0a` + version string + thread_id + salt + capabilities + charset + status + extended_salt
- Client response'tan username ve hashed password çıkarılır
- Password HASH olarak gelir (SHA1 veya SHA256), cleartext değil
- DB'ye password olarak `"[mysql_native_hash]"` veya `"[sha256_hash]"` yazılabilir

#### 5. Fake MSSQL Service (Port 1433)
MSSQL/TDS protocol credential capture:
1. Client TDS Login7 paketi gönderir
2. Login7'den username + password AÇIK METİN çıkarılır! (XOR obfuscation ile ama kolay decode edilir)
3. Server Login Failed yanıtı gönderir

**Uygulama:**
- TDS 7.0+ Login7 packet parsing
- Username/password offset'leri Login7 header'dan okunur
- Password XOR decode: her byte'ın nibble'ları swap edilir ve 0xA5 ile XOR'lanır
- Sonuç: cleartext username + password!

---

## 🔧 CLIENT MİMARİSİ

### Ana Bileşenler

```
honeypot_client/
├── main.py                 # Entry point, Windows service/tray integration
├── config.py               # Token, API URL, settings yönetimi
├── api_client.py           # Sunucu API iletişimi (requests/httpx)
├── agent/
│   ├── heartbeat.py        # Periyodik heartbeat
│   ├── block_manager.py    # Pending blocks polling + Windows Firewall
│   ├── port_reporter.py    # Open ports scanning + reporting
│   └── service_manager.py  # Honeypot servisleri orchestration
├── honeypot/
│   ├── base.py             # BaseHoneypot abstract class
│   ├── rdp.py              # Fake RDP service
│   ├── ssh.py              # Fake SSH service (paramiko)
│   ├── ftp.py              # Fake FTP service
│   ├── mysql.py            # Fake MySQL service
│   └── mssql.py            # Fake MSSQL service
├── rdp_migration.py        # RDP port taşıma mekanizması (MEVCUT - KORU)
└── utils/
    ├── firewall.py         # Windows Firewall netsh wrapper
    ├── network.py          # IP detection, port scanning
    └── logger.py           # Logging
```

### BaseHoneypot Abstract Class

```python
from abc import ABC, abstractmethod
import asyncio
import logging

class BaseHoneypot(ABC):
    def __init__(self, port: int, service_name: str, on_credential_captured: callable):
        self.port = port
        self.service_name = service_name
        self.on_credential_captured = on_credential_captured  # callback(attacker_ip, username, password, port)
        self.server = None
        self.running = False
        self.logger = logging.getLogger(f"honeypot.{service_name.lower()}")
    
    @abstractmethod
    async def start(self):
        """Servis dinlemeye başlar"""
        pass
    
    @abstractmethod
    async def stop(self):
        """Servis durdurulur"""
        pass
    
    @abstractmethod
    async def handle_connection(self, reader, writer):
        """Tek bağlantı işlenir, credential yakalanır"""
        pass
    
    def report_credential(self, attacker_ip: str, username: str, password: str = None):
        """Yakalanan credential'ı callback ile bildirir"""
        self.on_credential_captured(
            attacker_ip=attacker_ip,
            username=username or "",
            password=password or "",
            service=self.service_name,
            port=self.port
        )
```

### Credential Callback Flow

```python
# service_manager.py'de:

def _on_credential(self, attacker_ip, username, password, service, port):
    """Her yakalanan credential için çağrılır"""
    # 1. Rate limiting: Aynı IP + service için son 60 saniyede max 5 rapor
    # 2. Queue'ya ekle (thread-safe)
    # 3. Batch sender thread her 5 saniyede queue'yu boşaltıp POST /api/attack yapar
    
    payload = {
        "token": self.token,
        "ip": attacker_ip,
        "attacker_ip": attacker_ip,
        "target_ip": self.my_ip,
        "username": username,
        "password": password,
        "service": service,
        "port": port
    }
    self.attack_queue.put(payload)
```

### Polling Döngüleri

```
Her 30 saniye:
  - GET /api/agent/pending-blocks → Windows Firewall kuralları uygula → POST /api/agent/block-applied
  - GET /api/agent/pending-unblocks → Firewall kuralları kaldır → POST /api/agent/block-removed

Her 60 saniye:
  - POST /api/heartbeat

Her 2 dakika:
  - GET /api/premium/tunnel-status → desired vs actual karşılaştır → servisleri başlat/durdur
  - POST /api/agent/tunnel-status → güncel durumları raporla

Her 5 dakika:
  - Port scan → POST /api/agent/open-ports
```

---

## 🔒 RDP PORT TAŞIMA MEKANİZMASI (MEVCUT — KORU)

Bu mekanizma client'ta zaten var ve AYNEN korunmalı. Özet:

1. Kullanıcı dashboard'dan "RDP Honeypot Başlat" dediğinde:
2. Client gerçek RDP servisinin portunu (varsayılan 3389) yeni bir porta (örn. 53389) taşır
   - Registry: `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\PortNumber`
   - Windows Firewall: Yeni port için kural ekler
   - Eski porttan RDP'yi dinlemeyi durdurur
3. Kullanıcıya "Yeni RDP portunuz: 53389. Bu porttan bağlanmayı test edin" mesajı gösterir
4. Kullanıcı onay verene kadar bekler (timeout ile geri alınabilir)
5. Onay gelirse: Port 3389'da sahte RDP honeypot başlatılır
6. İptal/timeout olursa: Gerçek RDP portu eski yerine geri taşınır

**⚠️ KRİTİK:** Bu akış sırasında kullanıcı RDP erişimini kaybetmemeli! Rollback mekanizması sağlam olmalı.

---

## 📊 SUNUCU TARAFINDA VERİ MODELLERİ (Referans)

### Client Tablosu
```sql
CREATE TABLE clients (
    id INT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
    token VARCHAR(64) UNIQUE NOT NULL,
    server_name VARCHAR(255) NOT NULL,
    ip VARCHAR(45),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME,
    status ENUM('online','idle','offline','error') DEFAULT 'online',
    plan VARCHAR(20) DEFAULT 'standard',      -- 'standard' | 'premium'
    premium_expires_at DATETIME,
    notify_email VARCHAR(255),
    settings_json TEXT,                        -- JSON: dash_pass_hash, dash_auth_token, tunnels, tunnel_commands, open_ports, open_ports_updated_at
    first_name VARCHAR(100),
    last_name VARCHAR(100)
);
```

### Attack Tablosu
```sql
CREATE TABLE attacks (
    id INT PRIMARY KEY AUTO_INCREMENT,
    client_id INT UNSIGNED NOT NULL REFERENCES clients(id),
    service VARCHAR(50),            -- RDP, SSH, FTP, MYSQL, MSSQL, TELNET, SMB...
    ip VARCHAR(45),                 -- saldırgan IP (geri uyumluluk)
    attacker_ip VARCHAR(45),        -- saldırgan IP (tercih edilen)
    target_ip VARCHAR(45),          -- client IP
    port INT,
    username VARCHAR(255),
    password VARCHAR(255),          -- cleartext (veya hash prefix ile)
    country_code VARCHAR(2),        -- ISO 3166-1 alpha-2 (sunucu GeoIP ile doldurur)
    country_name VARCHAR(100),
    country VARCHAR(100),           -- backward compat
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### BlockRule Tablosu
```sql
CREATE TABLE block_rules (
    id INT PRIMARY KEY AUTO_INCREMENT,
    client_id INT UNSIGNED NOT NULL REFERENCES clients(id),
    ip_or_cidr VARCHAR(64) NOT NULL, -- "1.2.3.4", "1.2.3.0/24", "country:CN"
    reason VARCHAR(255),
    source VARCHAR(50) DEFAULT 'rule', -- 'manual' | 'rule'
    expires_at DATETIME,
    status VARCHAR(20) DEFAULT 'pending', -- pending | applied | remove_pending | removed | failed
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### TunnelStatus Tablosu
```sql
CREATE TABLE tunnel_status (
    id INT PRIMARY KEY AUTO_INCREMENT,
    client_id INT UNSIGNED NOT NULL REFERENCES clients(id),
    service VARCHAR(50) NOT NULL,    -- RDP, MSSQL, MYSQL, FTP, SSH
    listening_port INT,
    new_port INT,
    status VARCHAR(20) DEFAULT 'stopped', -- started | stopped | unknown | error
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY (client_id, service)
);
```

### NotificationRule Tablosu
```sql
CREATE TABLE notification_rules (
    id INT PRIMARY KEY AUTO_INCREMENT,
    client_id INT UNSIGNED NOT NULL REFERENCES clients(id),
    name VARCHAR(255) NOT NULL,
    services VARCHAR(255),           -- CSV: 'RDP,MSSQL,MYSQL'
    threshold_count INT DEFAULT 10,
    window_minutes INT DEFAULT 10,
    match_usernames TEXT,            -- newline-separated watchlist
    actions VARCHAR(255) DEFAULT 'email', -- 'email', 'block', 'email,block'
    enabled BOOLEAN DEFAULT TRUE,
    email_cooldown_min INT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME,
    last_triggered_at DATETIME
);
```

---

## 🔄 SERVİS YÖNETİMİ AKIŞI

### Dashboard'dan Kullanıcı Servis Başlatmak İstediğinde:

```
1. Kullanıcı dashboard'da "SSH → Başlat" butonuna tıklar
2. Dashboard POST /api/premium/tunnel-set {"token":"xxx","service":"SSH","action":"start"} → sunucu desired='started' yapar
3. Client her 2 dakikada GET /api/premium/tunnel-status poll eder
4. SSH.desired = 'started' ama SSH.status = 'stopped' → FARK VAR
5. Client FakeSSH honeypot'u port 22'de başlatır
6. Client POST /api/agent/tunnel-status ile {"service":"SSH","status":"started","listen_port":22} bildirir
7. Dashboard'da SSH durumu "started" olarak güncellenir
```

### Durdurma Akışı:
Aynı mantık, `desired='stopped'` olunca client servisi durdurur ve status bildirir.

---

## 📝 EK NOTLAR & EDGE CASE'LER

### Rate Limiting
- Aynı attacker_ip + service kombinasyonu için dakikada max 10 rapor gönder
- Fazlasını görmezden gel (bot'lar saniyede yüzlerce deneme yapabilir)

### Servis Port Çakışması
- Honeypot başlatılmadan önce ilgili portun gerçekten boş olduğu kontrol edilmeli
- Port kullanımdaysa hata logla ve status='error' bildir
- RDP için özel durum: Gerçek RDP servisini önce taşı, sonra honeypot başlat

### Otomatik Yeniden Başlatma
- Honeypot servisi çökerse otomatik restart (max 3 deneme, exponential backoff)
- Restart başarısızsa status='error' bildir

### Windows Firewall Kuralları
- Her honeypot servisi için inbound allow kuralı ekle (adı: `Honeypot-RDP`, `Honeypot-SSH` vb.)
- Servis durdurulunca kuralı kaldır
- Block kuralları ayrı bir naming convention ile: `HoneypotBlock-{ip}` veya `HoneypotBlock-{country}`

### Logging
- Her yakalanan credential logla (local dosya)
- Her API hatası logla
- Windows Event Log'a da yazılabilir (opsiyonel)

### Config Dosyası
```json
{
  "api_url": "https://honeypot.yesnext.com.tr",
  "token": "0ea8836b-...",
  "log_level": "INFO",
  "services": {
    "rdp": {"enabled": true, "port": 3389},
    "ssh": {"enabled": false, "port": 22},
    "ftp": {"enabled": false, "port": 21},
    "mysql": {"enabled": false, "port": 3306},
    "mssql": {"enabled": false, "port": 1433}
  },
  "real_rdp_port": 53389,
  "heartbeat_interval": 60,
  "block_poll_interval": 30,
  "service_poll_interval": 120,
  "port_report_interval": 300
}
```

---

## 🎯 ÇIKTI BEKLENTİSİ

1. Tüm mevcut client özelliklerini koru (RDP taşıma, blok yönetimi, heartbeat, port raporlama, servis yönetimi)
2. Tunnel/relay bağımlılığını tamamen kaldır
3. 5 adet lightweight honeypot servisi ekle (RDP, SSH, FTP, MySQL, MSSQL)
4. Her servis credential yakalasın ve `POST /api/attack` ile raporlasın
5. asyncio tabanlı olsun (tek event loop, tüm servisler paralel)
6. PyInstaller ile tek exe'ye derlenebilir olsun
7. Windows Service olarak çalışabilsin (opsiyonel: system tray icon ile)
8. Kaynak tüketimi düşük olsun (idle durumda <50MB RAM, <1% CPU)

**Mevcut client kodunu analiz et, tunnel/relay kısımlarını kaldır, honeypot modüllerini ekle, gerisini koru.**
