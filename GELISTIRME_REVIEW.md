# Cloud Honeypot Client — Güvenlik & Geliştirme İncelemesi

**Tarih:** 8 Temmuz 2026  
**İncelenen sürüm:** v4.4.0 (güncellendi)  
**Durum:** Aşağıdaki önerilerin çoğu v4.4.0 ile uygulandı — bkz. `release_notes_v4.4.0.md`

---

## Özet

YesNext Cloud Honeypot Client, Windows üzerinde çalışan, bulut yönetimli bir **çok protokollü honeypot + endpoint güvenlik ajanı**. RDP, SSH, FTP, MySQL ve MSSQL decoy servisleriyle saldırgan kimlik bilgilerini yakalar; v4 ile birlikte Event Log izleme, tehdit motoru, otomatik savunma, ransomware kalkanı ve uzaktan müdahale yetenekleri eklenmiş.

Genel mimari sağlam ve modüler. Ancak **TLS doğrulamasının kapalı olması**, **token'ların URL ve loglarda açık taşınması** ve **geniş uzaktan komut yüzeyi** acil ele alınması gereken konular. Ayrıca otomatik test, CI/CD ve backend kodu repoda bulunmuyor.

---

## Güçlü Yönler

| Alan | Değerlendirme |
|------|---------------|
| Modüler mimari | `client_honeypots`, `client_threat_engine`, `client_auto_response` vb. iyi ayrılmış |
| Honeypot tasarımı | Decoy servisler asla authenticate etmez; credential capture + bağlantı kesme |
| Protokol kapsamı | 5 servis (RDP, SSH, FTP, MySQL, MSSQL) native Python ile, harici bağımlılık az |
| RDP stratejisi | Gerçek RDP 53389'a taşınır, 3389 decoy olur — kullanıcı deneyimi korunur |
| Token depolama | Windows DPAPI + SHA-256 bütünlük başlığı (`CHP1\|`) |
| Savunma katmanları | Rate limiting, komut whitelist, korumalı hesap/süreç/servis listeleri |
| v4 yetenekleri | Event log, korelasyon, ransomware canary, silent hours, self-protection |
| Operasyonel | Watchdog, Task Scheduler, healthcheck, tray GUI, i18n (TR/EN) |
| Dokümantasyon | API spec, roadmap, release notes mevcut |

---

## Kritik Bulgular (Acil)

### 1. TLS sertifika doğrulaması kapalı

**Dosya:** `client_api.py`  
**Sorun:** Tüm HTTPS isteklerinde `verify=False`; urllib3 uyarıları bastırılıyor.

```python
response = self.session.request(..., verify=False)
```

**Risk:** MITM saldırısıyla API trafiği (token, yakalanan şifreler, uzaktan komutlar) okunabilir veya değiştirilebilir.

**Öneri:**
- `verify=True` yap; Let's Encrypt veya kurumsal CA sertifikasını bundle'a ekle
- İsteğe bağlı certificate pinning (`requests` + `SSLContext`)
- Geliştirme ortamı için `client_config.json` → `"api.tls_verify": false` (prod'da varsayılan `true`)

---

### 2. API token'ı URL query string'de taşınıyor

**Dosyalar:** `client_api.py`, `client_remote_commands.py`, `client_gui.py` (dashboard linki)

**Sorun:** Birçok GET endpoint'i `?token=...` kullanıyor. Dashboard URL'si de token içeriyor.

**Risk:**
- Sunucu/proxy access loglarında token sızıntısı
- Tarayıcı geçmişi, Referer header
- Log aggregation sistemlerinde kalıcı kayıt

**Öneri:**
- `Authorization: Bearer <token>` header'ına geç
- Dashboard için kısa ömürlü session token veya tek kullanımlık link
- Backend tarafında query string token desteğini kademeli kaldır

---

### 3. Token'lar log dosyasına düz metin yazılıyor

**Dosya:** `client_api.py` satır 81-82

```python
if params and show_logs:
    self.log(f"[API] Params: {params}")  # token dahil tam params
```

**Kanıt:** `client.log` içinde `Params: {'token': '0ea8836b-...'}` kayıtları mevcut.

**Risk:** Yerel log okuyan herhangi bir süreç veya kullanıcı tam API token'ına erişir → uzaktan komut çalıştırma, lockdown, şifre sıfırlama.

**Öneri:**
- Loglama öncesi `_redact_sensitive(params)` fonksiyonu
- `token`, `password`, `secret` alanlarını `***` ile maskele
- Mevcut `client.log` dosyasını sil/rotate et; token'ı backend'den revoke et

---

### 4. Uzaktan komut yüzeyi geniş — tek nokta arıza: token

**Dosya:** `client_remote_commands.py`

Desteklenen komutlar:
`block_ip`, `unblock_ip`, `logoff_user`, `disable_account`, `enable_account`, **`reset_password`**, `kill_process`, `stop_service`, `disable_service`, **`emergency_lockdown`**, `lift_lockdown`, `list_sessions`, `list_processes`, `snapshot`, `collect_diagnostics`

**Risk:** Token ele geçirilirse endpoint tam kontrol altına girer. `REQUIRES_CONFIRMATION` seti var ama doğrulama **sunucu tarafında** yapılmalı (bu repoda görülemiyor).

**Öneri (istemci + sunucu):**
- Komut imzalama (HMAC + timestamp + nonce)
- Kritik komutlar için 2FA / onay akışı
- Token rotation ve revocation API'si
- Komut audit log'u (kim, ne zaman, hangi IP'den)

---

## Orta Öncelikli Bulgular

### 5. Honeypot'lar `0.0.0.0` üzerinde dinliyor

**Dosya:** `client_honeypots.py`

Tüm ağ arayüzlerinde expose. LAN içi tarama veya yanlış firewall konfigürasyonunda istenmeyen erişim.

**Öneri:** `client_config.json` → `"bind_address": "0.0.0.0"` (varsayılan) veya `"127.0.0.1"` / belirli NIC IP'si. NAT arkasındaki makinelerde genelde sorun olmaz ama seçenek sunulmalı.

---

### 6. DPAPI `CRYPTPROTECT_LOCAL_MACHINE` flag'i

**Dosya:** `client_utils.py` → `TokenStore`

Aynı makinedeki **herhangi bir kullanıcı/süreç** (yeterli yetkiyle) token'ı decrypt edebilir. Service account senaryosu için mantıklı ama tehdit modeli dokümante edilmeli.

**Öneri:** `SECURITY.md` ile tehdit modeli yaz; alternatif olarak kullanıcı-scoped DPAPI + scheduled task service account ayrımı değerlendir.

---

### 7. RDP honeypot sınırlı credential yakalama

**Dosya:** `client_honeypots.py` → `RDPHoneypot`

Modern NLA/CredSSP client'ları çoğunlukla sadece **username** (mstshash cookie) verir; şifre yakalanmaz. Bu tasarım bilinçli ve kodda iyi dokümante edilmiş.

**Öneri:** Kullanıcıya GUI'de ve kurulum sihirbazında açıkça bildir. Dashboard'da RDP saldırılarında "username only" etiketi göster.

---

### 8. MySQL honeypot hash yakalar, plaintext değil

MySQL native auth protokolünde password hash olarak gelir. Brute-force için yeterli olabilir ama dashboard'da "hash" vs "plaintext" ayrımı yapılmalı.

---

### 9. Otomatik güncelleme — supply chain riski

**Dosya:** `client_updater.py`  
GitHub Releases (`cevdetaksac/yesnext-cloud-honeypot-client`) üzerinden NSIS installer indirilir.

**Öneri:**
- Release artifact imza doğrulaması (Authenticode zaten NSIS'te olabilir — doğrula)
- GitHub release checksum (SHA-256) kontrolü
- Update kanalı için ayrı imzalı manifest

---

### 10. Self-protection ve persistence

Task Scheduler, watchdog, DACL hardening — güvenlik ürünü için gerekli ama **antivirus/EDR false positive** ve **kaldırma zorluğu** yaratabilir.

**Öneri:**
- Temiz kaldırma (uninstaller) akışını test et ve dokümante et
- Windows Defender uyumluluk submission (kodda `DEFENDER_MARKERS` var — resmi başvuru yapılmalı)
- Kurulumda kullanıcı onayı ve şeffaf açıklama

---

### 11. `client.log` workspace'te mevcut

`.gitignore`'da var ama dosya diskte duruyor ve token içeriyor. Git'e commit edilmemiş olmalı — yine de silinmeli.

---

## Düşük Öncelik / Bilgilendirme

| Konu | Not |
|------|-----|
| SSH host key | RSA 2048, instance başına ephemeral — decoy için yeterli |
| Rate limiting | 10 credential report/IP/servis/dk — iyi başlangıç |
| Local control socket | `127.0.0.1:58632`, sadece `SHOW\n` — dar yüzey |
| Hardcoded secret | Kaynak kodda API key/şifre yok ✓ |
| `SECURITY.md` | README'de referans var, dosya yok |
| `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md` | README'de referans var, dosya yok |

---

## Eksik Özellikler & Fonksiyonel Boşluklar

### Honeypot protokolleri

| Protokol | Durum | Not |
|----------|-------|-----|
| RDP | ✅ | Username odaklı |
| SSH | ✅ | Plaintext password |
| FTP | ✅ | USER/PASS |
| MySQL | ✅ | Hash |
| MSSQL | ✅ | XOR-decoded password |
| HTTP/HTTPS | ❌ | Port listesinde isim var, decoy yok |
| SMB | ❌ | Sık hedeflenen protokol |
| Telnet | ❌ | |
| SMTP | ❌ | |
| Redis/MongoDB | ❌ | Cloud workload hedefleri |

### Test & kalite

| Alan | Durum |
|------|-------|
| Unit test | ❌ Yok (`pytest`/`unittest` bulunamadı) |
| Integration test | ❌ |
| CI/CD pipeline | ❌ Repoda yok |
| Protocol fuzzing | ❌ |
| Linting/formatting | Belirsiz |

**Önerilen test hedefleri:**
- Honeypot protocol parser'ları (FTP USER/PASS, MySQL handshake, MSSQL Login7)
- Rate limiter edge case'leri
- `ALLOWED_COMMANDS` validation
- Token redaction helper
- API client mock testleri

### Backend (repo dışı — ayrı inceleme gerekli)

Bu workspace'te sadece istemci var. Tam sistem güvenliği için `honeypot.yesnext.com.tr` backend'inde şunlar incelenmeli:

- Token yaşam döngüsü (revoke, rotate, expire)
- Komut yetkilendirme ve onay akışı
- Multi-tenant izolasyon
- SQL injection / IDOR dashboard endpoint'lerinde
- Rate limiting ve DDoS koruması
- Yakalanan credential'ların şifrelenmiş depolanması (at-rest encryption)
- GDPR/KVKK — kişisel veri (IP, username) saklama politikası

### Operasyonel eksikler

- Merkezi log aggregation (ELK, Loki vb.) entegrasyonu yok
- Metrik export (Prometheus) yok
- Alerting webhook (Slack, Teams, PagerDuty) istemci tarafında sınırlı
- Linux istemci desteği kısmi (`client_firewall.py` Linux ipset destekliyor ama honeypot'lar Windows odaklı)

---

## Mimari Diyagram

```
                    ┌─────────────────────────────┐
                    │  Dashboard / API Server      │
                    │  honeypot.yesnext.com.tr   │
                    └──────────┬──────────────────┘
                               │ HTTPS (verify=False ⚠️)
          ┌────────────────────┼────────────────────┐
          │                    │                    │
    POST /attack         GET /commands/pending   POST /alerts/urgent
    POST /heartbeat      GET /pending-blocks      POST /events/batch
          │                    │                    │
┌─────────┴────────────────────┴────────────────────┴─────────┐
│                  Windows Host (Client v4.3)                  │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │ Honeypots   │  │ Threat Engine│  │ Remote Commands   │  │
│  │ RDP SSH FTP │  │ Event Log    │  │ Auto-Response     │  │
│  │ MySQL MSSQL │  │ Ransomware   │  │ Firewall Agent    │  │
│  └──────┬──────┘  └──────┬───────┘  └─────────┬─────────┘  │
│         │                │                     │             │
│         └────────────────┴─────────────────────┘             │
│                          │                                   │
│                   token.dat (DPAPI)                          │
└──────────────────────────────────────────────────────────────┘
          ▲
          │ Scan / brute-force
     [Attacker]
```

---

## Öncelikli Geliştirme Yol Haritası

### Faz 1 — Güvenlik sıkılaştırma (1-2 hafta)

- [ ] TLS `verify=True` + sertifika bundle
- [ ] Token'ı header'a taşı (backend koordinasyonu)
- [ ] Log redaction (token, password, secret alanları)
- [ ] Mevcut `client.log` temizliği + token revoke
- [ ] `SECURITY.md` oluştur (tehdit modeli, sorumlu bildirim)

### Faz 2 — Kalite & güvenilirlik (2-4 hafta)

- [ ] Honeypot parser unit testleri
- [ ] GitHub Actions CI (lint + test + build)
- [ ] `client.log` ve `token.dat` için `.gitignore` doğrulama + pre-commit hook
- [ ] Release artifact SHA-256 checksum doğrulaması

### Faz 3 — Özellik genişletme (1-2 ay)

- [ ] HTTP honeypot (basit login form decoy)
- [ ] SMB honeypot veya en azından SMB port dinleme + banner
- [ ] `bind_address` konfigürasyonu
- [ ] Dashboard webhook entegrasyonu (Slack/Teams)
- [ ] Komut imzalama protokolü (client ↔ server)

### Faz 4 — Operasyon & ölçek (sürekli)

- [ ] Backend güvenlik audit (ayrı repo)
- [ ] Windows Defender / AV whitelist başvurusu
- [ ] Merkezi SIEM entegrasyonu
- [ ] Linux honeypot agent (SSH/FTP decoy)

---

## Kod Referansları (İncelenen Kritik Noktalar)

| Konu | Dosya | Satır (yaklaşık) |
|------|-------|------------------|
| TLS kapalı | `client_api.py` | 93, 221 |
| Token loglama | `client_api.py` | 81-82 |
| Token query param | `client_api.py` | 253, 352, 381, 414, 443, 505, 542 |
| Komut whitelist | `client_remote_commands.py` | 51-58 |
| DPAPI storage | `client_utils.py` | 150-225 |
| Honeypot bind | `client_honeypots.py` | 90, 159 |
| RDP sınırlaması | `client_honeypots.py` | 847-873 |
| Sürüm | `client_constants.py` | 39 |

---

## Sonuç

Proje, honeypot + endpoint detection birleşimi olarak **ciddi ve iyi düşünülmüş** bir ürün. v4 modülleri (threat engine, ransomware shield, auto-response) rekabetçi bir EDR-lite seviyesine yaklaşıyor.

En acil üç konu:
1. **TLS doğrulamasını aç**
2. **Token'ları log ve URL'den çıkar**
3. **Uzaktan komut yetkilendirmesini sunucu tarafında sıkılaştır**

Bu üçü çözüldükten sonra test altyapısı ve ek honeypot protokolleri ürünü production-grade seviyeye taşır.

---

*Bu belge otomatik kod incelemesi + manuel analiz ile oluşturulmuştur. Backend (`honeypot.yesnext.com.tr`) ayrı bir inceleme gerektirir.*
