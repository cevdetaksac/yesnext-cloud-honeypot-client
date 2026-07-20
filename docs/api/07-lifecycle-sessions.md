# Lifecycle, Sessions & Processes

> Cloud / Dashboard API sözleşmeleri — agent prompt’larından birleştirildi.
> API: `https://honeypot.yesnext.com.tr`

---

## Kaynak: `AGENT_LIFECYCLE_ALERTS_API_PROMPT.md`

# AGENT_LIFECYCLE_ALERTS_API_PROMPT.md

## Amac

Client (v4.4.51+) cokme / watchdog / memory-restart olaylarini hem lokal loglar
hem de API'ye ozet olarak iletir. Dashboard'da sunucu "neden kapandi?" gorunsun.

Client ham log dump etmez — sadece olay ozetleri (rate-limited, best-effort).

---

## Endpoint

### POST /api/alerts/lifecycle

Auth: agent token (body `token` ve/veya Bearer).

Body ornegi:

```json
{
  "token": "CLIENT_TOKEN",
  "ts": "2026-07-18T21:10:00Z",
  "event_type": "watchdog_restart",
  "reason": "client_not_running",
  "severity": "warning",
  "hostname": "SRV-01",
  "version": "4.4.51",
  "pid": 1234,
  "details": {
    "action": "start_daemon"
  }
}
```

Response 200:

```json
{ "status": "ok" }
```

404/501: client soft-fail eder, olay lokal kuyrukta kalir (sonraki flush).

---

## event_type katalogu (client)

| event_type | severity | Anlam |
|------------|----------|--------|
| `client_startup` | info | Client process acildi |
| `watchdog_restart` | warning | Watchdog process yok buldu, daemon baslatiliyor |
| `watchdog_restart_ok` | info | Restart sonrasi process ayakta |
| `watchdog_restart_failed` | error | Restart denendi ama process ayakta degil |
| `watchdog_error` | error | Watchdog kod hatasi |
| `memory_restart_begin` | info | 8s MemoryRestart basladi |
| `memory_restart_path` | info | Exe yolu cozuldu |
| `memory_restart_kill` | info | Process kill |
| `memory_restart_ok` | info | Restart basarili |
| `memory_restart_fallback` | warning | Direkt start fail, Background task ile denendi |
| `memory_restart_failed` | error | Restart basarisiz (exe yok / stick olmadi) |
| `memory_restart_skipped` | warning | Update lock nedeniyle atlandi |

---

## Dashboard UX (onerı)

- Sunucu detayinda **Client Lifecycle** timeline (son 50 olay)
- `severity=error` -> toast / email (opsiyonel, account prefs)
- Filtre: `watchdog_*`, `memory_restart_*`

---

## Saklama

- Tablo ornegi: `client_lifecycle_events` (server_id, ts, event_type, reason, severity, version, details JSON)
- TTL: 30-90 gun yeter

---

## Acceptance

- [ ] Watchdog client'i oldurunce ~2 dk icinde `watchdog_restart` kaydi olusur
- [ ] MemoryRestart yanlis path'te `memory_restart_failed` + reason `exe_not_found`
- [ ] Endpoint yokken client crash etmez (soft-fail + queue)
- [ ] Dashboard timeline'da olaylar hostname + version ile listelenir

## Client lokal log

`%ProgramData%\YesNext\CloudHoneypotClient\lifecycle.log`
`%ProgramData%\YesNext\CloudHoneypotClient\lifecycle_queue.jsonl`

---

## Kaynak: `AGENT_SESSIONS_PROCESSES_PROMPT.md`

# Agent Prompt: Aktif Oturumlar + Tam Süreç Listesi

> **Kime:** Windows tray / honeypot client uygulamasını geliştiren yapay zeka  
> **API:** `https://honeypot.yesnext.com.tr`  
> **Auth:** Tüm isteklerde `token` (UUID)  
> **Tarih:** 2026-07-18  
> **Bağlam:** Dashboard artık “Aktif Bağlı Kullanıcılar” ve “Çalışan Süreçler” tablolarını gösteriyor. Veri kaynağı `POST /api/health/report`. Şu an üretimde `active_sessions` çoğu zaman `null`; süreçler kısmi (`cpu`/`memory_mb`) geliyor. Bu prompt client tarafını tamamlamak içindir.

---

## 1) Senin görevin

1. Health report payload’ına **tam `active_sessions`** ve **zengin süreç listesi** ekle / düzelt.
2. Gönderim sıklığını ve alan isimlerini aşağıdaki kanonik şemaya uyarla.
3. Uzaktan komutları uygula: `list_sessions`, `list_processes`, `logoff_user`, `kill_process`, `block_process`.
4. Bitince kısa “ne değişti + acceptance checklist” yaz.

**Önemli:** Sunucu alan adlarını toleranslı normalize ediyor (`cpu` ↔ `cpu_percent`, `user` ↔ `username` vb.). Yine de **kanonik** alanları kullan.

---

## 2) Nereye yazılacak?

`POST /api/health/report`

Body **mutlaka** `snapshot` içinde olmalı (mevcut client zaten böyle gönderiyor):

```json
{
  "token": "<CLIENT_TOKEN>",
  "snapshot": {
    "timestamp": "2026-07-18T12:00:00Z",
    "cpu_percent": 12.5,
    "memory_percent": 48.2,
    "memory_used_gb": 7.1,
    "memory_total_gb": 16.0,
    "disk_usage_percent": 61.0,
    "disk_free_gb": 120.0,
    "disk_total_gb": 476.0,
    "process_count": 186,
    "connection_count": 42,
    "top_cpu_processes": [ /* süreçler — mevcut alan adı da OK */ ],
    "top_processes": [ /* süreçler — tercih edilen */ ],
    "active_sessions": [ /* oturumlar — YENİ / ZORUNLU */ ]
  }
}
```

Alternatif anahtarlar (sunucu kabul eder):

| Tercih edilen | Alias |
|---------------|--------|
| `top_processes` | `processes`, `all_processes`, `top_cpu_processes` |
| `active_sessions` | `sessions` |
| `open_connections` | `connection_count` |

**Sıklık önerisi**

| Veri | Interval |
|------|----------|
| CPU/RAM/Disk özeti | 30–60 sn |
| `top_processes` (tam liste veya top 100–150) | 30–60 sn |
| `active_sessions` | 15–30 sn (oturum değişince hemen) |
| Şüpheli süreç / yeni oturum | olay anında ekstra report |

Health report’u atlamak yok; dashboard bu tabloları buradan okuyor (`system_health.top_processes` / `active_sessions`).

---

## 3) `active_sessions[]` — kanonik şema

Her eleman bir **aktif logon / RDP / konsol oturumu**:

```json
{
  "username": "Administrator",
  "session_id": 2,
  "session_name": "RDP-Tcp#3",
  "status": "Active",
  "client_ip": "185.22.11.9",
  "protocol": "RDP",
  "logon_type": 10,
  "login_time": "2026-07-18T11:42:03Z",
  "duration_sec": 3840,
  "idle_sec": 120,
  "client_name": "ATTACKER-PC"
}
```

### Alan kuralları

| Alan | Zorunlu | Not |
|------|---------|-----|
| `username` | Evet | Domain\user ise `DOMAIN\\user` veya sadece SAM |
| `session_id` | Evet (mümkünse) | `query user` / WTS session id |
| `status` | Evet | `Active`, `Disconnected`, `Idle`… |
| `client_ip` | Evet (remote ise) | Dashboard “önceki şifre denemesi” için IP şart |
| `protocol` | Tercihen | `RDP`, `Console`, `SSH`, `SMB`… |
| `login_time` | Evet | ISO-8601 UTC (`...Z`) |
| `duration_sec` | Tercihen | Yoksa sunucu `login_time`’dan hesaplar |
| `idle_sec` | Opsiyonel | |
| `client_name` | Opsiyonel | RDP client hostname |

### Nasıl toplanır (Windows)

- `WTSEnumerateSessions` + `WTSQuerySessionInformation` (ClientAddress, UserName, ConnectTime)
- veya `query user` / `qwinsta` parse (daha kırılgan)
- Console session: `client_ip` boş veya `127.0.0.1` olabilir; `protocol: "Console"`

### Dashboard ne yapıyor?

Sunucu aynı IP için honeypot `attacks` kayıtlarından **login öncesi deneme sayısını** (`prior_attempts`) hesaplar ve risk rozeti basar. Bu yüzden **`client_ip` + `login_time` kritik**.

---

## 4) `top_processes[]` — kanonik şema (Görev Yöneticisi benzeri)

Mümkünse **tüm kullanıcı süreçleri** (limit ~120–150; Idle’ı dahil edebilirsin, sunucu Idle’ı alta iter).

```json
{
  "pid": 4820,
  "name": "powershell.exe",
  "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "username": "WIN-HOST\\Administrator",
  "cpu_percent": 18.4,
  "memory_mb": 212.5,
  "memory_percent": 1.3,
  "status": "running",
  "started_at": "2026-07-18T10:01:12Z",
  "runtime_sec": 9240,
  "cmdline": "powershell.exe -NoProfile -EncodedCommand ...",
  "company": "Microsoft Corporation",
  "signed": true,
  "suspicious": false,
  "suspicion_reasons": []
}
```

### Alan kuralları

| Alan | Zorunlu | Not |
|------|---------|-----|
| `pid` | Evet | |
| `name` | Evet | image name |
| `path` | Çok önemli | Temp/AppData path şüphe skoru için |
| `cpu_percent` | Evet | Alias: `cpu` (şu an client bunu gönderiyor — OK ama `cpu_percent` tercih) |
| `memory_mb` | Evet | Working set MB; alias yoksa sunucu sadece bunu kullanır |
| `memory_percent` | Tercihen | |
| `username` | Tercihen | |
| `started_at` / `runtime_sec` | Tercihen | Dashboard “ne zamandır çalışıyor” |
| `cmdline` | Tercihen | Şüphe analizi |
| `signed` | Tercihen | `false` → sunucu `unsigned` bayrağı |
| `suspicious` | Opsiyonel | Client kendi heuristiğini işaretleyebilir |
| `suspicion_reasons` | Opsiyonel | `["temp_path","unsigned","lolbin"]` |

### Client tarafı şüphe heuristiği (öneri)

Aşağıdakilerden biri varsa `suspicious: true` ve reason ekle:

- Path altında: `\Temp\`, `\AppData\Local\Temp\`, `\Downloads\`, `\Public\`
- İsim: `mimikatz`, `procdump`, `psexec`, `nc.exe`, `ncat`, `cobalt`, `beacon`, `ransom`…
- LOLBIN + şüpheli argüman: `powershell -enc`, `wscript`, `mshta`, `rundll32 http`, `certutil -urlcache`
- İmzasız + yüksek CPU veya yeni spawn
- Parent process anormal (ör. Office → cmd → powershell)

Sunucu da ek bayrak üretir (`name_match`, `temp_path`, `high_cpu`, `unsigned`, `agent_flag`).

### Nasıl toplanır

- `CreateToolhelp32Snapshot` / `EnumProcesses` + `GetProcessMemoryInfo` + CPU times
- Path: `QueryFullProcessImageName` / `GetModuleFileNameEx`
- Start time: `GetProcessTimes` → `runtime_sec`
- Owner: `OpenProcessToken` + `LookupAccountSid`
- Signature: WinVerifyTrust (maliyeti yüksekse sadece top-N veya şüpheli adaylarda)

**Performans:** Tam liste pahalıysa:
1. Her turda top 80 CPU + top 40 memory birleştir (unique PID)
2. + tüm `suspicious` adaylar
3. Toplam ≤ 150

---

## 5) Uzaktan komutlar (dashboard butonları)

`GET /api/commands/pending?token=...` → komut al  
`POST /api/commands/result` → sonuç bildir

| `command_type` | Params | Beklenen davranış |
|----------------|--------|-------------------|
| `list_sessions` | `{}` | Hemen health report ile güncel `active_sessions` gönder |
| `list_processes` | `{}` | Hemen health report ile güncel `top_processes` gönder |
| `logoff_user` | `{username, session_id}` | WTSLogoffSession / `logoff` |
| `kill_process` | `{pid, process_name}` | TerminateProcess; kritik sistem PID’lerine dokunma |
| `block_process` | `{path}` veya `{name_pattern}` | Kalıcı engel (hash/path rule) — dikkatli uygula |
| `collect_diagnostics` | `{}` | Zengin health + opsiyonel ekstra diag |

Komut sonucu örneği:

```json
{
  "token": "...",
  "command_id": 123,
  "success": true,
  "message": "logged off session 2",
  "data": {}
}
```

---

## 6) Acceptance checklist

- [ ] `POST /api/health/report` içinde `active_sessions` boş dizi değil (en az console session)
- [ ] Remote RDP oturumunda `client_ip` + `login_time` dolu
- [ ] Dashboard “Aktif Bağlı Kullanıcılar” tablosu kullanıcı / IP / süre / risk gösteriyor
- [ ] Aynı IP’den honeypot brute force varsa `prior_attempts` > 0 görünüyor (sunucu hesaplar)
- [ ] `top_processes` ≥ 20 satır; `memory_mb` veya `memory_percent` dolu
- [ ] `path` çoğu satırda dolu; şüpheli process sarı/kırmızı rozet alıyor
- [ ] Dashboard “Yenile” → `list_sessions` / `list_processes` komutu agent’ta işleniyor
- [ ] `logoff_user` / `kill_process` çalışıyor ve `commands/result` success dönüyor
- [ ] Health report 422 üretmiyor; access log’da 200

### Hızlı test (agent makinesinde)

1. RDP ile bağlan → 30 sn bekle → dashboard’da oturum satırı
2. Temp’ten test exe çalıştır → süreç tablosunda şüphe rozeti
3. Dashboard’dan oturum “logoff” → RDP düşmeli
4. Dashboard’dan process kill → PID kaybolmalı

---

## 7) Bilinen mevcut client durumu

Üretim örneği (`client_id=36`):

- `top_processes`: `{pid, name, cpu, memory_mb}` geliyor → **eksik:** `path`, `username`, `started_at`/`runtime_sec`, `signed`, `suspicious`
- `active_sessions`: **null** → **acil eklenmeli**

Bu iki eksik kapanınca dashboard tabloları dolacak; ekstra API değişikliği gerekmez.

---

## 8) Teslim özeti formatı

```
## Değişiklikler
- ...

## Acceptance
- [x] / [ ] ...

## Kalan riskler
- ...
```

---

## Kaynak: `AGENT_PROCESSES_FULL_LIST_PROMPT.md`

# Agent Prompt (kısa): Süreç listesi eksik — Notepad++ görünmüyor

> **Kime:** Windows honeypot-client  
> **Kanıt:** `process_count=159` ama `top_processes` yalnızca **10** satır (top-CPU). Dashboard’da Notepad++ yok.  
> **Detay:** `AGENT_SESSIONS_PROCESSES_PROMPT.md`

## Tek satırlık fix

`POST /api/health/report` → `snapshot.top_processes` (veya `top_cpu_processes`) artık **en az 80–150 unique PID** olmalı.

Her turda birleştir:
1. Top 80 CPU  
2. Top 40 memory  
3. **Interactive session süreçleri** (CPU %0 olsa bile: `notepad++.exe`, browser, explorer…)  
4. Şüpheli adaylar  

`list_processes` komutu → hemen bu geniş listeyi gönder.

Acceptance: Notepad++ aç → ≤ 60 sn dashboard “Çalışan Süreçler”de görünür.

---

## Kaynak: `AGENT_SELF_PROCESS_PROMPT.md`

# Agent Prompt: Self-Process Kimliği (Şüphe Yok + Kill Koruması + Anti-Spoof)

> **Kime:** Windows honeypot-client geliştiren AI  
> **API:** `https://honeypot.yesnext.com.tr`  
> **Tarih:** 2026-07-18  
> **Sorun:** Dashboard “Çalışan Süreçler”de `honeypot-client.exe` şüpheli görünebiliyor / kill butonu var. Sadece **isme** göre ayrıcalık vermek güvenli değil — saldırgan aynı exe adını taklit edebilir.

---

## 0) Cloud’un beklediği çözüm (özet)

| Durum | Dashboard |
|-------|-----------|
| Doğrulanmış gerçek agent | Şüphe **yok**, rozet **Agent**, kill butonu **gizli**, API `kill_process` **403** |
| `honeypot-client.exe` ama proof yok (strict mod) | **Taklit?** kritik uyarı, kill **açık** |
| Legacy (henüz proof yok, trusted path) | Soft-protect (geçici) |

Kimlik = **HMAC-SHA256 self-proof** (client token gizli anahtar). İsim tek başına yetmez.

---

## 1) Proof formülü (zorunlu)

```
message = "v1|{pid}|{exe_path_normalized}"
proof   = HMAC_SHA256_HEX(key = client_token, message)
```

`exe_path_normalized`:

- trim
- lower-case
- `/` → `\`
- Örnek: `c:\program files\yesnext\honeypot-client.exe`

Örnek (Python referans — cloud `helpers.make_agent_self_proof` ile aynı):

```python
import hmac, hashlib
def make_proof(token: str, pid: int, exe_path: str) -> str:
    norm = (exe_path or "").strip().lower().replace("/", "\\")
    msg = f"v1|{int(pid)}|{norm}"
    return hmac.new(token.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()
```

C# / .NET: `HMACSHA256` + UTF-8, hex lower-case.

---

## 2) `POST /api/health/report` — her health’te gönder

`snapshot` içine ekle:

```json
{
  "cpu_percent": 12.3,
  "process_count": 180,
  "top_processes": [ /* ... */ ],
  "agent_runtime": {
    "pid": 9312,
    "exe_path": "C:\\Program Files\\YesNext\\honeypot-client.exe",
    "proof": "<hmac hex>"
  }
}
```

Alias kabul: `self_process` (aynı alanlar).

Cloud proof doğrular → `settings_json.agent_runtime` kaydeder → sonraki listelerde de aynı PID korunur.

---

## 3) Kendi satırın `top_processes[]` içinde

Kendi PID satırında (önerilir):

```json
{
  "pid": 9312,
  "name": "honeypot-client.exe",
  "path": "C:\\Program Files\\YesNext\\honeypot-client.exe",
  "cpu_percent": 0.4,
  "memory_mb": 85,
  "is_agent_self": true,
  "self_proof": "<aynı hmac>",
  "suspicious": false
}
```

- `suspicious: false` — kendi heuristiğin agent’ı işaretlemesin  
- `signed` / path temp değilse ek flag üretme  
- **Başka** `honeypot-client.exe` kopyası görürsen `is_agent_self` koyma; istersen `suspicious: true` + reason `name_spoof_candidate`

---

## 4) `kill_process` self-protect (agent tarafı)

Sadece **kendi PID** (ve isteğe bağlı kendi image path) için reddet:

```text
Refusing to terminate self (PID {pid} = honeypot-client.exe)
```

- İsim eşleşmesiyle blanket protect **yapma** (sahte exe’yi öldüremezsin)  
- Cloud zaten doğrulanmış PID’ye `kill_process` için 403 döner; agent yine kendi PID’yi reddetsin

---

## 5) Güvenlik notları

- Token diskte zaten var; proof ekstra secret gerektirmez  
- Proof’u loglara **yazma**  
- PID değişince (restart) yeni proof + yeni `agent_runtime` gönder  
- Spoofer token bilmeden geçerli proof üretemez → isim taklidi dashboard’da **Taklit?** olur

---

## 6) Acceptance checklist

- [ ] Her `health/report` içinde `agent_runtime.pid` + `exe_path` + `proof`  
- [ ] Proof formülü cloud ile birebir (v1 \| pid \| norm path)  
- [ ] Kendi process satırında `is_agent_self` + `self_proof` + `suspicious: false`  
- [ ] Dashboard’da gerçek agent: yeşil **Agent** rozeti, kill yok, şüphe yok  
- [ ] Temp’ten kopyalanmış sahte `honeypot-client.exe`: **Taklit?** / kill açık  
- [ ] `kill_process` kendi PID → agent `failed` self-refuse; cloud 403 (doğrulanmışsa)  
- [ ] Restart sonrası yeni PID ≤ 1 health cycle içinde korunuyor

---

## 7) Test (hızlı)

1. Agent’ı çalıştır → health gönder.  
2. Dashboard süreç listesi → kendi satır: Agent / 🔒.  
3. `C:\Temp\honeypot-client.exe` kopyala çalıştır (proof yok) → Taklit?  
4. Dashboard’dan kendi PID’ye kill dene → buton yok / API 403.  
5. Sahte PID’ye kill → komut gider (agent TerminateProcess dener).

