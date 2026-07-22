# Client talimatı — Alert sinyal hijyeni (gürültü / false positive)

> Cloud tarafı (2026-07-23) zayıf sinyalleri düşürüyor / kritik şeritten siliyor.  
> Asıl kalıcı çözüm client’ta: **yanlış severity göndermemek**.  
> Hedef client: **≥ 4.9.9** (öneri). Contract ref: presence `1.4.12` + bu not.

Cloud soft-net (geçici güvenlik ağı):
- `vssadmin list shadows` → info
- küçük VSS delta → warning
- `agent_*_degraded` / trusted → “Son Kritik” listesinde yok
- canary / offline_suspect dedupe uzatıldı
- `ransomware_offline_suspect` artık warning→high zorlanmıyor

---

## 1) VSS / ransomware_process (zorunlu)

**Sorun:** Agent VSS sayımı için `vssadmin list shadows` çalıştırıyor; bunu `ransomware_process` + “Shadow copy manipulation” olarak critical/high gönderiyor.

| Yap | Yapma |
|-----|--------|
| Inventory: `vssadmin list shadows` → **urgent gönderme** veya `severity=info`, `threat_score≤15`, type `vss_inventory` | `list shadows` → `ransomware_process` high/critical |
| Sadece **`vssadmin delete shadows`**, `wmic shadowcopy delete`, `wbadmin delete` → critical ransomware | `list` ile `delete` aynı kova |

Öneri wire:

```json
{
  "threat_type": "ransomware_process",
  "severity": "critical",
  "threat_score": 90,
  "description": "… vssadmin delete shadows /all …"
}
```

List için ya hiç alert yok, ya:

```json
{ "threat_type": "vss_inventory", "severity": "info", "threat_score": 5 }
```

---

## 2) shadow_copy_deleted

**Sorun:** 1–2 shadow azalınca + kalan hâlâ ≥3 iken `critical` / score 100.

| Kural | Severity |
|-------|----------|
| Silinen ≥3 **veya** kalan = 0 | `critical` |
| Silinen ≤2 ve kalan ≥3 | `warning` veya `info` (OS rotasyonu) |
| `vssadmin delete` komutu görüldüyse | her zaman `critical` |

---

## 3) Canary (`ransomware_canary_triggered`)

**Sorun:** DESKTOP’ta ~30 dk’da bir critical (muhtemel sync/AV/self-touch).

- Canary dosyasına agent’ın kendi yazması / hash yenilemesi → **alert yok**
- OneDrive / backup path canary’si için debounce **≥ 30 dk** (aynı path)
- Tek dosya MODIFIED + VSS sağlam + şüpheli süreç yok → `warning` (critical değil) veya suppress
- Gerçek tetik: çoklu canary + suspect process → `critical`

---

## 4) Network Guard offline bomb / suspect

**Sorun:** `network_cut+fs_storm` Wi‑Fi kopması + OneDrive/update ile kolay patlıyor.

| Sinyal | Beklenen |
|--------|----------|
| `ransomware_offline_suspect` | `severity=warning` (high/critical değil); otomatik suspend yok |
| `ransomware_offline_bomb` | Yalnızca **confirm policy** / yüksek güven; kısa Wi‑Fi flap’te bomb yok |
| Aynı trigger+pid | Client-side dedupe ≥ 5 dk |

Cloud artık suspect’i high’a yükseltmiyor — client doğru severity göndermeli.

---

## 5) Agent resilience / persistence

**Sorun:** `guardian_running=false` iken motor ayakta → “dayanıklılık bozuldu” spam. `guardian_restarts_24h` 150–250 anormal.

- Urgent/alert **gönderme**; yalnız health `resilience` observe alanı
- Alert (isterseniz): yalnız `restart_storm=true` veya `binary_integrity=invalid` veya (`daemon_ok=false` **ve** `stand_down_reason` boş/update değil)
- Self-update / `stand_down_reason=update` → alert yok
- Guardian restart döngüsünü düzeltin (telemetry bug veya servis flap)

---

## 6) Trusted / local logon gürültüsü

`successful_logon` / `privilege_assigned` / `explicit_credential_logon` whitelist veya `local`:
- `severity=info`, score ≤10 (cloud zaten Trusted yapıyor)
- Başlıkta “Lateral Movement” **kullanma** (yanıltıcı); type neyse o kalsın
- Dashboard kritik şeridine zaten düşmemeli

---

## 7) Acceptance (client QA)

1. Agent VSS poll → dashboard’da **yeni ransomware_process yok**
2. `vssadmin delete shadows` simülasyonu (lab) → critical gelir
3. PC sleep → presence suspend ≤2 sn (`api/11-presence-realtime.md`)
4. Self-update → kalıcılık/dayanıklılık alert yok
5. Wi‑Fi kısa kopma → offline_bomb yok; en fazla suspect warning

---

## 8) Lifecycle çift kayıt (DB spam)

**Sorun:** 7 günde ~4000 lifecycle; neredeyse hepsi **aynı saniyede 2×** (`client_startup`, `gui_quit`).

- Tek emit / debounce: aynı `event_type` + aynı saniye → tek POST
- `gui_quit` thrash (control socket) → rate-limit
- `CLIENT_PROCESS_STOPPED` / `CLIENT_GRACEFUL_STOP` → **ThreatAlert/urgent değil**; yalnız lifecycle

## 9) Local konsol score=100 critical

**Sorun:** `source_ip=local` + `privilege_assigned`/`successful_logon` bazen score 100 critical gelmiş.

- `local` / console → her zaman `severity=info`, score≤10
- Başlıkta **Lateral Movement** kullanma (`explicit_credential_logon` kendi adıyla kalsın)

## 10) intel_watch / intel_banner

SecurityEvent info — sorun değil (observe). Urgent’e yükseltme.

- Presence: https://honeypot.yesnext.com.tr/static/shared-contract/api/11-presence-realtime.md  
- Zip: https://honeypot.yesnext.com.tr/static/shared-contract.zip  
- Bu dosya cloud `docs/CLIENT_ALERT_SIGNAL_HYGIENE.md` (client repo’ya kopyalanabilir)

