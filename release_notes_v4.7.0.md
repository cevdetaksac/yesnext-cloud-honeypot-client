# Release v4.7.0 — Network Guard (offline ransomware bomb defense)

Contract: `honeypot-contract` **v1.3.0** (`agent/network-guard.md`)

Fire-and-forget + offline fidye yazılımına karşı (dropper çalışır, ağı keser,
internetsiz şifreler) beş parçalı savunma.

## A) Ağ baseline yedeği
- İmzalı `network_baseline.json` (HMAC = agent token + COMPUTERNAME)
- Mapped drive / shares / adapter / DNS / gateway / route / firewall / connectivity
- Boot + 30 dk periyot; anlamlı değişimde versiyon bump; son 10 sürüm rotasyonu

## B) Offline davranışsal tespit (internetsiz)
- Ağ-kesme tespiti: baseline'a göre internet/adapter delta
- FS fırtınası: per-process `io_counters` yazma hızı (bytes/s + write_count/s)
- Şüpheli köken (Temp/Downloads/Public/UNC) skoru
- **Ağ-kesme + FS-fırtınası → canary beklemeden containment**

## C) Agresif containment (suspend-first)
- Şüpheli süreçler önce **suspend** edilir (adli kayıt korunur, geri alınabilir)
- Acil VSS shadow copy (best-effort)
- Ransomware quarantine'e kayıt; operatör onayıyla kill/release
- Opsiyonel `protection.network_guard.auto_kill` (varsayılan kapalı)

## D) Ağ / bağlantı kurtarma
- `auto_restore` (varsayılan açık): adapter enable / DNS / firewall / mapped-drive baseline'dan geri
- Amaç: malware'in kestiği ağı geri açıp **daemon'un buluta alarm atmasını** sağlamak

## E) Alarm
- `ransomware_offline_bomb` urgent → `system_context.network_guard`
  (trigger, score, network{internet_lost/adapters_down/restored/restore_actions},
  suspects[], vss_emergency_snapshot)

## Komutlar (control WS)
- `network_snapshot` — anlık baseline al
- `network_restore` — baseline'dan geri yükle (**server confirm + HMAC**)
- `list_network_baseline` — baseline özeti

## STATUS / health
- `network_guard{}` bloğu (enabled, baseline_version/age, internet_ok, mapped_drives,
  suspended_processes, last_trigger_ts, auto_restore, auto_kill)

## Dürüst sınır
Tam EDR/AV değil; davranışsal tespit ayarlanabilir eşik + güvenli (suspend-first)
varsayılan. Garanti: erken containment + kurtarılabilirlik.

## Ek
- Fix: `motor_session.json` `version` alanı artık `__version__` ile dolar.

## Cloud/API aksiyonları
- Yeni komut tiplerini whitelist + `network_restore` için destructive confirm
- `ransomware_offline_bomb` urgent'i popup builder'da işle (`system_context.network_guard`)
- Health ingest: `network_guard{}` bloğunu koruma sağlığı rozetine bağla
