# v4.9.6
- **Update disk bloat:** başarılı kurulum sonrası `ProgramData\YesNext\CloudHoneypotClient\update\` altındaki `cloud-client-installer*.exe` + `run-update-*.ps1` + Downloads kopyaları + `TEMP\honeypot_*update_*` temizlenir; indirme artık user Downloads’a yazmaz; staging’de yalnızca aktif installer tutulur; daemon auto-enforce prune.
- **Ayarlar → Güvenlik PIN:** yerel PIN belirle / değiştir / kaldır bölümü (durum + dashboard ipucu); cloud SECTIONS dışında `GuiLock`.

# v4.9.5
- **`list_services` boş liste fix (4.9.4 regression):** PowerShell `ConvertTo-Json` çıktısı TR locale (`cp1254`) altında `UnicodeDecodeError` ile düşüyordu → `success:true` + `services:[]`. Birincil yol artık **pywin32 SCM** (`EnumServicesStatus` + `QueryServiceConfig`/`QueryServiceStatusEx`); PS yedek yolu UTF-8 zorlamalı.
- **Uninstall PIN gate:** Control Panel / NSIS kaldırma önce GUI PIN (veya PIN yoksa onay); lifecycle `uninstall_*` eventleri; `--uninstall-gate`.

# v4.9.4
- **Contract 1.4.8 Server Management:** `list_services` + `name`/`service_name` on start/stop/restart; protected services refuse; `list_local_users.groups`; rich `list_processes`/`list_sessions` + post-mutate health refresh. Hesap silme yok → disable.
- **Remote Desktop:** oturum boyunca encode boyutu kilitli; adaptive yalnız fps/quality; minimum **800×600** tabanı — dashboard’da çözünürlük zıplaması giderildi.

# v4.9.3
- **OOB-501 acceptance visibility:** durable `oldest_dropped` / expire / too-large counters; `health/report` → `offline_urgent_queue{}`; pilot harness (`tests/test_offline_queue_pilot.py`). Flag hâlâ default off.
- **GUI:** istatistik kartlarında ikon+değer aynı satır; IP Listeleri tek scrollbar (sayfa yüksekliğine oturan tablo).

# v4.9.2
- **OOB-501 ↔ contract 1.4.7:** `api/10-offline-urgent-queue` hizası — yerel TTL 7 gün prune, payload ≤200 KB reddi, batch ≤500, `rejected` için schema/too_large/expired drop + transient retry; drain artık başarılı heartbeat **ve** control WS reconnect sonrası. Flag `security.offline_urgent_queue` hâlâ **default off** (pilot drain hazır).
- **Threat Center UX:** Autoblock eşiği threat score (0–100); Engellenen IP kartı IP Listeleri → Engellenen sekmesine gider; Skor kolonu.

# v4.9.1
- **WebRTC JPEG suppression:** ICE+DTLS gerçekten `connected` olduğunda bekleyen JPEG temizlenir ve WS sender binary JPEG göndermez; fallback durumunda JPEG-WS/HTTP anında yeniden devreye girer.
- **10 fps clamp kaldırıldı:** dashboard `fps=30` istediğinde client artık değeri 10'a düşürmez; JPEG adaptive ceiling 30 fps, WebRTC helper ceiling 60 fps.
- **WebRTC capture pacing:** media capture JPEG-era `fps/quality` değerlerinden ayrıldı (30 fps / Q78 başlangıç); persistent session helper 60 fps'e kadar media isteğini kabul eder. Stale kareler tek-slot mailbox/WS coalescing ile düşürülür.
- **DXGI Desktop Duplication:** WebRTC build profiline opsiyonel `dxcam` eklendi; media modunda önce change-driven DXGI capture denenir, yoksa mevcut GDI/ImageGrab/MSS zincirine güvenli fallback olur.
- **Re-offer recovery:** yeni stream offer'ları serialize edilir; eski peer senkron kapanır. Yeni peer kurulamazsa agent anında `webrtc_reject(reason=peer_setup_failed)` gönderir ve JPEG fallback'i tetikler.
- **Media telemetry:** `media.encoder`, `effective_capture_fps`, `capture_quality` ve `target_bitrate_bps` additive meta/status alanları. Hardware encoder henüz dürüstçe ilan edilmez; mevcut aiortc encoder kullanılır.
- **P1 security/resilience observe paketi:** signed-heartbeat/ACL drift adayları, ETW korelasyon, deception/canary health, network dry-run/version rollback, DPAPI offline queue, identity burst aggregate, operator-key metadata ve read-only TPM capability. Tümü default-off/observe; production enforcement ve floor değişmedi.

# v4.9.0
- **Release build:** `build.ps1 -WebRTC` profili ile aiortc/AV native runtime içeren 58.3 MB installer üretildi; SHA-256 `09082F5497262F688E91B69426943BA5AE1BC3C0A8E69A9FADD810A9BE7F4397`.
- **Remote Desktop v2:** Session 0 artık her kare için yeni proses + geçici JPEG üretmiyor. Seçili WTS oturumunda tek, kalıcı ve HMAC doğrulamalı helper; görüntüyü bellekte taşır ve mouse/klavyeyi aynı oturumda uygular.
- **Akıcı transport:** Sağlıklı agent WebSocket'i görüntünün tek yolu; HTTP yalnız bağlantı yokken fallback. En güncel kare mailbox'ı eski kare kuyruğunu ve çift upload'ı kaldırır; gerçek gönderim/coalesce metrikleri ayrı izlenir.
- **Input v2 + mobil kullanım:** Move flood kritik `mousedown`/`mouseup`/wheel/key olaylarını düşüremez. Relative trackpad, direct-touch, tap/double-tap/long-press, güvenli drag ve iki parmak yatay/dikey scroll; çoklu monitör negatif origin koordinatları desteklenir. Input içeriği loglanmaz.
- **Adaptif yayın:** Capture/send baskısına göre FPS, JPEG kalite ve çözünürlük kontrollü düşer; stabil pencerede kademeli toparlanır. Requested/effective değerler ve gecikme/backpressure telemetrisi status/meta içinde raporlanır.
- **WebRTC/H.264 hazırlığı:** Opsiyonel `aiortc`/`av` runtime ile H.264 öncelikli WebRTC, strict stream/session signaling, kısa ömürlü cloud STUN/TURN credential tüketimi ve data-channel input hazırdır. Runtime veya cloud signaling yoksa mevcut JPEG/WS otomatik fallback olmaya devam eder. Varsayılan build WebRTC bağımlılıklarını içermez; yayın profili `build.ps1 -WebRTC` kullanır ve runtime eksikse dürüstçe fail olur.

# v4.8.5
- **Dashboard "Kaldırılıyor…" takılı kalma fix:** Client yerel firewall kuralını siliyordu ve `pending-unblocks` kuyruğunu boşaltıyordu, ama `POST /api/agent/block-removed` ACK'i yalnız `block_ids` taşıyordu. Canlı probe: aynı endpoint `ip` ile `updated>0` dönüyor, `block_ids`-only ile çoğu zaman `updated:0` — cloud "removing" satırını kapatmıyor, dashboard butonu sonsuza dek "Kaldırılıyor…" kalıyor. FW-SYNC artık ACK'te **hem `block_ids` (int) hem `ips`/`ip`** gönderir; `updated=0` olursa IP başına fallback ACK dener. Yanıt `updated=` artık loglanır.
- AutoResponse unblock raporu da `updated=` değerini loglar (`updated=0` uyarısı).
- 3 unit test. **Cloud TODO:** `block-removed` remove_pending satırlarını `block_ids` ile de `updated>0` yapmalı; kuyruk ACK gelene kadar tutulmalı (GET'te silinmemeli).

# v4.8.4
- **Whitelist "eklendi ama görünmüyor" fix (cloud SoT):** frontend-only GUI'de engine nesneleri (`threat_engine`/`auto_response`/`event_watcher`) `None` olduğundan whitelist ekleme yalnız yerel setlere yazmaya çalışıyor, buluta **boş liste** gönderiyor (mevcut cloud whitelist'i silme riski) ve tablo hep "Whitelist boş" kalıyordu. Artık:
  - `_persist_whitelist_to_cloud(add/remove)` bulutun güncel `whitelist_ips`'ini okur, yerel setlerle birleştirir, açık add/remove deltasını uygular — asla kör overwrite yapmaz.
  - IP tablosu whitelist sekmesi bulut `threats/config.whitelist_ips`'i de okur (60 sn cache; add/remove sonrası effective response ile tazelenir).
- 5 yeni unit test (merge, wipe koruması, remove, cache, tokensız) + canlı round-trip doğrulaması (1.1.1.1 add → cloud'da göründü → tabloda "Güvenli" satırı → remove → temiz).

# v4.8.3
- **Dashboard'dan GUI PIN yönetimi:** yeni uzak komutlar `set_gui_pin` (pin 4-12 hane, confirm gate, PIN result/log'a asla yazılmaz) ve `clear_gui_pin` (PIN sıfırlama). SYSTEM daemon `gui_lock.json`'u yazar; GUI süreci dosya mtime'ından dış değişikliği algılayıp hash'i yeniden yükler ve aktif oturum kilidini düşürür — restart gerekmez. Hesap bağlıysa (`is_account_linked()`) tüm PIN diyaloglarında "Hesabınız bağlı — PIN kodunuzu dashboard üzerinden tanımlayabilir veya sıfırlayabilirsiniz" ipucu gösterilir (PIN unutma kurtarma yolu).
- **IP Listeleri hızlı aksiyon butonları:** tablo başlığının sağ üstüne **＋ IP Engelle** ve **＋ Whitelist'e Ekle** eklendi. Modal input ile IP alınır, `ipaddress` ile doğrulanır (geçersiz → toast), PIN gate'inden geçer ve satır aksiyonlarıyla aynı yolu kullanır (daemon IPC block/unblock + whitelist'in `POST /api/threats/config` sync'i).
- 11 yeni unit test: komut whitelist/confirm, pin format doğrulaması, set→verify→clear akışı, PIN sızıntısı kontrolü, dış mtime değişikliğinde relock.

# v4.8.2
- **Ayarlar webhook artık daemon'da etkili:** GUI Ayarlar sekmesi `webhook_enabled`/`webhook_url`'ü buluta (`POST /api/threats/config`) yazıyordu, ama daemon `_sync_threat_config` bu alanları okumuyordu; gerçek gönderici (`client_alerts._send_webhook`) yalnızca yerel `client_config.json` → `notifications.webhook_*` okuduğu için toggle daemon tarafında **no-op**'tu. Artık `_sync_threat_config`, buluttan gelen webhook alanlarını yerel `notifications.*`'e köprüler (cloud tek kaynak, forward client'ta). E-posta tercih alanlarını (`alert_email_enabled`, `instant_email_for_critical`, `min_severity_for_email`, `daily_digest_enabled`) cloud tüketir; client apply etmez.

# v4.8.1
- **Koruma detay popup'ı çelişki fix:** "Koruma Motoru" chip/kartı **AKTİF** derken detay popup'ı **Koruma: OFF** gösteriyordu. Kök neden: popup yerel `process_protection` nesnesini okuyordu; bu nesne yalnız SYSTEM daemon sürecinde yaşar, frontend-only GUI'de her zaman `None`. Popup ve `self_protect` kartı artık chip ile **aynı kaynağı** (daemon STATUS: `motor_ok` + `persistence.self_protection`) kullanır. Popup ayrıca motor, Guardian servisi, 24s tamper ve MemoryGuard durumunu tek ekranda tutarlı gösterir.

# v4.8.0
- **GUI Koruma Durumu şeridi (Anlık Durum):** tüm koruma katmanları tek bakışta — Koruma Motoru, Ransomware Shield, Network Guard, Guardian servisi, honeypot servisleri, karantina. Chip'ler tıklanınca ilgili detay popup'ı/sekmesi açılır; "Katmanları Yönet" ve "Ayarlar" kısayolları eklendi.
- **Yeni Ayarlar sekmesi:** E-posta bildirimleri, otomatik engelleme (eşik/süre/limitler), sessiz saatler ve webhook artık GUI'den yönetilir. Tüm değerler `GET/POST /api/threats/config` ile buluta yazılır; kaydetten sonra efektif config yeniden okunur (bulut = source of truth). Şema + patch üretimi `client_settings_util.py`'de, 10 unit test ile.
- **Güvenlik Katmanları toggle render fix:** `CTkSwitch.select()/deselect()` widget `disabled` iken sessizce no-op — toggle'lar config `True` olsa bile hep KAPALI görünüyordu. Artık önce `state="normal"` sonra knob set edilir (rollback yolu dahil). Katmanlar ve Ayarlar sekmeleri her ziyarette buluttan yeniden eşitlenir.
- **Daemon STATUS genişletildi:** `network_guard{present,enabled,running,suspended_processes,baseline_age_sec,internet_ok}` ve `ransomware_running` alanları eklendi — frontend GUI ransomware/nw-guard durumunu motordan okur (yerel engine yokken "OFF" yanılgısı biter).
- Guardian/persistence detay popup'ı: motor, servis, görevler, öz-koruma, 24 saatlik tamper sayısı ve operator-stop durumu tek ekranda.

# v4.7.6
- **Toplam Saldırı popup fix:** kart bulut `attack-count` (kümülatif) gösterirken detay popup yalnızca yerel `threat_engine`'i okuyordu. GUI frontend-only çalıştığında engine `None` olduğundan popup her zaman "Veri bulunamadı" veriyordu. Yeni `THREAT_TOP` IPC komutu ile motordan gerçek saldırgan listesi çekilir; motorda anlık IP context yoksa boş ekran yerine bulut toplamı + açıklama gösterilir.
- **Günlük log retention:** ana client, threat ve lifecycle logları artık doğrudan `*-YYYY-MM-DD.log` dosyalarına yazılır; yerel gün değişiminde yeni dosyaya geçer ve yalnızca son 7 takvim gününü tutar.
- Daemon + Guardian için gece yarısı rename yarışını önlemek amacıyla klasik timed rename yerine doğrudan tarihli dosya kullanılır.
- `update-install.log` aktif/liveness adı korunur; helper başlangıcında eski tarihli satırlar `update-install-YYYY-MM-DD.log` arşivlerine ayrılır ve 7 gün retention uygulanır.
- GUI “Logları Aç” aksiyonu güncel tarihli client logunu açar. Eski `.1`/`.2` rotasyonları retention süresi dolunca temizlenir.

# v4.7.5
- **Update/tamper handoff hotfix:** `update-and-install.ps1` artık `update_in_progress.lock` dosyasını yeni daemon `Ensure-DaemonMotor` ile hazır olduktan sonra temizler. Önceden lock daemon boot'tan önce siliniyor; planlı installer kapanışı yeni motor tarafından `unexpected_exit` / `agent_tamper` sayılıyordu.

# v4.7.4
- **IPC health hotfix:** daemon `STATUS` oluştururken `get_persistence_status()` tekrar aynı `:58632 STATUS` soketini çağırıyordu. Tek-thread control server recursive self-call kuyruğuyla doluyor; GUI/Guardian motor sorguları timeout oluyor ve çok sayıda `CLOSE_WAIT` bırakıyordu. STATUS artık yerel daemon durumunu override olarak geçirir ve kendi soketini probe etmez. Regression test eklendi.

# v4.7.3
- **Operator-approved containment (hard safety):** Network Guard detection is **always alert-only**. Cloud config cannot enable `auto_contain` / `auto_kill` / `auto_restore`. Suspend only via confirmed `suspend_process` (exact `pid` + image/path + `process_start_time`); `resume_process` releases.
- **GUI Control Center:** new **Güvenlik Katmanları** tab — ransomware / canary / Network Guard toggles write immediately via `POST /api/threats/config`, rollback on failure; daemon applies on `threat_config_updated` WS push.
- **Count/action UX:** tracked-IP card and popup share one blocked∪watching snapshot; active services card uses real PORT_TABLOSU total (no hardcoded /5); honeypot Start/Stop in detail; custom share Remove; unknown Windows service Stop; whitelist mutations persist to cloud.

# v4.7.2
- **KRİTİK güvenlik hotfix (Network Guard):** 4.7.0/4.7.1 canlı makinede normal uygulamaları (Chrome/Firefox/Cursor/GameLoop/EdgeWebView) "offline fidye bombası" sanıp **suspend ediyordu → PC kilitleniyordu.** İki kök neden + bir tasarım kararı:
  - **net_cut false-positive:** `diff_connectivity`, internet düşmese bile güncel adapter listesi boşken tüm baseline adapterlarını "down" sayıyordu. Artık `net_cut` yalnız gerçek internet erişim kaybında (`internet_lost`) True olur; adapter down/VPN-Wi-Fi churn yalnız bilgi amaçlı.
  - **Otomatik containment KAPATILDI (varsayılan):** `auto_contain=false`, `auto_kill=false`, `auto_restore=false`. Network Guard artık tespit edip **yalnız alarm** gönderir (`ransomware_offline_suspect`, severity=warning); süreç dondurma/ağ değiştirme yapılmaz. Operatör dashboard'dan inceleyip `network_restore`/kill onaylar (kontrat "suspend-first + operatör onayı").
  - **Güçlü imza şartı:** otomatik containment yalnız operatör `auto_contain=true` yaptıysa VE yüksek güvenli fidye imzası (canary/VSS quarantine aktif) varsa çalışır. Ham yazma hızı tek başına asla süreç dondurmaz.
  - Eşikler yükseltildi (150 MB/s, 400 write/s), 60 sn trigger debounce, alarm severity ayrımı (`_offline_suspect` warning vs `_offline_bomb` critical).

# v4.7.1
- Hotfix (Network Guard): `_run` subprocess çıktısı locale/OEM güvenli decode edilir (byte al → utf-8/cp1254/cp850/latin-1). TR locale'de cp1254 decode hatası `collect_adapters`/`collect_firewall` çıktısını yutuyor, baseline `adapters:[]` kalıyordu. PowerShell çıktısı UTF-8'e zorlandı. Artık adapter/DNS/route baseline dolu → ağ-kesme tespiti + DNS restore çalışır.

# v4.7.0
- Contract 1.3.0 — Network Guard (offline fidye bombası + ağ sürücü yedek/kurtarma):
  - **A) Baseline:** `network_baseline.json` (imzalı, HMAC) — mapped drive / shares / adapter / DNS / route / firewall / connectivity; 30 dk periyot + boot; son 10 sürüm rotasyonu.
  - **B) Offline tespit:** internetsiz davranışsal skorlama — ağ-kesme (baseline delta) + per-process yazma fırtınası (psutil io_counters) + şüpheli köken; ağ-kesme + FS-fırtınası → canary beklemeden tetik.
  - **C) Containment (suspend-first):** şüpheli süreçler önce **suspend** (kill değil), acil VSS snapshot, quarantine kaydı; operatör onayıyla kill/release; opsiyonel `auto_kill`.
  - **D) Kurtarma:** `auto_restore` ile adapter/DNS/firewall/mapped-drive baseline'dan geri yüklenir → daemon buluta yeniden bağlanır.
  - **E) Alarm:** `ransomware_offline_bomb` urgent (`system_context.network_guard`, suspects/network/restored/vss).
  - Komutlar: `network_snapshot`, `network_restore` (confirm), `list_network_baseline`; STATUS/health `network_guard{}` bloğu.
  - Fix: `motor_session.json` version alanı artık `__version__` ile dolar.

# v4.6.0
- Contract 1.2.0 — survival + disaster recovery:
  - **Guardian:** `CloudHoneypotGuardian` Windows servisi (SCM restart-on-failure) + motor çapraz watchdog
  - **Tamper:** beklenmedik motor çıkışı → `agent_tamper` urgent; dead-man `motor_heartbeat.json`; STATUS/health `persistence{}`
  - **PIN stop:** imzalı `operator_stop.json` — motor yalnız update-lock veya PIN ile durur; tray Exit → motor QUIT
  - **Recovery:** `create_user`, `remote_logon` (reconnect / autologon+reboot), `set_autologon`/`clear_autologon`/`reboot`
  - Autologon: LSA secret + `AutoLogonCount=1`; boot sonrası temizlik + `remote_logon` completion

# v4.5.68
- Hotfix: canary urgent tek zengin yol — ince `handle_alert` yarışı kalktı.
- `system_context.ransomware` / `raw_events` / `target_service=SYSTEM` her canary urgent'ta zorunlu.

# v4.5.67
- Contract 1.1.3: Canary urgent alert artık quarantine/suspect taramasından sonra zengin payload gönderir.
- `target_service=SYSTEM`, `recommended_action=isolate_host`, structured `raw_events`.
- `system_context.ransomware`: file, change_type, suspects (image/path/PID/cmdline/SHA-256), quarantine özeti.
- Health snapshot: `ransomware_quarantine` (active/trigger/entries) — cloud popup/fleet fallback.

# v4.5.66
- Contract gap close (`honeypot-contract` 1.0.0):
  - `POST /register` → `protection.block_rules` ProgramData’ya yazılır; boot + ThreatEngine normalize/apply
  - `GET /threats/config` → `protection.block_rules` SoT (legacy block-rules fetch fallback)
  - Control WS `threat_intel_updated` → anında `ThreatIntelManager.sync_once()` (HTTP poll yedek)

# v4.5.65
- UX: canary tetiklenince yerel tray/toast yok (dashboard/API urgent kalır) — kullanıcıyı korkutmama
- OneDrive-backed Documents'a canary konmaz (bulut senkronunda görünürlük/kota)
- Canary'lere NotContentIndexed; Explorer Hidden+System (önceki gibi)
- IFEO asla SearchIndexer / Defender / OneDrive / shell host süreçlerine uygulanmaz
- GUI metinleri yumuşatıldı ("tuzak" → "gizli koruma dosyası")

# v4.5.64
- SYSTEM motor: ProfileList + scan existing `Users\*\Documents\.cloud-honeypot-canary` so interactive-user canaries are watched (4.5.63 gap found in scenario test)
- Keep quarantine arm-first from 4.5.63

# v4.5.63
- Canary hit: quarantine **immediately armed** (open_files scan time-boxed ≤4s) — STATUS/GUI no longer lag
- SYSTEM motor seeds canaries into interactive users' Documents (not only systemprofile/Public/ProgramData)
- Scenario test on DESKTOP-F5SCL3G: threat-intel OK; canary MODIFIED detected; unlock IPC OK

# v4.5.62
- Canary sertleştirme: `!000_` sort-bait isimler, Hidden+System dosya+klasör, README sadece ProgramData
- Canary/VSS hit → şüpheli süreci öldür + IFEO karantina; unlock: GUI / `RS_UNLOCK` / `unlock_ransomware_quarantine`
- Canary kontrol aralığı 15 sn; ek TTP (fsutil USN, wevtutil cl, VSS PowerShell, net stop vss)
- Frontend ransomware detayı SYSTEM motor IPC (`RS_STATUS`) ile çalışır

# v4.5.61

## Cloud threat-intel feed (client consumer)
- Daemon polls `GET /api/agent/threat-intel` (ETag/304), caches under ProgramData.
- Applies firewall IoCs (policy-gated), merges ransomware watch lists, banners/alerts.
- Cloud SoT — agent does not scrape Abuse.ch/CISA directly.
- Spec for cloud team: `docs/CLOUD_THREAT_INTEL_API.md` + `docs/api/09-threat-intel.md`.

---

# v4.5.60

## Health: disk full / IDE I/O is not ransomware
- `disk_usage_percent` → capacity only (threshold 98%, no ransomware wording, no threat-engine spam).
- Disk I/O from Cursor/VS Code/browsers/Defender suppressed as benign performance.
- Sustained anonymous writers escalate to `ransomware_suspect` only; real ransomware remains canary/VSS/process layers.

---

# v4.5.59

## Daemon immortality: Watchdog checks SYSTEM motor, not GUI
- Architecture: Session-0 daemon = security motor; per-session tray/GUI = UI only.
- Watchdog no longer treats “any honeypot-client.exe” as healthy — requires `motor_ok` / Session 0.
- Interactive `--mode=daemon` no longer converts into a GUI motor (ensures Background + exits).

---

# v4.5.58

## Fix: duplicate tray/GUI instances
- Frontend/tray skipped the singleton check → two "Security" windows / tray icons.
- Per-session `Local\CloudHoneypotClient_GUI` mutex: second launch exits.
- Named show-event + window restore handoff so the existing UI comes to front.

---

# v4.5.57

## Fix: dashboard detail popup freezes the app
- Root cause (v4.5.53): `overrideredirect` applied after map + `transient` + `grab_set` left the dialog invisible while the main window stayed modal-locked.
- Frameless is set before show; no `grab_set` / no `transient`; lift + focus_force after widgets exist.

---

# v4.5.56

## Immortal self-update (Win10/11/Server 2012+)
- Stage helper as CRLF 7-bit ASCII + PowerShell `Parser` gate before launch (em-dash / UTF-8-no-BOM never ships again).
- Never `copy2` raw Unicode scripts; on stage/parse failure write embedded **emergency ASCII bootstrap**.
- Launch ladder: WMI → cmd start → schtasks → breakaway → emergency rewrite → last-resort schtasks bootstrap.
- Preflight: installer size + free disk on ProgramData/ProgramFiles.
- Silent update **refuses to exit** without `update-and-install start` (same as dashboard).
- Heal: detect launcher-only storms and clear stuck lock / re-stage helper.

---

# v4.5.55

## Remote Desktop: frame ACK input piggyback (AGENT_REMOTE_INPUT_HOTFIX)
- Cloud drains `inputs[]` on every `POST /api/remote/frame` / `frame-json` response — agent was ignoring them → dead mouse while video worked.
- `upload_remote_frame` returns `{ok, inputs}`; each frame HTTP post applies the batch.
- HTTP frame upload every capture (alongside WS) so the queue does not stall.
- `GET /api/remote/inputs` kept as backup (also while WS is up).

---

# v4.5.54

## Fix: helper script never ran (Unicode broke PowerShell 5.1)
- `update-and-install.ps1` contained em-dashes (U+2014). PS 5.1 UTF-8-without-BOM mis-parsed try/catch → launcher wrote `launcher start` then died; install never began.
- Script is ASCII-only; staging normalizes dashes/quotes when copying to ProgramData.
- Success now requires `update-and-install start` (not launcher-only).

---

# v4.5.53

## UI: detail popup double title bar
- Dashboard detail popups (Last Attack, etc.) no longer show native Win32 title + custom header together.
- Frameless dialog with one themed header, drag-to-move, Escape to close.

## Also in this train
- v4.5.52 updater fix (fresh `update-install.log` required) — use dashboard self_update to verify.

---

# v4.5.52

## Fix: self_update helper never started (stuck “Kurulum çalışıyor”)
- Root cause: `launch_safe_update_install` returned True if PowerShell looked alive for 0.4s; parent exited and the child died in a job object — no `update-install.log`, banner stuck on installing.
- Now requires a **fresh** log line (`launcher start` token / `update-and-install start`) before success.
- Spawn order: WMI Create → `cmd start /b` → schtasks (delete only after log) → breakaway Popen.
- `self_update` aborts with `helper_log_missing` instead of exiting into a fake install.

---

# v4.5.51

## Fix: stuck update banner
- Obsolete `failed` status (e.g. 4.5.43→4.5.45 while already on 4.5.49) is cleared automatically.
- Banner has an ✕ dismiss button (clears `update_ui_status.json`).
- Failed banners auto-hide after ~45s; expired status files are deleted.

---

# v4.5.50

## RDP honeypot: NetNTLMv2 hash capture
- When client requests NLA (`PROTOCOL_HYBRID` / `HYBRID_EX`), honeypot accepts CredSSP:
  TLS (self-signed) → NTLMSSP Type2 challenge → Type3 → **hashcat 5600 / John netntlmv2** line.
- Cookie-only probes still report `<rdp_connection_attempt>` (username IoC).
- New module `client_rdp_nla.py`; password field may be up to 2048 chars for hash lines.
- **Not** plaintext RDP passwords (CredSSP sealed credentials remain out of scope).

---

# v4.5.49

## Fix: auto-update stuck on SYSTEM hosts
- `download_installer` no longer writes to `systemprofile\Desktop` (Errno 2); uses ProgramData `update\` staging.
- Helper launch: breakaway detached PowerShell first; schtasks UpdateOnce waits for `update-install.log` before `/Delete` (was cancelling the one-shot).
- Stale `update_in_progress.lock` clears in ~15s when holder PID is dead (was blocking retries for minutes/hours).
- Silent update waits longer for helper log and retries launch once.

---

# v4.5.48

## Remote Desktop prepare path
- `list_local_users`, `list_sessions.can_capture`, `remote_session_prepare` (auth + tscon/WTSConnect + JPEG probe).
- `remote_session_logoff` alias; one-shot password never logged / not stored in history.
- Docs: `docs/api/05-remote-desktop.md` flow (user → prepare → stream).

### Note (RDP honeypot passwords)
Cleartext RDP password capture remains a separate CredSSP/NTLM project — **partially addressed in v4.5.50** (NetNTLMv2 hashes, not plaintext).

---

# v4.5.47

## Cleanup
- Remove unused methods (utils RDP/update helpers, dead client/GUI/helpers/security APIs).
- Delete `_archive/client_networking.py`, scattered `docs/release_notes_v*.md` (CHANGELOG is SoT).
- Drop unused theme tokens (`FONTS`, `CORNER_RADIUS`, purple); ignore local junk logs/probes.

---

# v4.5.46

## Centralization / P1 cleanup
- Threat intel coalesce (sequential PS in one worker); service toggle off-thread.
- Expand `client_winproc` (`run_ps` / `run_ps_script` / `popen_detached`) and migrate GUI + helpers + AR + IPC call sites.

---

# v4.5.45

## Fix: stuck “Kurulum çalışıyor”
- Helper install heartbeats no longer reset the stale clock (`phase_started_at`).
- Banner auto-dismisses when current version is already ≥ update target.

---

# v4.5.44

## Stability / performance review
- Periodic Engellenen refresh no longer forces full `netsh name=all` every ~20s (coalesce + throttle).
- Failed firewall scan must not wipe ProgramData / API inventory.
- GUI block/unblock/whitelist off Tk thread; prefer SYSTEM IPC `BLOCK_IP` / `UNBLOCK_IP`.
- `clear_firewall` does not hold cleanup lock across netsh/HTTP (busy flag).
- Motor health cached off UI thread; `client_winproc.run_hidden` centralizes hidden subprocess.
- Architecture doc refreshed: `docs/api/08-architecture.md`.

---

# v4.5.43

## Güncelleme banner takılması
- “Kurulum çalışıyor” helper ölünce / NSIS hiç başlamayınca sonsuza kadar kalıyordu.
- Active phase timeout: installing ~10 dk → `failed` + lock release (“Güncelleme takıldı”).
- Boot: hâlâ eski sürümdeyken `installing` → `install_did_not_complete`.
- Helper: NSIS beklerken her 5 sn `update_ui_status` heartbeat.

---

# v4.5.42

## Tümünü temizle: gerçekten siler (SYSTEM)
- GUI unelevated → `netsh delete` “requires elevation” ile sessizce başarısız oluyordu; CMD flaş + kural/API değişmiyordu.
- Fix: GUI `CLEAR_FIREWALL` IPC → Session-0 Background daemon (elevated) purge + `sync-rules []` + `clear-data`.
- Tek gizli PowerShell `Remove-NetFirewallRule` sweep (CMD yağmuru yok); netsh sadece kalanlar için.
- Yetkisiz süreç store/API’yi boşaltmaz (firewall doluyken yalan UI yok).

---

# v4.5.41

## CMD penceresi flaşları
- Firewall `netsh` taraması (`client_firewall.run_cmd`) artık `CREATE_NO_WINDOW` + `SW_HIDE` ile gizli çalışır.
- Engellenen yenileme / daemon poll sırasında siyah konsol açılıp kapanmaz.
- Birkaç diğer gizli olmayan spawn (shutdown, daemon Popen, RDP/helpers) aynı şekilde kapatıldı.

---

# v4.5.40

## Engellenen listesi düzeltmesi + Tümünü temizle
- Root cause: `netsh show rule` without `name=all` fails on Windows → 0 rules.
- Second cause: `text=True` + cp1254 decode crash on large netsh dumps → empty stdout.
- Fix: `name=all` + bytes decode (utf-8/cp857/…); failed scan no longer wipes ProgramData store.
- IP table: **Tümünü temizle** button → delete all HP-BLOCK/HONEYPOT_* rules + `sync-rules []` + `clear-data` scopes=blocks.

---

# v4.5.39

## GUI: güncelleme durumu banner
- Dashboard `self_update` komutu alındığında GUI üstünde uyarı bandı:
  “Güncelleme talimatı alındı” → indirme % → kurulum → tamamlandı/başarısız.
- Daemon (SYSTEM) → ProgramData `update_ui_status.json` → GUI poll (1 sn).
- Toast + kalıcı üst banner; başarı ~12 sn sonra kapanır.

---

# v4.5.38

## Engellenen = firewall (HP-BLOCK) source of truth
- GUI no longer relies only on empty/stale `blocked_ips.json`.
- On Engellenen refresh: live `netsh` scan → ProgramData store → table.
- Numbered dashboard rules (`HP-BLOCK-1010`…) get RemoteIP via per-rule lookup when bulk list omits it.
- Turkish/locale RemoteIP field parsing hardened.

---

# v4.5.37

## Daemon always-on after update (root cause)

Silent/interactive update helper previously **disabled** `CloudHoneypot-Background` + `Watchdog`, then often never re-enabled them on success → motor dead, dashboard “poll yok”.

### Fix
- After every install (success **and** fail): `Restore-HoneypotTasks` + `Ensure-DaemonMotor`
- Prefer `schtasks /run CloudHoneypot-Background` (SYSTEM Session 0)
- Wait/re-kick until control port `127.0.0.1:58632` answers
- Then tray (if logon) — GUI is not the motor

Includes 4.5.36 emergency GUI bridge as safety net.

---

# v4.5.36

## Dashboard offline while GUI says Connected
- GUI “API Bağlı” only meant auth worked; **commands/pending poll** is owned by SYSTEM daemon.
- After silent update, if Background daemon is down → dashboard “çevrimdışı / poll yok”.
- Fix: frontend motor watchdog starts **emergency command bridge** (poll + heartbeat) when daemon won’t come up.
- Connection card: `API var · motor yok` when auth OK but motor/poll missing.
- Silent helper: prefer `CloudHoneypot-Background` + wait for `:58632` before tray.

---

# Changelog — Cloud Honeypot Client

Otomatik birleştirildi: eski 
elease_notes_v*.md dosyaları.
Kaynak: GitHub Releases + bu dosya.

---

# v4.5.35

## Silent self-update polish
- Dashboard update sonrası görünen `timeout /t 120` CMD penceresi kaldırıldı (one-shot schtasks hemen siliniyor).
- Sessiz güncelleme bitince: SYSTEM daemon + logon varsa **tray** (tam `--show-gui` penceresi yok).

## Included from 4.5.34 (if not yet on host)
- Firewall HP-BLOCK → Engellenen GUI + periyodik `sync-rules`
- NSIS `/S` mid-install daemon Exec yok; helper installer timeout
- Uzak masaüstü: helper probe 12s, WS öncesi JPEG kuyruğu

---

# v4.5.34

## Firewall ↔ GUI ↔ API inventory
- Engellenen listesi artık frontend-only GUI’de de `blocked_ips.json` (ProgramData) üzerinden doluyor (`threat_engine` şart değil).
- Daemon ~15 dk’da bir (ve pending block/unblock sonrası) firewall taraması → store → `POST /api/agent/sync-rules`.
- Store: dosya mtime cache yenileme; kuraldaki tüm RemoteIP’ler.

## Silent self-update (önceki kısır döngü)
- NSIS `/S` artık kurulum ortasında daemon başlatmıyor (helper restart eder).
- Defender exclusion async; helper installer timeout (480s).
- Staging: çift `cloud-client-installer-` prefix engellendi.

## Uzak masaüstü
- SYSTEM Session 0 → RDP oturumu helper probe timeout 3s → **12s**.
- Helper zorunluyken Session-0 BitBlt fallback kaldırıldı (siyah ekran tuzağı).
- JPEG’ler WS bağlanmadan önce kuyruğa alınır (probe kaybı yok).
- Siyah karede input desktop yeniden attach + tscon hedef session.

---

# v4.5.32 — Silent self_update helper sertleştirme

- `update_in_progress.lock` varken silent NSIS **daemon başlatmaz** (helper restart eder) — installer hang önlemi
- SYSTEM helper: `schtasks /Create /RU SYSTEM` one-shot (DETACHED powershell kaybolmasın)
- Staged installer adı: `cloud-client-installer-X.Y.Z.exe` (çift prefix yok)

Not: Dashboard “Agent bekleniyor” — client zaten `running`/`completed` POST ediyor; UI status map cloud tarafında.

---

# v4.5.31 — Agent control WebSocket (komut push)

- `wss://…/ws/agent/control` + Bearer — dashboard komutları anında
- HTTP `commands/pending` poll emniyet ağı (WS ayaktayken ~30s)
- `command_id` dedup (poll + WS çift teslimat)
- Result: WS `command_result` + HTTP `commands/result` (dual)
- `self_update` erken ACK aynı kanalda

Cloud hub hazır değilse connect fail → reconnect; poll çalışmaya devam eder.

---

# v4.5.30 — Engellenen IP’ler ProgramData + firewall hydrate

- `%ProgramData%\YesNext\CloudHoneypotClient\blocked_ips.json` — kalıcı envanter
- Daemon açılışında `HP-BLOCK-*` taranır → store + AutoResponse/ThreatEngine hydrate
- GUI Engellenen sekmesi store + firewall envanterinden dolar (RAM şişmeden yüzlerce IP)
- API `sync-rules` ile eşzamanlı
- Unblock/block store’u günceller

---

# v4.5.29 — IP Listeleri sekmelerinde sayı

Aktivite / Engellenen / Whitelist sekme başlıklarında toplam:
`Activity (3)`, `Blocked (12)`, `Whitelist (1)`.
Refresh ve veri güncellemesinde sayılar anlık güncellenir.

---

# v4.5.28 — Agent API: Bearer auth (no query token)

Token artık varsayılan olarak **sadece** `Authorization: Bearer` ile gider.

- `api.legacy_token_query`: **false** (config + kod varsayılanı)
- GET/POST: query’den `token` kaldırıldı; POST body `token` uyumluluk için duruyor
- Remote Desktop WS: URL’de `?token=` yok; `Authorization: Bearer` header
- Acil rollback: `client_config.json` → `"legacy_token_query": true`

Cloud dual-read (Bearer → body → query) ile uyumlu; dashboard deep-link (`/dashboard?token=`) ayrı konu, değişmedi.

---

# v4.5.27 — Installer: Finish checkbox yok, otomatik başlat

Kurulum bitince Finish ekranı / “Launch now” kutusu yok.
Uygulama hemen açılır; installer `AutoCloseWindow` ile kapanır.
Silent: daemon; interaktif: GUI (`--show-gui`).

---

# v4.5.26 — Logon’da tray (Admin / Türkçe Windows)

## Sorun
Kimse logon değilken Administrator ile girişte tray düşmüyordu.
Türkçe Windows `query session` durumunda **Aktif** yazar; agent yalnızca İngilizce **Active** arıyordu → oturum “yok” sanılıp tray tetiklenmiyordu.

## Düzeltme
- Oturum algısı locale-aware: Active / Aktif / Aktiv / …
- `query user` yedek kontrol
- Daemon izleyici: 10 sn poll; logon rising-edge’de hemen tray
- `schtasks /run` yetmezse SYSTEM → **CreateProcessAsUser** ile Active session’a `--mode=tray`
- Tray LogonTrigger gecikmesi 15s → **5s**

---

# v4.5.25 — PIN kaldır yalnızca PIN varsa

Ayarlar → Güvenlik: **PIN kaldır** menü öğesi sadece PIN tanımlıysa gösterilir.

---

# v4.5.24 — Ayarlar menüsü + i18n

- Ayarlar popup: **Hesap / Güvenlik / Dil / Bakım** bölüm başlıkları
- Bağlı durum rozeti (tıklanmaz); çift “My servers” kaldırıldı
- Emoji kalabalığı azaltıldı
- TR: `Sunucularım`, `Panel verisini temizle`, `Güvenlik duvarı…`
- Hardcoded `Yükleniyor…` → `gui_loading`
- Eksik TR loading_* anahtarları tamamlandı

---

# v4.5.23 — disable_all_users = unified AGENT_DISABLE_ALL_USERS_PROMPT

- **Administrator dahil** disable (`exclude` yoksa)
- Params: `logoff` (default true), `exclude` (break-glass)
- Hard-skip: SYSTEM / LOCAL SERVICE / NETWORK SERVICE / WDAGUtilityAccount / DefaultAccount
- `skipped`: `[{username, reason}]`
- Kısmi: `completed` + `ok:false`; tam hata: `failed`

---

# v4.5.22 — disable_all_users ↔ cloud contract

Cloud `AGENT_DISABLE_ALL_USERS_PROMPT.md` ile hizalandı:

- `skip_protected` (default **true**) → Administrator / Guest skip
- `logoff_sessions` (alias `logoff`)
- `exclude` + `protected_accounts` skip listesine eklenir
- `skipped` string[] (cloud örnekleriyle aynı)
- Kısmi başarı → `ok: false`
- Concurrent lock + lifecycle begin/ok/failed

**Panik notu:** Cloud varsayılanı Administrator’ı **disable etmez**. Admin’i de kilitlemek için send’de:
`skip_protected: false` ve `exclude` içinden `administrator` çıkarılmalı  
(veya ayrı `disable_account` / `contain_user`).

---

# v4.5.21 — `disable_all_users` (panic IR)

Panik: tüm yerel kullanıcıları tek komutta disable (Administrator dahil).  
API/dashboard sözleşmesi: `AGENT_DISABLE_ALL_USERS_API_PROMPT.md`

```json
{ "command_type": "disable_all_users", "parameters": { "logoff": true, "exclude": [] } }
```

Recovery: `reset_password` + `enable_account` (hesap bazlı).

---

# v4.5.20 — reset_password: dashboard şifresi, echo yok

## Akış
1. Dashboard kullanıcıya yeni şifreyi sorar (≥8 karakter).
2. `POST /api/commands/send` → `{ username, new_password }`
3. Agent: `net user {username} {new_password}`
4. Result (şifre **dönmez**):

```json
{
  "command_id": "…",
  "status": "completed",
  "result": { "ok": true, "username": "attacker" }
}
```

## Agent kuralları
- `new_password` yoksa → `failed` + `missing_password` (kendi üretmez)
- `< 8` karakter → `password_too_short`
- `contain_user` aynı kural: `new_password` zorunlu, result’ta parola yok

---

# v4.5.19 — self_update anında ACK + fleet güncelleme sertleştirme

## Teşhis (v4.5.18)
GitHub’da `cloud-client-installer.exe` **downloadCount = 0** → sunucular indirmeye hiç geçmemiş.
Yani sorun “yavaş kurulum” değil; komut ya **poll’a düşmemiş** ya da **URL resolve / kilit / size** aşamasında takılmış.

## Client düzeltmeleri
- `self_update` / `check_update`: IR poll + **erken ACK** (`status=running`, `update_accepted`) — dashboard “pending”de asılı kalmaz
- `tag` varken GitHub API olmasa bile resmi release URL’si üretilir
- `force=true`: takılı update lock temizlenir
- Yanlış `size` artık güncellemeyi **engellemez** (sadece uyarı)
- `self_update` öncelik sırası = kill/logoff ile aynı (0)

## Dashboard — fleet komutu (önerilen payload)
```json
{
  "command_type": "self_update",
  "parameters": {
    "tag": "4.5.19",
    "download_url": "https://github.com/cevdetaksac/yesnext-cloud-honeypot-client/releases/download/v4.5.19/cloud-client-installer.exe",
    "force": true
  }
}
```
`tag` + `download_url` gönderin; agent’ların GitHub API’ye ihtiyacı kalmaz.

## Önkoşul
- `self_update` handler: **≥ 4.5.11**
- Motor `commands/pending` poll: **≥ 4.5.12**
- Daha eski agent’lar remote update alamaz → manuel installer veya Task Scheduler silent update gerekir

## Beklenen süre
- Komut alınma: ~0.5–1 sn (motor ayaktaysa)
- İndirme + sessiz kurulum: ağ hızına göre 30 sn–birkaç dk

---

# v4.5.18 — IR containment (Administrator dahil)

Saldırı / sızma anında dashboard’un sunucuyu kurtarma aracı: saldırgan Administrator olsa bile **anında** müdahale.

## Ne değişti
- **Administrator / Guest / tüm kullanıcılar** için `logoff_user`, `reset_password`, `disable_account` serbest (koruma sadece SYSTEM / LOCAL SERVICE / NETWORK SERVICE).
- Yeni IR komutu **`contain_user`**: tek komutta  
  1) tüm oturumları logoff  
  2) güçlü şifre ata (`new_password` dashboard’a döner)  
  3) hesabı disable (varsayılan; `disable: false` ile atlanabilir)
- IR sonuçları senkron + 0.5 sn poll (önceki sürümden).

## Dashboard kullanımı
```json
{ "command_type": "contain_user", "parameters": { "username": "Administrator" } }
```
Opsiyonel: `"new_password": "..."`, `"disable": false`, `"session_id": 3`

Ayrı ayrı da kullanılabilir: `logoff_user` → `reset_password` → `disable_account` (aynı poll batch’te hepsi öncelikli).

## Güvenlik notu
`contain_user` / `reset_password` / `disable_account` için dashboard tarafında onay diyaloğu önerilir (`REQUIRES_CONFIRMATION`). Token ele geçirilirse bu komutlar kritik — sunucu imza + onay şart.

---

# v4.5.17 — Logoff her hesap + anında IR tepkisi

## Değişiklikler
- **logoff_user**: `Administrator` dahil **tüm** kullanıcı hesapları logoff edilebilir (koruma yok). Tek istisna: session 0 (services).
- IR komutları (`logoff`, `kill`, `block`, …) sonuçları **senkron** raporlanır — dashboard hemen görür.
- IR sonrası **0.5 sn** poll + 45 sn sticky hızlı tarama.
- Pending fetch timeout 3 sn; domain\user eşleşmesi iyileştirildi.

## Not
Disable / reset password hâlâ `Administrator` için korumalı; sadece oturum sonlandırma serbest.

---

# v4.5.16 — Remote logoff (Disc / ghost sessions)

## Sorun
Dashboard “Aktif Bağlı Kullanıcılar” listesinde kimse logon değilken eski Console satırları görünüyordu; uzaktan logoff çoğu zaman işe yaramıyordu.

## Düzeltmeler
- **logoff_user**: `Administrator` artık sadece hesap disable/reset’te korumalı; oturum sonlandırma (IR) serbest
- Disc / inatçı oturumlar: `logoff` → `reset session` / `rwinsta`, sonra session hâlâ var mı doğrulama
- Aynı kullanıcı için **tüm** session id’ler temizlenir (`query user` + `query session`)
- Gerçek oturum yoksa net hata: dashboard listesi stale olabilir
- Health: session 0 / services / Listen / kullanıcı adı boş satırlar raporlanmaz; sahte `login_time=now` kaldırıldı

## Not
Daemon + `RemoteCommandExecutor` çalışıyor olmalı (≥4.5.12 motor poll). Güncellemeden sonra logoff tekrar deneyin; liste boşalmazsa health report yenilenene kadar bekleyin.

---

# v4.5.15 — SYSTEM daemon WinError 183 fix

**Hata:**  
`[WinError 183] Halen varolan bir dosya oluşturulamaz: ...\systemprofile\AppData\Roaming\YesNext\CloudHoneypotClient`

**Neden:** Session 0 SYSTEM, Roaming APPDATA altında `makedirs` (dosya/klasör çakışması).

**Düzeltme:**
- SYSTEM / Session 0 → `APP_DIR` = `%ProgramData%\YesNext\CloudHoneypotClient`
- `makedirs` WinError 183’e dayanıklı (`_ensure_directory`)

---

# v4.5.14 — onedir (kendi klasörü)

**Sorun:** `_MEI*` (TEMP veya ProgramData) → `LoadLibrary: Erişim engellendi`

**Çözüm:** PyInstaller **onedir** — `python312.dll` artık  
`C:\Program Files\YesNext\Cloud Honeypot Client\_internal\` altında sabit.

- Runtime extract yok
- Concurrent launch / AV TEMP kilidi yok
- Installer `dist\honeypot-client\*` + `_internal` kurar

---

# v4.5.13 — PyInstaller TEMP Access denied fix

**Hata:** `Failed to load Python DLL 'C:\WINDOWS\TEMP\_MEI*\python312.dll' — LoadLibrary: Erişim engellendi`

**Neden:** Onefile extract `C:\WINDOWS\TEMP` altında; SYSTEM/Admin + AV / execute-from-TEMP politikası DLL yüklemeyi kesiyor.

**Düzeltme:**
- `runtime_tmpdir` → `%ProgramData%\YesNext\CloudHoneypotClient\runtime`
- Installer bu klasörü + Defender exclusion oluşturur

---

# v4.5.12 — Remote komut / RD poll geri

**Sorun:** GUI `:58632` portuna bind edip PING cevaplıyordu → herkes “daemon var” sanıyordu → `commands/pending` ve remote WS hiç açılmıyordu.

**Düzeltme:**
- STATUS: `daemon` / `motor_ok` / `remote_commands_running` gerçek motor bilgisi
- Frontend **asla** kontrol portuna bind etmez
- `is_motor_healthy()` — yalnızca PING yetmez
- `ensure_daemon_running` → schtasks Background + motor_ok bekle
- Daemon: RemoteCommands zorunlu construct + poll thread watchdog
- Frontend: 45s motor watchdog

---

# v4.5.11 — Dashboard self_update

- Remote komutlar: `self_update` + `check_update`
- Dashboard **Şimdi güncelle** → pending poll → hemen silent install (takvim beklemez)
- `force=false` + aynı sürüm → `already_current`
- Sadece resmi GitHub release URL; update lock; lifecycle begin/ok/failed
- `expires_at` / 30 dk TTL desteği; result sync sonra process exit

---

# v4.5.10 — GUI performans

- UI thread'de **senkron daemon IPC yok** (protection mode cache + 5s background poller)
- Pulse blink her 800ms IPC çağırmıyor (cache)
- Frontend açılışta threat/Faz motor stack **kurulmuyor** (daemon zaten motor)
- Prewarm 0.9s/1.6s → **8s/12s** (Status paint ile yarışmıyor)
- IP tablo: değişmediyse rebuild yok; max 60 satır
- Session `query` UI thread dışı
- `[PERF]` logları: page_build, nav, dashboard, ip_table, protection_mode, daemon ping

---

# v4.5.9 — Logon'da tray otomatik

- Tray görevi `Users` yerine **Authenticated Users** (Administrator / RDP dahil)
- Daemon oturum izleyici: yalnızca console değil, **Active RDP** de tray başlatır
- Sessiz update sonrası etkileşimli oturum varsa Tray de tetiklenir
- Watchdog: daemon varken tray yoksa Logon Tray görevini çalıştırır

---

# v4.5.8 — Hizli sekme gecisi

- Tiklamada senkron sayfa build yok (once goster, idle'da doldur)
- Services/Threat acilistan sonra arka planda prewarm
- Threat panelleri 3 dilimde build (UI donmaz)
- Threat'e her donuste security intel yeniden taranmiyor

---

# v4.5.7 — Lazy GUI pages

- Shell (sidebar + ust bar) hemen acilir
- Sayfa widgetlari ilk ziyarette build edilir (status / threat / services)
- Veriler adim adim yuklenir (attack count, IP tablo, security intel…)
- Threat/Services acilista build edilmez
- Frontend modda motor + agir API hâlâ SYSTEM daemon'da; GUI sadece goruntuleme/IPC

Ayrica 4.5.6'dan: RDP buton guncellemesi Tk main thread'e alindi.

---

# v4.5.6 — Hizli acilis (snappy GUI)

Olculen: `Building main GUI` → pencere/tray **15–36 sn** suruyordu.

**Kaldirilan engeller:**
- Task Scheduler XML refresh her acilista (artik sadece VERSION degisince)
- schtasks aktivasyon dongusu GUI'de arka plana alindi
- Lifecycle API + exe SHA hash UI thread'den cikti
- ipify / attack-count senkron cagrilar kaldirildi
- Tray menu `refresh_account_link_status` (API) tray baslatmadan once calismiyordu
- RDP netstat probe acilista yok
- PIN dialog build'i bloklamaz; once pencere, sonra PIN
- Tray `after(50)` ile first paint sonrasina alindi

---

# v4.5.5 — PIN popup stack fix

Tray ikonuna tekrar tiklayinca `wait_window` event loop'u islerken yeni PIN
pencereleri aciliyordu.

- Tek aktif PIN dialog; tekrar tiklayinca mevcut pencere one gelir
- `show_window` busy guard
- Pencere zaten acik + unlock ise PIN sormadan focus

---

# v4.5.4 — TLS CA / guncelleme alert duzeltmesi

**Sorun:** PyInstaller `Temp\_MEI*\certifi\cacert.pem` yolu RDP/TEMP temizliginde kaybolunca:
- API "Baglanti Yok"
- Guncelleme kontrolu kirmizi alert: `Could not find a suitable TLS CA certificate bundle`

**Cozum:**
- `cacert.pem` ProgramData altina kalici kopyalanir
- `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` bu yola isaret eder
- Runtime hook + `resolve_tls_verify()` her HTTPS cagrisinda gecerli bundle kullanir
- GitHub update check/download `verify=` ile ayni bundle'i kullanir

---

# v4.5.3 — GUI stutter / kasma

- Tray ikonu her health tick'te diskten yeniden aciliyordu → cache + ayni state skip
- GUI, daemon gelmeden motor (firewall 30s, open-ports, update watchdog) baslatiyordu → build_gui'de erken PING + frontend skip
- Frontend modda update watchdog GUI'de tekrar baslamasin

---

# v4.5.2 — Silent auto-update recovery

**Kok neden:** `--silent-update-check` (Task Scheduler SilentUpdater) indirme basinda `schtasks /end CloudHoneypot-SilentUpdater` cagirarak **kendini olduruyordu**. Sonuc:
- `update_in_progress.lock` takili kaliyordu
- Watchdog / SilentUpdater / Background **disable** kalabiliyordu
- Install helper hic baslamiyordu (ProgramData'da `update-install.log` yok)
- Agentler eski surumde mahsur kaliyordu

**Duzeltmeler:**
- SilentUpdater / Updater artik update akisinda `/end` edilmiyor (sadece disable)
- Installer `ProgramData\...\update\` altina stage ediliyor (TEMP yolu kalkti)
- Stale lock: olu PID → otomatik temizlenir
- Basarisiz helper: gorevler tekrar enable + daemon restart
- SilentUpdater tetikleyicisi CalendarTrigger (15 dk) + `network_required=false`
- Her silent-check basinda `heal_update_machinery()` (kilit + gorev recovery)

---

# v4.5.1 — GUI acilis hotfix

- Kontrol portu mesgulse GUI artik **sessizce kapanmiyor** (`sys.exit` kaldirildi)
- Kurulum sonrasi GUI hemen acilir; daemon arka planda baslatilir (20sn blok yok)
- `--show-gui` registry LastMode artik `gui` (yanlis `daemon` yazmiyordu)
- Onceki: port mesgul / SHOW path → pencere gelmiyordu

---

# v4.5.0 — SYSTEM daemon motor + multi GUI frontend

- **SYSTEM Session 0 daemon** kalici motor: threat, firewall, honeypot, Remote Desktop, API
- **GUI** frontend-only: coklu kullanici ayni anda acabilir; daemon'i oldurmez
- IPC: `127.0.0.1:58632` — PING / STATUS / HONEYPOT START|STOP|LIST
- Daemon logon olunca artik `os._exit` yapmaz (tray handoff soft)
- `status.json` → `%ProgramData%\YesNext\CloudHoneypotClient\` (paylasimli)
- Dashboard prompt: `AGENT_SYSTEM_DAEMON_FRONTEND_API_PROMPT.md`

---

# v4.4.53 — Multi-user GUI stabil + masaustu kisayol opt-in

- **Cok kullanicili RDP:** Tray task `StopExisting` -> `IgnoreNew` (ikinci logon birinci GUI'yi oldurmez)
- **MemoryRestart:** sadece Session 0 daemon; interactive GUI'ye dokunmaz
- **Singleton steal:** baska oturumda interactive client varsa kill yok
- **QUIT** olayi lifecycle log'a yazilir
- Installer: **Desktop Shortcut** varsayilan **kapali** (kullanici isaretlerse eklenir)

---

# v4.4.52 — Desktop shortcut checkbox + Guest disable

- Installer Components: **Desktop Shortcut** secenegi (varsayilan isaretli); kaldirirsan masaustune kisayol eklenmez
- Start Menu kisayolu her zaman olusur
- **Guest** artik Pasife Al ile kapatilabilir (PROTECTED listeden cikarildi)

---

# v4.4.51 — Watchdog 2m + MemoryRestart fix + lifecycle API

- **Watchdog:** 15 dk -> **2 dk** (cokme sonrasi hizli kaldirma)
- **MemoryRestart:** yanlis InstallPath duzeltildi (`Cloud Honeypot Client`); exe yoksa Background task fallback
- Script artik `INSTDIR\scripts\memory_restart.ps1` ( _MEIPASS degil )
- **Lifecycle log:** `%ProgramData%\YesNext\CloudHoneypotClient\lifecycle.log`
- API: `POST /api/alerts/lifecycle` (kuyruk + flush) — prompt: `AGENT_LIFECYCLE_ALERTS_API_PROMPT.md`

---

# v4.4.50 — Port izleme ≠ honeypot bait

- Header/tray: honeypot kapalıyken bile EventLog/threat açıksa **Port İzleme Aktif**
- Gerçek port brute-force (RDP 3389 vb.) kurallar aktifken bait’siz de bildir/engelle
- API kuralı yoksa yerel `DEFAULT_BLOCK_RULES` (servis başı 3 fail / Network 10)
- Aktif servis detayında port izleme açıklaması
- Dashboard seed API: `AGENT_DEFAULT_BLOCK_RULES_API_PROMPT.md`

---

# v4.4.49 — Remote keyboard fix (Unicode) + CAD SendSAS

- **Klavye:** tek karakter (`a`, `ğ`, `@`, `€`…) artık `KEYEVENTF_UNICODE` `SendInput` — QWERTY VK map yok
- **SendInput** 64-bit güvenli INPUT union (önceki bozuk struct klavyeyi sessizce düşürüyordu)
- `type_text`, `escape`/`enter`/`ctrl+c` vb. korunuyor
- Log: `[remote-input] t=input event=… key=…`
- **CAD:** `remote_send_sas` → `sas.dll` `SendSAS(0)` (sentetik ctrl+alt+del değil)

---

# v4.4.48 — Remote Desktop session picker

- `remote_stream_start` artık `session_id` / `username` / `monitor` dinliyor
- 0 interaktif oturum → `NO_INTERACTIVE_SESSION` (streaming yalanı yok)
- Varsayılan: Console Active → Console → Active RDP → ilk
- Farklı WTS session → `CreateProcessAsUser` helper ile o masaüstü
- Result + WS meta: `session_id`, `username`

---

# v4.4.47 — Remote command coalesce + faster IP update

- **Remote Desktop:** Aynı poll batch’inde birden fazla `remote_stream_start` varsa yalnızca **en yenisi** uygulanır; eskiler `cancelled` / `SUPERSEDED` olarak raporlanır
- **Poll docstring** güncellendi (1s IR/stream)
- **WAN IP:** Public IP cache **5 dk → 60 sn**; ağ değişince `update-ip` daha hızlı

---

# v4.4.46 — Faster silent update checks

- Silent update poll: **30 dk → 15 dk** (Task Scheduler + in-process watchdog)
- Startup: first check ~**90 sn** after launch (previously waited a full interval)
- Config floor lowered to **5 dk** (`updates.check_interval_minutes`)
- No-update poll is a small GitHub `releases/latest` GET only; installer downloads only when a newer version exists

---

# v4.4.45 — Update: client must be closable

Self-protect artık güncelleme sırasında kapanmayı engellemez:

- `disarm_for_update()` — DACL kaldırılır, `HoneypotClientGuard` kapatılır
- GUI + silent update çıkışında disarm + QUIT
- `prepare_client_for_installer` her zaman disarm eder
- Update lock varken QUIT asla ignore edilmez (startup grace bypass)
- `graceful_exit` önce self-protect’i indirir

---

# v4.4.44 — Log / runtime fixes

- **Firewall:** `HTTPAdapter` import fixed (`client_firewall.py`) — agent no longer fails on startup
- **Reconcile:** tunnel-status payload’taki `pending_tunnel_commands` listesi artık servis sanılmıyor; crash yok
- **Self-protect:** `PROCESS_TERMINATE` için `win32con` kullanılıyor (DACL katmanı çalışır)
- **Tray:** aktif servis yokken spam WARNING kaldırıldı (iş istasyonunda normal)

---

# v4.4.43 — Session 0 GUI fix

Kurulum sonrası süreç çalışıyor ama pencere görünmüyordu: client Session 0 (SYSTEM) içinde Tk GUI açıyordu; kullanıcı masaüstünde (Session 1) görünmez.

- Session 0’da GUI açılmaz; interactive `CloudHoneypot-Tray` / `--show-gui` oturumuna devredilir
- Daemon, çalışan GUI’yi çalmaz (Watchdog yarışı engellendi)
- Watchdog: herhangi bir client örneği varsa yeni daemon başlatmaz
- SHOW: Session 0 her zaman `NOGUI` döner (yanlış “pencere açıldı” cevabı yok)
- Tray görevi argümanı: `--show-gui`

---

# v4.4.38 — Setup Finish'te Python DLL / _MEI hatasi

## Sorun
- Finish → Launch: once `--create-tasks` sonra hemen `--show-gui`
- PyInstaller onefile iki kez `%TEMP%\_MEI*` aciyordu → `Failed to load Python DLL ... python312.dll`

## Fix
- Interactive finish: tek `ExecShell --show-gui` (task'lar app init'te)
- Silent: tek `--mode=daemon` (create-tasks cift launch yok)
- Kill sonrasi 2s bekle (_MEI temizlik)

---

# v4.4.37 — Uygulama ici hesaba bagla

## Yenilik
- "Hesaba bagla" popup: e-posta + sifre
- Once `POST /api/agent/link-account` (API prompt: `AGENT_ACCOUNT_LINK_INAPP_API_PROMPT.md`)
- Yoksa web fallback: `/account/login` + `/account/link-server`
- Tray menusu ayni popup'i acar; "Web'de ac" hala var

## Not
- Sifre saklanmaz; basarida e-posta cache + account-status sync

---

# v4.4.36 — GUI tray'e inmiyordu

## Sorun
- `force_gui_onboarding.flag` token olsa bile tray minimize'i engelliyordu
- `--show-gui` bayragi kalici kilitleyebiliyordu

## Fix
- Token varsa onboarding bitmis sayilir → tray'e izin + bayrak temizlenir
- `--show-gui` artik kalici force flag yazmaz

---

# v4.4.35 — "Installer'i simdi calistir?" sonrasi installer acilmiyordu

## Sorun
- Evet sonrasi helper once kendi process'ine QUIT gonderiyordu
- Uygulama installer baslamadan kapaninca NSIS hic acilmiyordu
- Gizli powershell yolu da log uretmeden sessiz kaliyordu

## Fix
- Interaktif guncelleme: NSIS installer'i **dogrudan gorunur** ac (UAC/SW_SHOWNORMAL)
- Self-QUIT yarisi kaldirildi; client installer acildiktan sonra cikar
- Silent path helper'i ayri kaldi (arka plan guncelleme)

---

# v4.4.34 — Kurulum sonrasi GUI acilmiyordu

## Sorun
- Eski/gizli `honeypot-client` ornegi singleton mutex'i tutuyordu
- `--show-gui` DACL yuzunden kapatamayip **exit code 2** ile cikiyordu
- Finish page GUI'yi acamiyordu

## Fix
- Calisan ornege once `SHOW` gonder (pencereyi one getir, yeni process gerekmez)
- Steal basarisizsa `kill-honeypot.ps1 -Force` + taskkill
- Control socket log storm (WinError 10038) duzeltildi
- Installer finish: launch oncesi kill + `--create-tasks`

---

# v4.4.33 — Token kimligi: ProgramData + asla rastgele yenilenmez

## Sorun
- Token `%APPDATA%` altindaydi; SYSTEM daemon ile kullanici GUI farkli dosya okuyup yeni `/register` yapiyordu
- Load/decrypt fail → otomatik yeni token (API'de eski "silindi" gibi)

## Fix (client)
- Canonical token: `%ProgramData%\YesNext\CloudHoneypotClient\token.dat`
- Eski AppData / SystemProfile / token.txt → bir kez migrate
- Dosya varken veya okunamazken **yeni register yok**
- Kayit kilidi (cift register engeli)
- `/register` body: `machine_id` / `hwid` (Windows MachineGuid)
- Mevcut token uzerine farkli token yazma engeli

## API (ayri)
- `AGENT_TOKEN_IMMUTABLE_API_PROMPT.md` → register upsert by machine_id

---

# v4.4.32 — GUI guncelleme: indirme sonrasi installer acilmiyordu

## Fix
- UAC artik `ShellExecuteW runas` ile GUI prosesinden aciliyor (gizli powershell UAC'yi yutuyordu)
- Indirme bitince hemen "Installer'i calistir?" soruluyor; Evet → helper + hizli exit
- Helper basarisiz/UAC iptal → dogrudan installer fallback
- `update-and-install.ps1` hizlandirildi (kisa grace, hizli kill, 0.8s settle)
- Bloklayan "helper basladi" messagebox kaldirildi (exit gecikiyordu)

---

# v4.4.31 — Hizli installer kill

## Fix
- PRE-KILL / kill artik tek hizli gecis: taskkill + SeDebug, max 3 kisa tur
- NSIS artik kill scriptini 15 kez tekrar calistirmiyor; process yoksa skip
- Settle sureleri kisaltildi (~15s+ -> ~1-2s tipik)

---

# v4.4.30 — Installer PRE-KILL fix

## Fix
- `scripts/kill-honeypot.ps1` UTF-8 em-dash (`—`) Windows PowerShell'de string'i kırıyordu → `Unexpected token ')'`
- Script artık ASCII-only; installer PRE-KILL parse hatası giderildi

---

# v4.4.29 — Hesap bağlılığı API’den

## Değişiklikler
- `GET /api/agent/account-status?token=` (fallback: `client_status` içindeki `account_linked`)
- API yanıtı source of truth: `true`/`false` local cache’i günceller
- Heartbeat yanıtında `account_linked` varsa otomatik sync
- Üst bar: bağlıysa e-posta rozeti; ~60 sn + link sonrası poll
- Manuel işaretleme yalnızca API yokken offline fallback

---

# v4.4.28 — Hesaba bağlı CTA + i18n

## Hesaba bağla
- Bağlıysa üst barda CTA yerine **Hesaba bağlı** rozeti.
- Ayarlar → **Zaten bağlı — işaretle** (mevcut bağlı sunucular için).
- Link sonrası onay sorusu; Evet → CTA gizlenir.
- ProgramData `account_link.json` (güncellemede kalır).

## i18n
- Güncelleme diyaloglarındaki sabit TR metinler `client_lang.json` (TR/EN).
- Token etiketi `lbl_token` ile dil uyumlu.

---

# v4.4.27 — Güvenli güncelleme akışı (DLL / _MEI hatası)

## Sorun
Çalışan onefile EXE kapanmadan üzerine yazılınca PyInstaller `_MEI…\python312.dll` yüklenemiyordu.
Kullanıcı düzeyinde kill, DACL self-protect yüzünden çoğu zaman başarısızdı.

## Yeni akış
1. İndirme biter → `update-and-install.ps1` (elevated, ayrı süreç) başlar  
2. Uygulama kendisi çıkar (QUIT)  
3. Helper SeDebug ile kalan süreçleri öldürür ve **süreç yoksa** kurar  
4. Installer WAIT → `--create-tasks` → `--show-gui`  

Log: `%ProgramData%\YesNext\CloudHoneypotClient\update-install.log`

---

# v4.4.26 — Sistem dili + güncelleme kill koruması + ilk kurulum GUI

## Dil
- İlk açılışta Windows arayüz diline göre (TR/EN).
- Kullanıcı dil değiştirirse ProgramData’da saklanır; güncellemede kaybolmaz.

## Güncelleme ortasında kapanma
- `kill-honeypot.ps1` artık `update_in_progress.lock` varsa (indirme) öldürmez (`-Force` yalnızca installer).
- MemoryRestart da aynı kilidi kontrol eder.

## İlk kurulum → GUI görünür
- Tray görevi çalışan GUI’yi çalmaz (soft singleton).
- Installer `%ProgramData%` onboarding bayrağı + Tray/Background end.
- `--show-gui` / onboarding’de pencere zorunlu görünür; tray minimize engellenir.

---

# v4.4.25 — Onboarding GUI + hesap bağlantısı + self-process proof

## Non-silent kurulum
- Silent değilse pencere tray’e gizlenmez; kullanıcı token / dashboard kaydı yapabilsin.
- `force_gui_onboarding.flag` (ProgramData) + token yokken pencere zorunlu görünür.
- Token kopyala / Hesaba bağla / Dashboard açıldıktan sonra tray minimize serbest.

## Hesap / çoklu sunucu (Account)
- Üst barda **Hesaba bağla** + token kopyala (Link server talimatı).
- Tray: Dashboard aç, Hesaba bağla, Token’ı kopyala, sunucu adı.

## Self-process (HMAC)
- Her `health/report` → `agent_runtime` / `self_process` (pid, exe_path, proof).
- Kendi satır: `is_agent_self` + `self_proof`; isim taklidi → `name_spoof_candidate`.
- `kill_process` kendi PID → self-refuse (isme göre blanket protect yok).

---

# v4.4.24 — Güncelleme indirme “imha” düzeltmesi + daha sık kontrol

## Sorun
GUI “Güncellemeleri Denetle” ile indirirken uygulama kapanıyordu.

**Kök neden:** `update_in_progress.lock` kullanıcı `APPDATA` altındaydı.  
`CloudHoneypot-SilentUpdater` **SYSTEM** olarak çalışıp kilidi görmüyor → indirme ortasında `kill-honeypot` / QUIT.

## Düzeltmeler
- Kilit artık **ProgramData** (makine geneli) — GUI + SYSTEM aynı dosya
- İndirme sırasında kilit heartbeat (15 sn)
- Silent update: kilidi **indirmeden önce** alır; süreç öldürme **yalnızca indirme bitince**
- İndirme sırasında SilentUpdater + MemoryRestart + Watchdog **durdurulur**
- Sürüm kontrolü: **30 dk** (Task Scheduler SilentUpdater PT30M + in-process watchdog)
- Mevcut kurulumlarda startup’ta SilentUpdater aralığı yenilenir

## Config
```json
"updates": {
  "auto_check": true,
  "check_interval_minutes": 30
}
```

---

# v4.4.23 — Uzak masaüstü siyah ekran (RDP disconnected / input desktop)

Dashboard kanıtı (`/api/remote/status`): `has_frame:false`, `live:false` — viewer WS açık ama agent JPEG göndermiyor.

## Kök neden
RDP oturumu **Disconnected** iken (veya thread input desktop’ta değilken) GDI/ImageGrab **siyah** bitmap döner; client kareyi bilerek göndermez → dashboard “Yayın başlatılıyor…”.

## Düzeltme
- Capture thread: `OpenInputDesktop` + `SetThreadDesktop`
- Session state log (Active / Disconnected)
- Disconnected / siyah karede bir kez `tscon <sid> /dest:console` (masaüstü yeniden çizilsin)
- Probe karesini WS kuyruğuna da koy; WS bağlanınca son iyi kareyi tekrar gönder
- HTTP probe başarısızsa `frames_sent` yalan söylemesin

## Not
`tscon … /dest:console` fiziksel konsolu kısa süre agent oturumuna alabilir — uzak masaüstü için gerekli trade-off.

---

# v4.4.22 — Aylarca uptime: RAM / thread koruması

Saldırı trafiği altında sınırsız büyüyebilecek yapılar ve thread fırtınası giderildi.

## Kritik
- Honeypot rate-limiter: idle key eviction + max 10k key
- Honeypot accept: max **48** concurrent handler / servis (fazlası drop)
- `unique_ips` set: max **5000** (MemoryGuard trim)
- Alert batch: API down iken hard-cap **1000** (eski drop)
- Dedup map: hard-cap **20k** + her flush’ta temizlik
- Urgent/auto-block API raporları: bounded pool (8 worker / 64 pending)
- Auto-response `_blocks`: max **500** in-memory
- Threat IP pool LRU: blocked IP’ler de evict edilebilir
- GDI capture: `finally` ile HDC/HBITMAP sızıntısı yok; log spam azaltıldı
- FP tuner: stale IP’ler gerçekten siliniyor
- MemoryGuard: honeypot limiter + unique_ips + auto blocks kayıtlı

## Beklenen
Aylarca açık sunucuda RAM’in saldırı yoğunluğunda kontrolsüz şişmemesi; process kitlenmesi riskinin düşmesi.

---

# v4.4.21 — Daha hızlı IR (kill / logoff)

Sızma anında dashboard’dan gelen `kill_process` / `logoff_user` 10 sn poll yüzünden geç uygulanıyordu.

## Değişiklikler
- Komut poll: **10s → 1s** (`threat_detection.command_poll_interval`)
- IR komutları rate-limit dışı: kill, logoff, block_ip, disable_account, stop_service, lockdown…
- Aynı poll batch’inde kill/logoff **önce** çalışır
- Health report kill/logoff yolunu **bloklamaz** (async)
- `taskkill` / `logoff` timeout 5s

## Beklenen
Dashboard → Kill/Logoff → agent ≤ ~1 sn içinde uygular.

---

# v4.4.20 — `clear_firewall` remote command

Dashboard Hesap → Bakım “Firewall bloklarını temizle” artık `clear_firewall` kuyruğa atıyor; agent işlemezse `HP-BLOCK-*` Windows’ta kalıyordu.

## Değişiklikler
- `command_type: clear_firewall` handler (`ALLOWED_COMMANDS` + `_cmd_clear_firewall`)
- Tüm `HP-BLOCK-`, `HONEYPOT_BLOCK*`, `HONEYPOT_BLOCK_REMOTE*`, legacy prefix’leri sil
- Yerel blok cache boşalt + `sync-rules []` + `clear-data` scopes=`blocks`
- `params.ips[]` için isim şablonlarıyla yedek silme
- `priority: critical` / clear_firewall sonrası poll **≤ 2 sn**
- `DataCleanupManager` remote executor’a bağlandı

## Acceptance
- Dashboard firewall temizle → ≤ 60 sn Windows’ta honeypot block kuralı kalmaz
- `POST /api/commands/result` success + `rules_removed`

---

# v4.4.19 — RDP session=2 capture fix (err 1314)

Log örneği:
`pid_session=2 console=1` + `WTSQueryUserToken(1) failed err=1314` + `ImageGrab failed`

**Sorun:** Agent RDP oturumundayken (session 2) helper yanlışlıkla **physical console (1)** için token istiyordu → privilege yok (1314).

## Düzeltme
- Token helper **yalnızca Session 0**’da çalışır; session>0 ise atlanır
- GDI: BitBlt fail → desktop window DC; brightness log
- ImageGrab: bbox / primary / all_screens varyantları

---

# v4.4.18 — Siyah ekran: CAPTURE_NO_DESKTOP + Session 0 helper

`AGENT_REMOTE_BLACK_SCREEN_PROMPT.md` uyumu:

Kanıt (`frames_sent=0`, `screen 0×0`, `streaming=true`) için:

- **Dürüst start:** probe capture; `screen/capture` 0 veya siyah/tiny JPEG → `success:false`, `error: CAPTURE_NO_DESKTOP` (streaming yalanı yok)
- **Siyah / &lt;1500B kare gönderme** (API “Frame too small”)
- **10 sn frames_sent=0** → stream fail + stop
- **Session 0:** `CreateProcessAsUser` + `--rd-capture-once` ile interaktif session’dan JPEG
- Probe sonrası ilk HTTP keyframe hemen basılır

Acceptance: başarılı start’ta `screen.w/h > 0`, birkaç saniyede `frames_sent` artar.

---

# v4.4.17 — Uzak masaüstü siyah ekran düzeltmesi

Dashboard’da siyah görüntü için client tarafı sertleştirildi:

- **GDI BitBlt** birincil yakalama (ImageGrab yedek)
- **Session 0 / yanlış oturum** uyarısı (servis oturumunda capture çoğu zaman siyah)
- **Siyah kare tespiti** + log
- **JPEG magic** doğrulama (`FFD8…FFD9`)
- **Thread-safe WebSocket**: kareler kuyrukla WS thread’inden gönderilir (bozuk binary önlenir)
- **HTTP keyframe** her N karede (WS kopsa / proxy binary düşürse dashboard cache dolu kalsın)

Log örnekleri: `first frame ok`, `Nearly-black frame`, `Session ok`.

---

# v4.4.16 — Tam süreç listesi (Notepad++ görünür)

`AGENT_PROCESSES_FULL_LIST_PROMPT.md`:

- `top_processes` / `top_cpu_processes` artık **80–150 unique PID** (eskiden dashboard’da ~10 top-CPU)
- Birleşim: top 80 CPU + top 40 RAM + **interactive session uygulamaları** (0% CPU dahil) + şüpheli
- `top_cpu_processes` alias’ı artık kısaltılmıyor (15 satır bug’ı)
- Acceptance: Notepad++ açıkken ≤60 sn içinde dashboard listesinde

Log: `processes collected: N` / `report ok — … processes=N`

---

# v4.4.15 — Uzak masaüstü akıcı WebSocket

`AGENT_REMOTE_DESKTOP_PROMPT.md` uyumu:

- **WebSocket birincil:** `wss://…/ws/remote/agent?token=` — hello + meta JSON + binary JPEG
- **HTTP fallback:** `POST /api/remote/frame` + `GET /api/remote/inputs` (~300 ms) WS yokken
- Hedef **~6 fps** (max 10), JPEG q≈35, kare ≤ ~320 KB
- Girdi: `mousedown` / `move` / `mouseup` (sürükle), `wheel`, `click`, `dblclick`, `type_text`, `key`
- UI rozeti: WebSocket (yeşil) / HTTP fallback (turuncu)

---

# v4.4.14 — Uzak masaüstü durum paneli

- Tehdit sekmesinde **Uzak Masaüstü** kartı: Hazır / Yayın aktif / Kullanılamıyor
- FPS, çözünürlük, kare/girdi sayıları; yayın başlayınca toast
- Yerel **Durdur** (acil kesim) — başlatma yalnızca Dashboard’dan
- Repo: `DASHBOARD_CLEANUP_API_PROMPT.md` (temizlik API dashboard prompt’u)

---

# v4.4.13 — Login’liyken oturum raporu hiç başlamıyordu

**Kök neden:** `CloudHoneypot-Background` (`--mode=daemon`) kullanıcı oturumu görünce GUI’ye geçiyor ama `start_delayed_api_sync()` çağrılmıyordu. Tray de cmdline’da `--mode=daemon` görüp health’i atlıyordu → **kimse `active_sessions` göndermiyordu**.

## Düzeltme
- Daemon→GUI (logon) path’inde `start_delayed_api_sync()` eklendi
- Tray UI-only health fallback (4.4.12) + daemon health (4.4.11) korunuyor

---

# v4.4.12 — Tray UI-only da oturum raporlasın

v4.4.11 daemon’a HealthMonitor ekledi; pratikte tray hâlâ “daemon var” deyip health’i atlıyor, daemon logu da görünmeyebiliyor → oturum yine gitmiyordu.

## Düzeltme
- Tray UI-only: ServiceManager/firewall atlanır, **HealthMonitor + RemoteCommands mutlaka başlar**
- Daemon path (4.4.11) korunur
- Log: `Faz 3 started (tray-ui: …)` + `report ok — sessions=N`

---

# v4.4.11 — Aktif oturumlar daemon’da raporlanmıyordu

**Sorun:** Daemon + Tray (UI-only) mimarisinde `HealthMonitor` hiç başlatılmıyordu. Tray “daemon halleder” diye atlıyor, daemon ise health/sessions kodunu hiç çalıştırmıyordu. Sonuç: giriş yapmış olsanız bile dashboard’da **Aktif Bağlı Kullanıcılar = 0**.

## Düzeltme
- `run_daemon()` artık Threat + RemoteCommands + **HealthMonitor** başlatıyor
- İlk health report hemen gönderiliyor (`force_report`)
- Log: `report ok — sessions=N processes=M`

---

# v4.4.10 — Güncelleme indirme yarış durumu düzeltmesi

**Sorun:** "Güncellemeleri Denetle" ile indirme ~%20–%25 iken tüm client örnekleri kapanıyor, indirme yarıda kesiliyordu.

**Kök neden:** `CloudHoneypot-SilentUpdater` (veya saatlik watchdog) kendi indirmesini bitirince `prepare_client_for_installer()` çağırıp QUIT + `kill-honeypot.ps1` ile **tüm** `honeypot-client` süreçlerini öldürüyordu — GUI indirmesi de dahil.

## Düzeltmeler
- İndirme sırasında `update_in_progress.lock` kilidi
- Silent updater / watchdog kilit varken atlanır
- İndirme başında yalnızca SilentUpdater/Updater görevleri durdurulur (Background/Tray öldürülmez)
- Süreç kill yalnızca installer kullanıcı tarafından başlatılınca
- Installer önce `Start-Process`, sonra kill (Start-Process kaçmasın)

---

# v4.4.9 — Uzak Masaüstü (ekran aynası MVP)

Dashboard **Koruma → Uzak Masaüstü** için agent tarafı.

## Komutlar
- `remote_stream_start` — JPEG capture loop (fps/quality/max_width)
- `remote_stream_stop` — yayını kes
- `remote_input` — click / dblclick / type_text / key

## Upload
- `POST /api/remote/frame` (multipart `file`)
- Fallback: `POST /api/remote/frame-json` (base64)

## Güvenlik / limit
- Yayın yalnızca komut sonrası
- 5 dk idle (input yok) → otomatik stop
- Input rate limit ~20/sn
- `ctrl+alt+del` OS tarafından engelli (atlanır)

## Acceptance
- [x] start → frame upload
- [x] click / type_text
- [x] stop
- [x] Pillow ImageGrab (user session desktop)

---

# v4.4.8 — V4 update gaps + sessions/processes + stale blocks

## CLIENT_V4_UPDATE_PROMPT — kapatılan boşluklar

| Madde | Önce | Şimdi |
|--------|------|--------|
| Commands poll | 5s | **10s** |
| events/batch | 60s / max 50 / zayıf summary | **120s / 500** + category + full summary; fail’de buffer korunur |
| Urgent | fire-forget | **3 retry / 30s** + `actions_requested` |
| Urgent cooldown | critical 60s | **5 dk** (threat_type+IP) |
| Config sync | 2 dk | **5 dk** + auto_block limits + channels |
| Health report | const 300 (runtime 60) | **60** |
| Canary check | 10s | **30s** + config paths |
| Remote cmds | eksik start/restart / lockdown alias | **eklendi** |
| Protected accounts | SYSTEM… | + **ADMINISTRATOR** |
| Silent hours TZ | local | **Europe/Istanbul** (zoneinfo) |

## Önceki 4.4.8 işleri (aynı sürüm)

- `active_sessions` + zengin `top_processes`
- `pending-unblocks` batch ACK
- Bakım/temizlik menüsü (clear-data)

## Kalan riskler

- Event channel değişince subscription restart gerekir (uygulandı)
- `signed`/WinVerifyTrust hâlâ yok (opsiyonel)
- Canary Public Desktop yolu görünür olabilir — config’ten kapatılabilir

---

# v4.4.7 — Bakım / Temizlik (local + firewall + dashboard)

## Özet

Dashboard’da eski saldırı/KPI verisi kalmasın diye istemci **yerel + firewall + sunucu** temizliğini sırayla destekler. Ayarlar menüsünden çalıştırılır; otomatik limitler arka planda HP-BLOCK kural sayısını ve IP havuzunu sınırlar.

## Client

- `DataCleanupManager` (`client_cleanup.py`)
  - Yerel: IP pool, session stats, alert dedup, `threats.log`
  - Firewall: tüm `HP-BLOCK-*` + `sync-rules([])` + `clear-data` scopes=`blocks`
  - Sunucu: `POST /api/agent/clear-data`
  - Tam bakım: local → firewall → server
- Ayarlar menüsü: 4 temizlik eylemi + onay diyalogları
- Auto limit: max 500 firewall kuralı, max 8000 IP pool (`cleanup.*` config)

## Backend (zorunlu — dashboard temizliği için)

Detay: [`API_CLEAR_DATA_PROMPT.md`](API_CLEAR_DATA_PROMPT.md)

```
POST /api/agent/clear-data
{ "token", "scopes": ["attacks","blocks","alerts","threat_summary","all"], "reason" }
```

`POST /api/agent/sync-rules` boş `blocks: []` ile **replace** (listeyi sıfırla).

Endpoint yoksa client yerel/firewall temizliği yine yapılır; sunucu adımı kullanıcıya uyarı döner.

---

# v4.4.6 — Installer process kill fix

Self-protection DACL + `HoneypotClientGuard` görevi installer'ın `taskkill`'ini engelliyordu / yeniden başlatıyordu.

## Düzeltmeler
- **QUIT control socket:** Installer önce `127.0.0.1:58632` üzerinden `QUIT` gönderir — süreç kendini kapatır (DACL bypass)
- **SeDebugPrivilege kill:** `scripts/kill-honeypot.ps1` ile admin TerminateProcess (DACL'yi aşar)
- **HoneypotClientGuard:** Task Scheduler temizliği artık `HoneypotClient*` wildcard'ını da siler
- **Stop flags:** `CloudHoneypotClient\watchdog.token` dahil tüm watchdog yolları

---

# v4.4.5 — API sözleşme hizalaması (dashboard sync)

AGENT_CLIENT_REVIEW_PROMPT.md referans alınarak üretim loglarındaki uyumsuzluklar giderildi.

## Düzeltmeler

| # | Sorun | Düzeltme |
|---|--------|----------|
| 1 | Auto-block path `v4/auto-block` | Kanonik `POST /api/alerts/auto-block` |
| 2 | Urgent `auto_response` / float score | `auto_response_taken: string[]`, `threat_score: int`, ISO timestamp |
| 3 | Attack payload | `ip` alias eklendi; credential → urgent'e password aktarımı |
| 4 | Health field adları | `disk_io_*_bytes_sec`, `network_bytes_*_sec`, `open_connections` |
| 5 | Tunnel status | `listen_port` + `port` birlikte gönderiliyor |
| 6 | events/batch | `batch_id` + kanonik event şeması |
| 7 | API 422 | Schema `detail` loglanıyor; 2xx kabul |
| 8 | Open ports | `process` adı (pid üzerinden) |
| 9 | Installer kill | 5 turlu watchdog-safe process kill |

## Breaking changes
Yok — sunucu toleranslı alias'lar korunuyor; client kanonik forma geçti.

---

# v4.4.4 — Sidebar hizalama

- **Sidebar nav:** İkon + metin düzeni sabitlendi (sabit ikon sütunu, metin sütunu)
- **Tema değişkenleri:** Sidebar layout değerleri `client_gui_theme.py` içine taşındı (design tokens)

---

# v4.4.3 — GUI, API & güncelleme akışı

- **API bağlantı:** GET isteklerinde `?token=` query parametresi artık her zaman ekleniyor
- **Dashboard link:** `?token={full_token}` formatına geri döndü
- **Sidebar:** Nav butonları hizalı container içinde yeniden düzenlendi
- **Güncelleme UX:** İlerleme penceresi anında açılır; installer indirme sonrası kullanıcı onayıyla başlar
- **Installer:** Çalışan client örnekleri kurulum başında hızlıca kapatılır

---

# v4.4.2 — Auto-update fix

- Silent updater now uses `installer_url` from GitHub API (was broken: looked for `download_url`)
- Weekly updater Task Scheduler task fixed (`--silent-update-check` instead of invalid `--mode=updater`)

**Note:** Clients on v4.4.0/v4.4.1 need one manual update (GUI → Güncellemeleri Denetle) to receive this fix; after that auto-update works every 2 hours.

---

# v4.4.1 — Tray, Performance & Debug

**Date:** 2026-07-08

## Tray
- Thread-safe `show_window()` / `minimize_to_tray()` (Tk main thread)
- Windows `SetForegroundWindow` for reliable foreground focus
- Removed session health auto-hide (prevented reopen from tray)
- `TrayManager.notify()` for alert balloons

## Performance
- Dashboard refresh: 10s default (config: `ui.dashboard_refresh_seconds`)
- Lazy security intel: scans only when Threat Center tab is active
- IP table refresh only on Dashboard tab
- `FalsePositiveTuner.start()` periodic cleanup loop
- Non-blocking CPU sampling in PerformanceOptimizer

## Debug
- `--debug` CLI flag (verbose logs, skip consent, skip admin elevation)
- `debug.*` config section unified with `logging.debug_mode`
- DEBUG badge in title bar when active

## Watchdog
- Restart with `--show-gui` so window is visible after crash recovery

---

# v4.4.0 — Security, Honeypots & Modern UI

**Date:** 2026-07-08

## Security
- TLS certificate verification enabled by default (`api.tls_verify`)
- Bearer token in `Authorization` header; legacy query param optional
- Log redaction for tokens and passwords
- HMAC command signing for remote commands
- `SECURITY.md` added

## Features
- HTTP honeypot (login form decoy, port 80)
- SMB honeypot (minimal negotiate probe, port 445)
- Configurable `services.bind_address`
- Webhook notifications (`notifications.webhook_url`)
- Installer SHA-256 verification option

## UI
- Sidebar navigation (replaces tabs)
- New slate/emerald design system (`client_gui_theme.py`)
- Wider default window (1100×720)

## Quality
- Unit tests (`tests/`)
- GitHub Actions CI
- Pre-commit secret check script
- `OPERATIONS.md` deployment guide

## Migration
1. Update `client_config.json` or reinstall (config merged on upgrade)
2. Revoke old tokens if `client.log` was exposed
3. Backend: enable Bearer auth when ready; set `api.legacy_token_query: false`

---

# v4.0.7 — Auto-Response Fix: Honeypot Attackers Now Auto-Blocked

**Release Date:** 2025-01-20
**Priority:** 🔴 Critical Fix

## Problem

Honeypot saldırganları tespit ediliyor ve dashboard'da görünüyordu ama:
- Windows Firewall'a blok kuralı **eklenmiyordu**
- API'ye saldırı IP'si **bildirilmiyordu**
- Saldırgan engellenmeden bağlantılarına devam edebiliyordu

## Root Causes

### 1. Standalone Alert — Empty Auto-Response
`ThreatEngine.process_event()` içinde honeypot credential 90 skor alıyor (critical) ama standalone alert dalı `auto_response=[]` gönderiyordu. AlertPipeline boş auto_response görünce `block_ip` çağırmıyordu.

**Fix:** `honeypot_credential` event'leri veya `critical` severity durumlarında `auto_response = ["block_ip", "notify_urgent"]` set ediliyor.

### 2. Score Degradation — FAILED_LOGON_TYPES Bug
`honeypot_credential` yanlışlıkla `FAILED_LOGON_TYPES` set'ine eklenmişti. 10+ honeypot hit'inde burst detection tetikleniyor ve skor 90'dan 40'a **düşürülüyordu** (warning seviyesine → auto_response tetiklenmiyordu).

**Fix:** `honeypot_credential` artık `FAILED_LOGON_TYPES`'ta değil. Her honeypot hit sabit 90 skor alıyor.

### 3. Event Field Mapping — target_service/target_port
Honeypot credential event'leri `service` ve `port` key'lerini kullanıyordu ama `_emit_alert` ve `IPContext.add_event` sadece `target_service` ve `target_port` arıyordu. Alert'lerde servis/port bilgisi boş kalıyordu.

**Fix:** Fallback eklendi: `event.get("target_service", "") or event.get("service", "")`

### 4. Missing Alert Title
`_build_title` içinde `honeypot_credential` event type'ı için title tanımlı değildi.

**Fix:** `"honeypot_credential": "🍯 Honeypot Credential Captured"` eklendi.

## Changed Files

| File | Change |
|------|--------|
| `client_threat_engine.py` | Standalone alert auto_response fix, FAILED_LOGON_TYPES fix, field mapping fallback, honeypot title |
| `client_constants.py` | VERSION → 4.0.7 |

## Expected Behavior After Fix

1. **İlk honeypot hit:** Skor 90 → severity `critical` → `auto_response=["block_ip", "notify_urgent"]`
2. **AlertPipeline:** `_execute_auto_response` → `AutoResponse.block_ip()` → Windows Firewall inbound block rule
3. **API:** `POST /api/alerts/urgent` + `POST /api/alerts/auto-block` ile bildirim
4. **3+ hit (10 dk içinde):** `honeypot_brute_force` correlation rule → aynı blok aksiyonu
5. **Skor 90'da sabit kalıyor** — burst logic'e takılmıyor

## Test Checklist
- [ ] Honeypot'a bağlanan ilk IP anında firewall'a bloklanmalı
- [ ] Dashboard'da "🍯 Honeypot Credential Captured" alert görünmeli
- [ ] API'de alerts/urgent ve alerts/auto-block endpoint'lerine bildirim gitmeli
- [ ] Tekrarlayan saldırılarda skor 40'a düşmemeli

---

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

---

# 🚀 Cloud Honeypot Client v3.1.0 - UI Polish & Reliability

**Release Date:** February 8, 2026

## 🎨 GUI Improvements

### Dark Mode & Layout
- **Unified top bar**: PC/IP, Token, version, Dashboard, Settings, Help — all in one compact row
- **Custom dark popup menus**: Settings and Help dropdowns now use CTkToplevel dark popups instead of tk.Menu
- **Popup toggle fix**: Menus now properly reopen after first use (replaced FocusOut with global click-away)
- **Service card icon alignment**: Fixed RDP/MSSQL icon extra spacing caused by emoji variation selectors
- **Fixed icon widths**: All service cards now have consistent icon column width (30px, centered)

### Protection Status
- **Accurate header badge**: "Koruma Aktif" (green) shows immediately on startup when services are running — no more 5-second delay
- **Faster pulse blink**: Status dot now blinks every 800ms (was 5 seconds tied to dashboard refresh)

## 🔄 Service Auto-Restore

- **Persistent service state**: Services that were running before app close/update are now automatically restarted on next launch
- **Background restore**: Services restart in a background thread so GUI doesn't freeze
- **Consent-aware**: Auto-restore only activates if user consent is accepted
- **Per-service logging**: Each restored service logs success/failure individually

## 🌐 API Connection Status

- **Real-time tracking**: Dashboard "API Connection" card now reflects actual API call success/failure (`_last_api_ok` flag)
- **Instant disconnect detection**: If API becomes unreachable, status switches to "Disconnected" (red) within one polling cycle
- **No false positives**: Previously showed "Connected" forever after first successful call

## 📦 Installer Improvements

### Finish Page
- **Launch checkbox**: "Launch Cloud Honeypot Client now" checkbox on finish page (checked by default)
- **De-elevated launch**: App launches as current user (not admin) via `explorer.exe` — prevents session/elevation issues
- **No ghost window**: Fixed issue where GUI would flash and disappear into tray after install

### Encoding Fix
- **ASCII-safe finish page**: Replaced Turkish characters with English text in NSIS finish page (NSIS processes .nsi as ACP/ANSI, corrupting Turkish chars like ı, ş, ü, ö, ç, ğ)

## 🐛 Bug Fixes

| Issue | Fix |
|-------|-----|
| Popup menu won't reopen after first use | Replaced `<FocusOut>` with global `<Button-1>` + `_active_popup` tracking |
| Header shows "Koruma Pasif" despite active services | Set header status immediately after service cards build |
| All services reset on every GUI startup | Replaced `write_status([], False)` with `_restore_saved_services()` |
| API status always "Connected" after first success | Track `_last_api_ok` per API call, update dashboard in real-time |
| Installer finish page Turkish chars corrupted | Use English-only text for NSIS finish page defines |
| App launches as admin from installer | Use `explorer.exe` for de-elevated launch via custom NSIS function |
| RDP/MSSQL service card icons misaligned | Remove variation selectors from emojis + fixed 30px icon width |

## 📋 Technical Details

- **Commits**: 7 commits in this release
- **Files changed**: `client_gui.py`, `client.py`, `installer.nsi`, `client_constants.py`
- **Compatibility**: Windows 10/11, Python 3.12.6, CustomTkinter 5.2.2

---

# 🚀 Cloud Honeypot Client v2.8.5 - Performance Optimized

**Release Date:** December 8, 2025

## 📊 Performance Improvements

Bu sürüm uygulamanın performansını ve akıcılığını önemli ölçüde artıran kapsamlı optimizasyonlar içerir.

### 🔴 Kritik İyileştirmeler

| Sorun | Çözüm | İyileştirme |
|-------|-------|-------------|
| Attack count için her 10sn'de yeni thread | Thread reuse sistemi | **~8,640 thread/gün tasarrufu** |
| File heartbeat her 10sn I/O | 60sn'ye optimize edildi | **%83 dosya I/O azaltma** |
| `gc.collect()` GUI thread'inde | Kaldırıldı | **50-200ms donmalar önlendi** |
| HEARTBEAT_INTERVAL çift tanım | FILE/API olarak ayrıldı | **Bug düzeltildi** |

### 🟡 Orta Öncelikli İyileştirmeler

| Sorun | Çözüm | İyileştirme |
|-------|-------|-------------|
| Public IP her 60sn HTTP çağrısı | 5 dakika cache sistemi | **%80 HTTP azaltma** |
| İki ayrı tunnel loop (sync + watchdog) | Tek loop'a birleştirildi | **1 thread tasarrufu** |
| GUI IP güncelleme spam | Sadece değişince güncelle | **Gereksiz render önlendi** |
| Log spam | Sadece önemli olaylar | **I/O azaltma** |

### 🐛 Bug Fixes

- **Tray Mode Bug**: Tray modunda pencere kendiliğinden açılma sorunu düzeltildi
- `minimized_to_tray` flag sistemi eklendi
- `refresh_gui()` artık tray moduna saygı gösteriyor

## 📈 Optimizasyon Metrikleri

| Metrik | v2.8.4 | v2.8.5 | İyileştirme |
|--------|--------|--------|-------------|
| Thread oluşturma/gün | ~8,640 | ~0 | **%100** |
| Dosya I/O/gün | ~17,280 | ~1,440 | **%92** |
| HTTP IP çağrısı/gün | 1,440 | 288 | **%80** |
| GUI health check | 30sn | 60sn | **%50** |
| Attack count poll | 10sn | 15sn | **%33** |
| Dashboard sync | 30sn | 45sn | **%33** |

## ⏱️ Yeni Timing Değerleri

```python
FILE_HEARTBEAT_INTERVAL = 60    # (was 10s)
API_HEARTBEAT_INTERVAL = 60     # API heartbeat
ATTACK_COUNT_REFRESH = 15       # (was 10s)
DASHBOARD_SYNC_INTERVAL = 45    # (was 30s)
DASHBOARD_SYNC_CHECK = 10       # (was 5s)
WATCHDOG_INTERVAL = 15          # (was 10s)
IP_CACHE_DURATION = 300         # 5 min (NEW)
```

## 🔄 Otomatik Güncelleme

Client'ler bu sürümü otomatik olarak alacaktır:

- **GUI/Tray Mode**: Her 1 saatte bir güncelleme kontrolü
- **Daemon Mode**: Task Scheduler ile her 2 saatte bir (oturum açık olmasa bile)
- **Silent Update**: Arka planda sessiz güncelleme desteği

## 📦 Modül Güncellemeleri

- `client_helpers.py`: IP cache sistemi eklendi
- `client_networking.py`: Tunnel loop'lar birleştirildi
- `client_constants.py`: Timing sabitleri optimize edildi
- `client.py`: GUI refresh ve tray mode iyileştirmeleri

## ⬆️ Upgrade Notes

Bu sürüm geriye dönük uyumludur. Mevcut kurulumlar otomatik olarak güncellenir.

---

**Full Changelog**: v2.8.4...v2.8.5

