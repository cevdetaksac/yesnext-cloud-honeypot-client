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
