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
