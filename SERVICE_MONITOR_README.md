# Honeypot Monitor Service

Windows hizmeti olarak çalışan basit ve güvenilir watchdog uygulaması.

## 🎯 Amaç

Ana Honeypot Client uygulamasını sürekli izler ve gerektiğinde yeniden başlatır:
- ✅ Ana uygulama çöktüğünde otomatik restart
- ✅ Mükerrer çalıştırma önleme 
- ✅ PID tabanlı süreç takibi
- ✅ Configurable restart limitleri
- ✅ Minimal resource kullanımı

## 🚀 Kurulum

### Otomatik Kurulum (Önerilen)
```bash
# Yönetici olarak çalıştırın
install_monitor_service.bat
```

### Manuel Kurulum
```bash
# 1. Gerekli paketleri yükle
pip install psutil pywin32

# 2. Servisi yükle
python service_monitor.py install

# 3. Servisi başlat  
python service_monitor.py start
```

## 🛠️ Yönetim Komutları

```bash
# Servis kontrolü
python service_monitor.py start    # Başlat
python service_monitor.py stop     # Durdur  
python service_monitor.py restart  # Yeniden başlat
python service_monitor.py remove   # Kaldır

# Durum kontrolü
check_monitor_status.bat           # Detaylı durum
sc query HoneypotClientMonitor     # Hızlı durum
```

## 📁 Dosya Yapısı

```
service_monitor.py              # Ana servis kodu
install_monitor_service.bat     # Kurulum scripti  
remove_monitor_service.bat      # Kaldırma scripti
check_monitor_status.bat        # Durum kontrol scripti
monitor.log                     # Servis log dosyası (otomatik)
monitor_status.json             # Durum dosyası (otomatik)
```

## ⚙️ Konfigürasyon

`service_monitor.py` içinde düzenlenebilir ayarlar:

```python
CHECK_INTERVAL = 30         # Kontrol sıklığı (saniye)
RESTART_DELAY = 5          # Restart öncesi bekleme
MAX_RESTART_ATTEMPTS = 3   # Saatte max restart sayısı  
RESTART_WINDOW = 3600      # Restart sayma penceresi
```

## 📊 İzleme

### Log Dosyası
`monitor.log` - Servis aktivitelerini içerir:
```
2025-09-25 21:15:30,123 [INFO] Client running: PID 1234
2025-09-25 21:16:00,456 [WARNING] Client not running, attempting restart
2025-09-25 21:16:05,789 [INFO] Client started successfully: PID 5678
```

### Durum Dosyası  
`monitor_status.json` - Anlık durum bilgisi:
```json
{
  "pid": 1234,
  "last_check": 1695661800.123,
  "restart_count": 2
}
```

## 🔧 Sorun Giderme

### Servis Başlamıyor
```bash
# 1. Admin yetkileri kontrol et
net session

# 2. Python ve paket kurulumlarını kontrol et
python --version
pip list | findstr psutil
pip list | findstr pywin32

# 3. Manuel başlatma test et
python service_monitor.py debug
```

### Ana Uygulama Restart Edilmiyor
1. `client.exe` veya `client.py` dosyalarının varlığını kontrol edin
2. Ana uygulama crash sebeplerini kontrol edin
3. Restart limitine ulaşmış olabilir (saatte 3)

## 🛡️ Güvenlik

- Servis minimal yetkilerle çalışır
- Ana uygulamadan tamamen bağımsız
- Restart rate limiting ile DoS koruması
- Process isolation

## 📈 Performans

- ~1MB RAM kullanımı  
- CPU kullanımı: %0.1'den az
- 30 saniye kontrol periyodu
- Lazy logging (sadece önemli olaylar)

---

**Not**: Bu servis sadece ana uygulamayı izler, kendisi honeypot işlevi görmez.