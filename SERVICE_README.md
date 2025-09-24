# Cloud Honeypot Client - Windows Service

Bu Windows servisi, Cloud Honeypot Client uygulamasının sürekli çalışmasını sağlar. Sistem resetlendiğinde veya uygulama beklenmedik şekilde kapandığında otomatik olarak yeniden başlatır.

## 🚀 Kurulum

### Otomatik Kurulum (Önerilen)
```batch
# Admin olarak çalıştırın:
install_service.bat
```

### Manuel Kurulum
```cmd
# Admin olarak PowerShell/CMD açın:
python install_service.py install
```

## 🛠️ Yönetim Komutları

```cmd
# Servis durumunu kontrol et
python install_service.py status

# Servisi başlat
python install_service.py start

# Servisi durdur  
python install_service.py stop

# Servisi yeniden başlat
python install_service.py restart

# Servisi kaldır
python install_service.py uninstall
```

## 📋 Servis Özellikleri

- **Otomatik Başlatma**: Windows başladığında otomatik çalışır
- **Akıllı İzleme**: Her 30 saniyede honeypot-client.exe'nin çalışıp çalışmadığını kontrol eder
- **Güvenli Yeniden Başlatma**: Çok sık restart denemelerini engeller (cooldown sistemi)
- **Yapılandırma Takibi**: Config dosyasından autostart ayarlarını okur
- **Detaylı Loglama**: `%PROGRAMDATA%\YesNext\CloudHoneypotClient\service.log`

## 🔍 Servis Ne Zaman Client'ı Başlatır?

Servis aşağıdaki durumlarda honeypot client'ını başlatır:

1. **status.json dosyasında aktif tunnel var**
2. **client_config.json'da autostart=true**  
3. **Windows Registry'de autostart kayıtlı**

## 📍 Log Dosyaları

- **Servis Logları**: `%PROGRAMDATA%\YesNext\CloudHoneypotClient\service.log`
- **Windows Event Logs**: Windows Services → Cloud Honeypot Client Monitor
- **Client Logları**: Normal client log konumları

## 🔧 Sorun Giderme

### Servis Başlamıyor
1. Admin yetkileriyle kurulduğundan emin olun
2. Python'ın PATH'te olduğunu kontrol edin
3. Log dosyasını kontrol edin

### Client Sürekli Restart Yapıyor
1. Client executable'ının bulunduğunu kontrol edin
2. Config dosyalarının doğru olduğunu kontrol edin  
3. Firewall/Antivirus engellemelerini kontrol edin

### Performans Sorunları
- Servis minimal kaynak kullanır (30 saniyelik check interval)
- Log dosyası otomatik rotate edilir (max 10MB, 5 backup)
- Background service olarak çalışır

## 🛡️ Güvenlik

- Servis SYSTEM hesabı altında çalışır
- Client uygulaması interactive session'da başlar (tray erişimi için)
- Minimum yetkilerle çalışır
- Sadece kendi process'lerini yönetir

## 📖 Örnek Kullanım

```cmd
# 1. Servisi kur ve başlat
install_service.bat

# 2. Durumu kontrol et
python install_service.py status

# 3. Gerekirse yeniden başlat  
python install_service.py restart

# 4. Kaldırmak için
uninstall_service.bat
```

Bu servis sayesinde honeypot client uygulamanız kesintisiz çalışacak ve sistem yeniden başlatıldığında otomatik olarak devreye girecektir.