# RDP'yi 3389 portuna geri döndür (popup testi için)
# Admin olarak çalıştırın

Write-Host "RDP portunu 3389'a geri döndürüyor..."

# Registry değerini değiştir
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber" -Value 3389

# Terminal Service'i yeniden başlat
Write-Host "Terminal Service yeniden başlatılıyor..."
Restart-Service -Name "TermService" -Force

Write-Host "RDP şimdi 3389 portunda. Popup testi için hazır!"
Write-Host "GUI'dan RDP satırını seçip 'Start' butonuna basabilirsiniz."