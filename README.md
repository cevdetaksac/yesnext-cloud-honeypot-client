Cloud Honeypot Client
=====================

Cloud Honeypot Client; belirlediğiniz servis portlarını güvene alıp ters tünel üzerinden Honeypot servisine ileten, tepside (tray) çalışan bir Windows istemcisidir. Açık kaynak geliştirilir; sunucu/dashboard tarafındaki gelişmiş özellikler ayrıca lisanslanabilir.

Özellikler
- Ters tünel: Seçili portları TLS üzerinden sunucuya taşır.
- RDP koruma: RDP portunu 3389 → 53389 taşıma ve geri alma akışı.
- Kalıcılık: İsteğe bağlı Görev Zamanlayıcı ile açılışta çalışma.
- Kalp atışı ve saldırı sayacı: API ile haberleşme.
- Kullanıcı onayı: Açılışta görünür onay ve tercihler.
- Dil desteği: Türkçe ve İngilizce; uygulama içinden değiştirilebilir.
- Otomatik güncelleme: GitHub Releases üzerinden yeni sürümü indirip kendini günceller (SHA256 doğrulaması destekli).

Derleme
- Gereksinimler: Python 3.11/3.12, pip, PyInstaller
- Tek komut: `powershell -ExecutionPolicy Bypass -File scripts/build.ps1`
- Çıktı: `dist/client.exe`

İmzalama (isteğe bağlı)
- Üretim için OV/EV Code Signing sertifikası önerilir.
- Geliştirme için self-signed PFX ile imza atabilirsiniz:
  - `scripts/sign.ps1 -File dist\client.exe -PfxPath C:\certs\codesign.pfx -PfxPassword PAROLA`
- `scripts/build-and-sign.ps1` uçtan uca derleme+imzalama yapar.

Otomatik Güncelleme
- Uygulama açılışında veya menüden “Güncellemeleri Denetle” ile GitHub Releases’ı kontrol eder.
- Yeni sürüm bulursa indirir, SHA256 dosyası varsa doğrular; onayla birlikte kendini günceller.
- Repo bilgisi `client.py` içinde `GITHUB_OWNER`/`GITHUB_REPO` ile yapılandırılır.

Sürümleme
- SemVer: `__version__` değişkeni üzerinden.
- Dağıtımlar GitHub Releases ile etkinleştirilir (bkz: `.github/workflows/release.yml`).

Katkılar
- Lütfen CONTRIBUTING.md ve CODE_OF_CONDUCT.md belgelerini inceleyin.

Güvenlik
- Güvenlik açıklarını kamuya açık issue yerine SECURITY.md’teki kanallardan bildirin.

Lisans
- Apache-2.0 Lisansı (LICENSE dosyasına bakın).

