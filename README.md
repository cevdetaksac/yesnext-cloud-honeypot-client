Cloud Honeypot Client
=====================

Cloud Honeypot Client; belirlediğiniz servis portlarını güvene alıp ters tünel üzerinden Honeypot servisine ileten, tepside (tray) çalışan bir Windows istemcisidir. Açık kaynak geliştirilir; sunucu/dashboard tarafındaki gelişmiş özellikler ayrıca lisanslanabilir.

Özellikler
- Ters tünel: Seçili portları TLS üzerinden sunucuya taşır.
- RDP koruma: RDP portunu 3389 ↔ 53389 taşıma ve geri alma akışı.
- Kalıcılık: İsteğe bağlı Görev Zamanlayıcı ile açılışta çalışma.
- Kalp atışı ve saldırı sayacı: API ile haberleşme.
- Kullanıcı onayı: Açılışta görünür onay ve tercihler.
- Dil desteği: Türkçe ve İngilizce; uygulama içinden değiştirilebilir.
- Otomatik güncelleme: GitHub Releases üzerinden yeni sürümü indirip kendini günceller (SHA256 doğrulaması destekli).
- Firewall Agent: Dashboard’tan verilen IP/CIDR/ülke bloklarını (Windows/Linux) yerel firewall’a uygular, kaldırmaları da takip eder.

Firewall Agent (Yeni)
- Kural adı: `HP-BLOCK-<id>`
- Windows: `netsh advfirewall firewall add rule ... action=block remoteip=<CIDR>`; büyük listelerde otomatik parçalama.
- Linux: Tercihen `ipset` + `iptables -m set` (fallback: `iptables` + `comment`).
- Ülke blokları: Varsayılan kaynak ipdeny.com (`https://www.ipdeny.com/ipblocks/data/countries/<cc>.zone`), günlük cache.
- Konfig: `API_BASE`, `TOKEN`, `CIDR_FEED_BASE` (opsiyonel), `REFRESH_INTERVAL_SEC` (varsayılan 10s).
- Uygulama: `client.py`, arkaplanda `firewall_agent.py`’yi otomatik başlatır.

Derleme
- Gereksinimler: Python 3.11/3.12, pip, PyInstaller
- Onedir paket (önerilen dağıtım): `powershell -ExecutionPolicy Bypass -File scripts/build-onedir.ps1`
  - Çıktılar: `dist/client-onedir/`, `dist/client-onedir.zip`, `dist/hashes.txt`
- Tek dosya (isteğe bağlı): `powershell -ExecutionPolicy Bypass -File scripts/build.ps1`
  - Çıktı: `dist/client.exe`

İmzalama (isteğe bağlı)
- Üretim için OV/EV Code Signing sertifikası önerilir.
- Geliştirme için self-signed PFX ile imza atabilirsiniz:
  - `scripts/sign.ps1 -File dist\client.exe -PfxPath C:\certs\codesign.pfx -PfxPassword PAROLA`
- `scripts/build-and-sign.ps1` uçtan uca derleme+imzalama yapar.

Otomatik Güncelleme
- Uygulama açılışında veya menüden "Güncellemeleri Denetle" ile GitHub Releases’ı kontrol eder.
- Yeni sürüm bulursa `client-onedir.zip`’i indirir; `hashes.txt` varsa SHA256 doğrular; onayla birlikte kendini günceller.
- Repo bilgisi `client.py` içinde `GITHUB_OWNER`/`GITHUB_REPO` ile yapılandırılır.

CI/CD ve Release
- GitHub Actions workflow: `.github/workflows/release.yml`
- Tetikleyici: `v*` etiketi push edildiğinde çalışır.
- Üretilen ve release’a yüklenen dosyalar:
  - `dist/client-onedir.zip`
  - `dist/hashes.txt`
  Bu isimler istemcinin otomatik güncelleme mekanizması tarafından beklenir.

Sürümleme
- SemVer: `__version__` değişkeni üzerinden.
- Dağıtımlar GitHub Releases ile etkinleştirilir (bkz: `.github/workflows/release.yml`).

Katkılar
- Lütfen CONTRIBUTING.md ve CODE_OF_CONDUCT.md belgelerini inceleyin.

Güvenlik
- Güvenlik açıklarını kamuya açık issue yerine SECURITY.md’teki kanallardan bildirin.

Lisans
- Apache-2.0 Lisansı (LICENSE dosyasına bakın).

Kullanım (Windows)
- `client-onedir.zip`’i release sayfasından indirin ve bir klasöre çıkarın.
- `client-onedir.exe`’yi yönetici olarak çalıştırın.
- İlk açılışta token’ı girin; firewall agent arka planda otomatik başlar.

Notlar
- Ülke CIDR feed’i varsayılan ipdeny.com’dur; istenirse `CIDR_FEED_BASE` ile değiştirilebilir.
- Firewall komutları için Windows’ta Administrator, Linux’ta root yetkisi gerekir.

