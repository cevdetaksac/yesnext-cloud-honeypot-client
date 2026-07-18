# v4.5.4 — TLS CA / guncelleme alert duzeltmesi

**Sorun:** PyInstaller `Temp\_MEI*\certifi\cacert.pem` yolu RDP/TEMP temizliginde kaybolunca:
- API "Baglanti Yok"
- Guncelleme kontrolu kirmizi alert: `Could not find a suitable TLS CA certificate bundle`

**Cozum:**
- `cacert.pem` ProgramData altina kalici kopyalanir
- `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` bu yola isaret eder
- Runtime hook + `resolve_tls_verify()` her HTTPS cagrisinda gecerli bundle kullanir
- GitHub update check/download `verify=` ile ayni bundle'i kullanir
