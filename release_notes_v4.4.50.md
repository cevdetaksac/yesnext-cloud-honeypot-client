# v4.4.50 — Port izleme ≠ honeypot bait

- Header/tray: honeypot kapalıyken bile EventLog/threat açıksa **Port İzleme Aktif**
- Gerçek port brute-force (RDP 3389 vb.) kurallar aktifken bait’siz de bildir/engelle
- API kuralı yoksa yerel `DEFAULT_BLOCK_RULES` (servis başı 3 fail / Network 10)
- Aktif servis detayında port izleme açıklaması
- Dashboard seed API: `AGENT_DEFAULT_BLOCK_RULES_API_PROMPT.md`
