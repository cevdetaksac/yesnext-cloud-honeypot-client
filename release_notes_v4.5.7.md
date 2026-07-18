# v4.5.7 — Lazy GUI pages

- Shell (sidebar + ust bar) hemen acilir
- Sayfa widgetlari ilk ziyarette build edilir (status / threat / services)
- Veriler adim adim yuklenir (attack count, IP tablo, security intel…)
- Threat/Services acilista build edilmez
- Frontend modda motor + agir API hâlâ SYSTEM daemon'da; GUI sadece goruntuleme/IPC

Ayrica 4.5.6'dan: RDP buton guncellemesi Tk main thread'e alindi.
