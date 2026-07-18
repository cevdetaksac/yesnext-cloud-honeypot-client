# v4.4.31 — Hizli installer kill

## Fix
- PRE-KILL / kill artik tek hizli gecis: taskkill + SeDebug, max 3 kisa tur
- NSIS artik kill scriptini 15 kez tekrar calistirmiyor; process yoksa skip
- Settle sureleri kisaltildi (~15s+ -> ~1-2s tipik)
