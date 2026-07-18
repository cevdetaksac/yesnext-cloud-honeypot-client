# v4.4.19 — RDP session=2 capture fix (err 1314)

Log örneği:
`pid_session=2 console=1` + `WTSQueryUserToken(1) failed err=1314` + `ImageGrab failed`

**Sorun:** Agent RDP oturumundayken (session 2) helper yanlışlıkla **physical console (1)** için token istiyordu → privilege yok (1314).

## Düzeltme
- Token helper **yalnızca Session 0**’da çalışır; session>0 ise atlanır
- GDI: BitBlt fail → desktop window DC; brightness log
- ImageGrab: bbox / primary / all_screens varyantları
