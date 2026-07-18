# v4.4.47 — Remote command coalesce + faster IP update

- **Remote Desktop:** Aynı poll batch’inde birden fazla `remote_stream_start` varsa yalnızca **en yenisi** uygulanır; eskiler `cancelled` / `SUPERSEDED` olarak raporlanır
- **Poll docstring** güncellendi (1s IR/stream)
- **WAN IP:** Public IP cache **5 dk → 60 sn**; ağ değişince `update-ip` daha hızlı
