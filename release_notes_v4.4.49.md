# v4.4.49 — Remote keyboard fix (Unicode) + CAD SendSAS

- **Klavye:** tek karakter (`a`, `ğ`, `@`, `€`…) artık `KEYEVENTF_UNICODE` `SendInput` — QWERTY VK map yok
- **SendInput** 64-bit güvenli INPUT union (önceki bozuk struct klavyeyi sessizce düşürüyordu)
- `type_text`, `escape`/`enter`/`ctrl+c` vb. korunuyor
- Log: `[remote-input] t=input event=… key=…`
- **CAD:** `remote_send_sas` → `sas.dll` `SendSAS(0)` (sentetik ctrl+alt+del değil)
