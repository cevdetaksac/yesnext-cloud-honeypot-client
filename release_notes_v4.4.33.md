# v4.4.33 — Token kimligi: ProgramData + asla rastgele yenilenmez

## Sorun
- Token `%APPDATA%` altindaydi; SYSTEM daemon ile kullanici GUI farkli dosya okuyup yeni `/register` yapiyordu
- Load/decrypt fail → otomatik yeni token (API'de eski "silindi" gibi)

## Fix (client)
- Canonical token: `%ProgramData%\YesNext\CloudHoneypotClient\token.dat`
- Eski AppData / SystemProfile / token.txt → bir kez migrate
- Dosya varken veya okunamazken **yeni register yok**
- Kayit kilidi (cift register engeli)
- `/register` body: `machine_id` / `hwid` (Windows MachineGuid)
- Mevcut token uzerine farkli token yazma engeli

## API (ayri)
- `AGENT_TOKEN_IMMUTABLE_API_PROMPT.md` → register upsert by machine_id
