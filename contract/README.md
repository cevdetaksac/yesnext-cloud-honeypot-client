# Contract pointer

**CONTRACT_ROOT** for this workspace:

```text
c:\honeypot-cloud\honeypot-contract
```

(relative from `cloud-client/`: `../honeypot-contract`)

Remote: https://github.com/cevdetaksac/honeypot-contract · tag ≥ **v1.1.1**

`docs/api/*` ve `docs/CLIENT.md` stub’dır — SoT yalnızca contract.

## Agent / Cursor — zorunlu sıra

1. Oku `CONTRACT_ROOT/VERSION` + `INDEX.md` + `FLEET.md`
2. İlgili `api/*` veya `agent/*` dosyasını aç
3. Sözleşmeye aykırı kod yazma; belirsizse contract’a Open questions notu
4. API değişikliği → önce contract MD + CHANGELOG + VERSION → sonra kod
5. Cloud: `git pull` + `publish_contract.sh` — API bu MD’leri referans alır

See Cursor rule: `.cursor/rules/honeypot-contract.mdc`
