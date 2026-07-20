# Contract pointer

**CONTRACT_ROOT** for this workspace:

```text
c:\honeypot-cloud\honeypot-contract
```

(relative from `cloud-client/`: `../honeypot-contract`)

## Agent / Cursor — zorunlu sıra

1. Oku `CONTRACT_ROOT/VERSION` + `CONTRACT_ROOT/INDEX.md`
2. İlgili `api/*` veya `agent/*` dosyasını aç
3. Sözleşmeye aykırı kod yazma; belirsizse contract’a Open questions notu
4. API değişikliği → önce contract MD + CHANGELOG + VERSION → sonra kod
5. Cloud-only (PM2, nginx, dashboard HTML) varsayma

See Cursor rule: `.cursor/rules/honeypot-contract.mdc`
