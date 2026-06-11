# YARA rules

The `yara_scan` agent tool reads `malware_rules.yar` from this folder.
Bootstrap a starter ruleset (1.7 MB, public-domain aggregate from the
Kirandawadi/volatility3-mcp project — re-source as needed):

```
curl -L -o rules/malware_rules.yar \
  https://raw.githubusercontent.com/Kirandawadi/volatility3-mcp/main/malware_rules.yar
```

Drop your own `.yar` files alongside it; pass `rules_file` to the
`yara_scan` tool to point at a specific ruleset.
