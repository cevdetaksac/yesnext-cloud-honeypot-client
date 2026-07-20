# Requires Administrator — create fake HP-BLOCK rules for GUI/block-store test
$ErrorActionPreference = "Continue"
$created = 0
$failed = 0
foreach ($base in @("203.0.113", "198.51.100")) {
  1..40 | ForEach-Object {
    $ip = "$base.$_"
    $name = "HP-BLOCK-$ip"
    & netsh advfirewall firewall add rule name="$name" dir=in action=block remoteip=$ip enable=yes | Out-Null
    if ($LASTEXITCODE -eq 0) { $created++ } else { $failed++ }
  }
}
$out = netsh advfirewall firewall show rule name=all dir=in | Select-String -Pattern 'HP-BLOCK-203\.0\.113\.|HP-BLOCK-198\.51\.100\.'
Write-Output "created=$created failed=$failed matched=$($out.Count)"
# Seed ProgramData via installed/venv python
Set-Location "C:\honeypot-cloud\cloud-client"
& ".\.venv\Scripts\python.exe" -c @"
from client_block_store import merge_from_firewall_rules
rules=[]
for a in range(1,41):
  for base in ('203.0.113','198.51.100'):
    ip=f'{base}.{a}'
    rules.append({'name':f'HP-BLOCK-{ip}','remoteip':ip,'suffix':ip,'legacy':False})
m=merge_from_firewall_rules(rules)
print('store_count', len(m))
"@
