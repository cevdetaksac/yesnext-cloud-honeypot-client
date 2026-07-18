# v4.4.12 — Tray UI-only da oturum raporlasın

v4.4.11 daemon’a HealthMonitor ekledi; pratikte tray hâlâ “daemon var” deyip health’i atlıyor, daemon logu da görünmeyebiliyor → oturum yine gitmiyordu.

## Düzeltme
- Tray UI-only: ServiceManager/firewall atlanır, **HealthMonitor + RemoteCommands mutlaka başlar**
- Daemon path (4.4.11) korunur
- Log: `Faz 3 started (tray-ui: …)` + `report ok — sessions=N`
