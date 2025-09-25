@echo off
REM ============================================================================
REM Cloud Honeypot Client Monitor Service - Status Check Script  
REM ============================================================================

echo.
echo ==============================================
echo  Honeypot Monitor Service Status
echo ==============================================
echo.

echo Checking service status...
sc query HoneypotClientMonitor

echo.
echo Service configuration:
sc qc HoneypotClientMonitor

echo.
echo Recent log entries:
if exist monitor.log (
    echo [Last 10 lines from monitor.log]
    powershell -Command "Get-Content monitor.log -Tail 10"
) else (
    echo No log file found (monitor.log)
)

echo.
echo Monitor status file:
if exist monitor_status.json (
    echo [monitor_status.json content]
    type monitor_status.json
) else (
    echo No status file found (monitor_status.json)
)

pause