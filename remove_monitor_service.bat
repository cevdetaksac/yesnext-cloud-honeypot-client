@echo off
REM ============================================================================
REM Cloud Honeypot Client Monitor Service - Removal Script
REM ============================================================================

echo.
echo ==============================================
echo  Honeypot Monitor Service Removal
echo ==============================================
echo.

REM Check admin privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This script requires Administrator privileges.
    echo Please run as Administrator.
    pause
    exit /b 1
)

echo Stopping Honeypot Monitor Service...
python service_monitor.py stop

echo.
echo Removing Honeypot Monitor Service...
python service_monitor.py remove

if %errorlevel% equ 0 (
    echo SUCCESS: Service removed successfully!
) else (
    echo WARNING: Service removal may have failed.
    echo Check Services.msc to verify removal.
)

pause