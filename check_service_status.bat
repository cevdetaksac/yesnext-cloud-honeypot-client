@echo off
REM Cloud Honeypot Client - Service Status Check
REM This script checks the current status of the monitor service

title Cloud Honeypot Client - Service Status

echo.
echo ================================================================
echo            Cloud Honeypot Client Service Status
echo ================================================================
echo.

echo [INFO] Checking Cloud Honeypot Monitor Service status...
echo.

REM Check service status using client command
python.exe client.py --service-status
if %errorLevel% == 0 (
    echo.
    echo ================================================================
    echo                     STATUS CHECK COMPLETE
    echo ================================================================
    echo.
    echo For more detailed service information, you can also:
    echo   * Open Windows Services: Run "services.msc"
    echo   * Look for "Cloud Honeypot Monitor Service"
    echo   * Check Windows Event Viewer for service logs
) else (
    echo.
    echo ================================================================
    echo                   STATUS CHECK FAILED
    echo ================================================================
    echo.
    echo Could not retrieve service status information.
    echo.
    echo This might mean:
    echo   * The service is not installed
    echo   * Python is not accessible from command line
    echo   * Client files are missing or corrupted
    echo.
    echo To install the service, run "install_service.bat"
)

echo.
pause