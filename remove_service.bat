@echo off
REM Cloud Honeypot Client - Service Removal Batch
REM This script removes the monitor service

title Cloud Honeypot Client - Service Removal

echo.
echo ================================================================
echo            Cloud Honeypot Client Service Remover
echo ================================================================
echo.
echo This script will remove the Cloud Honeypot Monitor Service.
echo After removal, the client application will run normally but
echo will not automatically restart if it crashes.
echo.

REM Check for admin privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [INFO] Administrator privileges confirmed.
) else (
    echo [ERROR] This script requires Administrator privileges!
    echo.
    echo Please right-click this file and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

echo [WARNING] Are you sure you want to remove the service? (Y/N)
set /p choice=Please type Y or N: 
if /i "%choice%" neq "Y" (
    echo.
    echo [INFO] Service removal cancelled by user.
    echo.
    pause
    exit /b 0
)

echo.
echo [INFO] Removing Cloud Honeypot Monitor Service...
echo.

REM Try to run the service removal
python.exe client.py --remove
if %errorLevel% == 0 (
    echo.
    echo ================================================================
    echo                 SERVICE REMOVED SUCCESSFULLY!
    echo ================================================================
    echo.
    echo The Cloud Honeypot Monitor Service has been removed.
    echo.
    echo The client application will continue to work normally,
    echo but will not automatically restart if it crashes.
    echo.
    echo To reinstall the service later, run "install_service.bat"
) else (
    echo.
    echo ================================================================
    echo                   SERVICE REMOVAL FAILED
    echo ================================================================
    echo.
    echo The service removal encountered an error.
    echo.
    echo The service might not be installed or there could be
    echo permission issues. Please contact support if needed.
)

echo.
pause