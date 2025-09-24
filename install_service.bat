@echo off
REM Cloud Honeypot Client - Service Installation Batch
REM This script installs the monitor service for automatic restart functionality

title Cloud Honeypot Client - Service Installation

echo.
echo ================================================================
echo            Cloud Honeypot Client Service Installer
echo ================================================================
echo.
echo This script will install the Cloud Honeypot Monitor Service.
echo The service will automatically restart the client application
echo if it crashes or after system reboots.
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

echo [INFO] Installing Cloud Honeypot Monitor Service...
echo.

REM Try to run the service installation
python.exe client.py --install
if %errorLevel% == 0 (
    echo.
    echo ================================================================
    echo                 SERVICE INSTALLED SUCCESSFULLY!
    echo ================================================================
    echo.
    echo The Cloud Honeypot Monitor Service has been installed and will:
    echo   * Monitor the client application continuously
    echo   * Automatically restart it if it crashes
    echo   * Start automatically after system reboots
    echo   * Run in the background without interrupting your work
    echo.
    echo You can:
    echo   * Check service status: run "check_service_status.bat"
    echo   * Remove the service: run "remove_service.bat"
    echo   * View service logs in Windows Event Viewer
    echo.
    echo The client application will now be protected by the monitor service.
) else (
    echo.
    echo ================================================================
    echo                   SERVICE INSTALLATION FAILED
    echo ================================================================
    echo.
    echo The service installation encountered an error.
    echo.
    echo Please ensure:
    echo   * You are running as Administrator
    echo   * Python is properly installed and in PATH
    echo   * All client files are present in the directory
    echo   * No antivirus software is blocking the installation
    echo.
    echo Contact support if the problem persists.
)

echo.
pause
pause