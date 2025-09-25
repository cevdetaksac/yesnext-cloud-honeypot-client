@echo off
REM ============================================================================
REM Cloud Honeypot Client Monitor Service - Installation Script
REM ============================================================================

echo.
echo ==============================================
echo  Honeypot Monitor Service Installation
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

echo Installing required Python packages...
pip install psutil pywin32 --quiet

if %errorlevel% neq 0 (
    echo ERROR: Failed to install required packages.
    echo Please ensure Python and pip are properly installed.
    pause
    exit /b 1
)

echo.
echo Installing Honeypot Monitor Service...
python service_monitor.py install

if %errorlevel% equ 0 (
    echo.
    echo SUCCESS: Service installed successfully!
    echo.
    echo Starting service...
    python service_monitor.py start
    
    if %errorlevel% equ 0 (
        echo SUCCESS: Service started successfully!
        echo.
        echo The Honeypot Monitor Service is now running.
        echo It will automatically monitor and restart the client application.
    ) else (
        echo WARNING: Service installed but failed to start.
        echo You can start it manually from Services.msc
    )
) else (
    echo ERROR: Service installation failed.
    echo Check the error messages above.
)

echo.
echo Service Management Commands:
echo   Start:   python service_monitor.py start
echo   Stop:    python service_monitor.py stop
echo   Remove:  python service_monitor.py remove
echo   Status:  python service_monitor.py status

pause