@echo off
echo ====================================================
echo Cloud Honeypot Client - Service Uninstaller  
echo ====================================================
echo.
echo This will remove the Cloud Honeypot Client Monitor Service.
echo.
pause

python install_service.py uninstall

echo.
echo Service removal complete!
echo.
pause