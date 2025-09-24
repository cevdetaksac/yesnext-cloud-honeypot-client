; Cloud Honeypot Client Installer Script
!include "MUI2.nsh"
!include "FileFunc.nsh"

Name "Cloud Honeypot Client"
OutFile "cloud-client-installer.exe"

!define APPNAME "Cloud Honeypot Client"
!define COMPANYNAME "YesNext"
!define DESCRIPTION "Cloud Honeypot Client - System Security Monitor"
!define VERSIONMAJOR 2
!define VERSIONMINOR 2
!define VERSIONBUILD 4

!define INSTALLSIZE 15000

; Modern UI Configuration
!define MUI_ICON "certs\honeypot.ico"
!define MUI_UNICON "certs\honeypot.ico"
!define MUI_WELCOMEFINISHPAGE_BITMAP "certs\welcome.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "certs\welcome.bmp"

InstallDir "$PROGRAMFILES64\${COMPANYNAME}\${APPNAME}"

; Request application privileges for Windows Vista/7/8/10
RequestExecutionLevel admin

; Interface Settings
!define MUI_ABORTWARNING

; Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES

; Finish page without reboot options
!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_FINISHPAGE_NOREBOOTSUPPORT
!define MUI_FINISHPAGE_TEXT "Cloud Honeypot Client kurulumu başarıyla tamamlandı.$\r$\n$\r$\nUygulama otomatik olarak başlatıldı ve Windows Service olarak kayıt edildi.$\r$\n$\r$\nSistem yeniden başlatma gerektirmez."
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

; Languages
!insertmacro MUI_LANGUAGE "English"

; Pre-installation cleanup function
Function .onInit
    SetShellVarContext all
    
    ; Check if application is already running and stop it
    DetailPrint "Checking and stopping running processes..."
    nsExec::ExecToLog 'taskkill /f /im honeypot-client.exe'
    nsExec::ExecToLog 'taskkill /f /im cloud-client.exe'
    
    ; Stop and remove existing service
    DetailPrint "Stopping and removing existing services..."
    nsExec::ExecToLog 'net stop CloudHoneypotClient'
    nsExec::ExecToLog 'sc delete CloudHoneypotClient'
    
    ; Give processes time to fully terminate
    Sleep 2000
    
    ; Force close any open handles
    nsExec::ExecToLog 'handle.exe -accepteula -a -p honeypot-client.exe'
    nsExec::ExecToLog 'handle.exe -accepteula -a -p cloud-client.exe'
    
    ; Check if there's an existing installation
    ReadRegStr $R0 HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "UninstallString"
    StrCmp $R0 "" clean_anyway
    
    ; Try to run uninstaller first
    DetailPrint "Running uninstaller..."
    ExecWait '$R0 /S _?=$INSTDIR'
    
    clean_anyway:
    ; Force clean up installation directory
    DetailPrint "Force cleaning installation directory..."
    RMDir /REBOOTOK "$PROGRAMFILES64\${COMPANYNAME}\${APPNAME}"
    nsExec::ExecToLog 'cmd.exe /c "cd \ && rmdir /s /q "$PROGRAMFILES64\${COMPANYNAME}\${APPNAME}"'
    
    ; Clean up program data
    DetailPrint "Cleaning program data..."
    RMDir /REBOOTOK "$PROGRAMDATA\${COMPANYNAME}\${APPNAME}"
    nsExec::ExecToLog 'cmd.exe /c "cd \ && rmdir /s /q "$PROGRAMDATA\${COMPANYNAME}\${APPNAME}"'
    
    ; Clean registry
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}"
    
    ; Final wait to ensure cleanup
    Sleep 3000
    
    ; Create fresh directories
    CreateDirectory "$PROGRAMFILES64\${COMPANYNAME}\${APPNAME}"
    CreateDirectory "$PROGRAMDATA\${COMPANYNAME}\${APPNAME}"
FunctionEnd

; Installer Sections
Section "Cloud Honeypot Client (Required)" SEC_MAIN
    SectionIn RO  ; Read-only (always installed)
    ; Make sure the installation directory is empty and writable
    RMDir /r "$INSTDIR"
    CreateDirectory "$INSTDIR"
    
    ; Write uninstaller first
    WriteUninstaller "$INSTDIR\Uninstall.exe"
    
    SetOutPath $INSTDIR
    
    ; Mevcut kurulumu sessizce kaldır
    ExecWait '$R0 /S _?=$INSTDIR'
    
    ; Kısa bir bekleme ekle ve eski dosyaları temizle
    Sleep 1000
    RMDir /r "$INSTDIR"
    
    proceed_install:
    ; Yeni kurulum dizinini oluştur
    CreateDirectory "$INSTDIR"
    SetOutPath "$INSTDIR"
    
    ; AppData klasöründeki durum dosyasını temizle
    StrCpy $0 "$APPDATA\YesNext\CloudHoneypotClient"
    RMDir /r "$0"
    CreateDirectory "$0"
    
    ; Add files
    File /r "dist\honeypot-client\*.*"
    
    ; Copy icon file for shortcuts
    File "certs\honeypot.ico"
    
    ; Create uninstaller
    WriteUninstaller "$INSTDIR\Uninstall.exe"
    
    ; Start Menu
    CreateDirectory "$SMPROGRAMS\${COMPANYNAME}"
    CreateShortCut "$SMPROGRAMS\${COMPANYNAME}\${APPNAME}.lnk" "$INSTDIR\honeypot-client.exe" "" "$INSTDIR\honeypot.ico" 0
    CreateShortCut "$SMPROGRAMS\${COMPANYNAME}\Uninstall.lnk" "$INSTDIR\Uninstall.exe"
    
    ; Desktop Shortcut
    CreateShortCut "$DESKTOP\${APPNAME}.lnk" "$INSTDIR\honeypot-client.exe" "" "$INSTDIR\honeypot.ico" 0
    
    ; Registry information for add/remove programs
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "DisplayName" "${APPNAME}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "UninstallString" "$\"$INSTDIR\Uninstall.exe$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "QuietUninstallString" "$\"$INSTDIR\Uninstall.exe$\" /S"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "InstallLocation" "$\"$INSTDIR$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "DisplayIcon" "$\"$INSTDIR\honeypot-client.exe$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "Publisher" "${COMPANYNAME}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "DisplayVersion" "${VERSIONMAJOR}.${VERSIONMINOR}.${VERSIONBUILD}"
    
    ; Application will be started after service installation is complete
SectionEnd

; Windows Service Monitor (Always Installed)
Section "Windows Service Monitor" SEC_SERVICE
    SectionIn RO  ; Make service installation mandatory
    DetailPrint "Installing Cloud Honeypot Monitor Service..."
    
    ; Method 1: Try system Python first
    DetailPrint "Attempting service installation with system Python..."
    ExecWait '"$SYSDIR\python.exe" "$INSTDIR\service_wrapper.py" install' $0
    ${If} $0 == 0
        DetailPrint "✅ Service installed successfully using system Python"
        Goto service_installed
    ${EndIf}
    
    ; Method 2: Try Python from PATH
    DetailPrint "System Python failed, trying Python from PATH..."
    ExecWait 'python.exe "$INSTDIR\service_wrapper.py" install' $1
    ${If} $1 == 0
        DetailPrint "✅ Service installed successfully using PATH Python"
        Goto service_installed
    ${EndIf}
    
    ; Method 3: Try local Python if available
    DetailPrint "PATH Python failed, trying local Python..."
    ExecWait '"$INSTDIR\python.exe" "$INSTDIR\service_wrapper.py" install' $2
    ${If} $2 == 0
        DetailPrint "✅ Service installed successfully using local Python"
        Goto service_installed
    ${EndIf}
    
    ; Method 4: Try using client script with system Python
    DetailPrint "Local Python failed, trying client script method..."
    ExecWait '"$SYSDIR\python.exe" "$INSTDIR\client.py" --install' $3
    ${If} $3 == 0
        DetailPrint "✅ Service installed successfully using client script"
        Goto service_installed
    ${EndIf}
    
    ; Method 5: Direct service registration
    DetailPrint "All Python methods failed, trying direct registration..."
    ExecWait 'sc create CloudHoneypotClient binPath= "\"$SYSDIR\python.exe\" \"$INSTDIR\service_wrapper.py\"" DisplayName= "Cloud Honeypot Client Monitor" start= auto' $4
    ${If} $4 == 0
        DetailPrint "✅ Service registered successfully using SC command"
        Goto service_installed
    ${EndIf}
    
    ; If all methods fail, show error but continue
    DetailPrint "⚠️ Service installation failed with all methods. Manual installation may be required."
    DetailPrint "You can install the service manually using install_service.bat after installation."
    Goto service_start_attempt
    
    service_installed:
    DetailPrint "🔧 Service registration completed successfully"
    
    service_start_attempt:
    ; Start the service with multiple attempts
    DetailPrint "Starting Cloud Honeypot Monitor Service..."
    
    ; First attempt: Standard net start
    ExecWait 'net start CloudHoneypotClient' $5
    ${If} $5 == 0
        DetailPrint "✅ Monitor service started successfully"
        Goto service_running
    ${EndIf}
    
    ; Second attempt: Try with CloudHoneypotMonitor name (fallback)
    DetailPrint "Trying alternative service name..."
    ExecWait 'net start CloudHoneypotMonitor' $6
    ${If} $6 == 0
        DetailPrint "✅ Monitor service started successfully (alternative name)"
        Goto service_running
    ${EndIf}
    
    ; Third attempt: SC start command
    DetailPrint "Trying SC start command..."
    ExecWait 'sc start CloudHoneypotClient' $7
    ${If} $7 == 0
        DetailPrint "✅ Monitor service started successfully (SC command)"
        Goto service_running
    ${EndIf}
    
    ; If service fails to start, it's not critical - app can still run
    DetailPrint "⚠️ Service installed but failed to start automatically"
    DetailPrint "Service will start on next system boot"
    Goto start_application
    
    service_running:
    DetailPrint "🛡️ Your system is now protected by the monitor service"
    
    start_application:
    ; Always start the application regardless of service status
    DetailPrint "🚀 Starting Cloud Honeypot Client application..."
    
    ; Kill any existing processes first
    nsExec::ExecToLog 'taskkill /f /im honeypot-client.exe'
    nsExec::ExecToLog 'taskkill /f /im cloud-client.exe'
    Sleep 1000
    
    ; Start the main application
    Exec '"$INSTDIR\honeypot-client.exe" --minimized'
    Sleep 3000
    
    ; Verify application started
    nsExec::ExecToLog 'tasklist /FI "IMAGENAME eq honeypot-client.exe"'
    
    DetailPrint "✅ Cloud Honeypot Client installation completed!"
    DetailPrint "📊 Check Windows Services (services.msc) to verify service status"
    DetailPrint "🔍 Application is running in system tray"
    
    service_end:
SectionEnd

; Section Descriptions
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC_MAIN} "Main Cloud Honeypot Client application with all required files"
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC_SERVICE} "Windows Service Monitor provides automatic restart functionality and is always installed for system stability."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; Uninstaller Section
Section "Uninstall"
    SetShellVarContext all
    
    DetailPrint "Stopping service and processes..."
    
    ; Stop and remove the monitor service
    nsExec::ExecToLog 'net stop CloudHoneypotClient'
    nsExec::ExecToLog '"$SYSDIR\python.exe" "$INSTDIR\service_wrapper.py" uninstall'
    
    ; Stop client processes  
    nsExec::ExecToLog 'taskkill /f /im honeypot-client.exe'
    nsExec::ExecToLog 'taskkill /f /im cloud-client.exe'
    nsExec::ExecToLog 'taskkill /f /im python.exe'
    
    ; Give processes time to terminate
    Sleep 2000
    
    DetailPrint "Removing shortcuts..."
    Delete "$SMPROGRAMS\${COMPANYNAME}\${APPNAME}.lnk"
    Delete "$SMPROGRAMS\${COMPANYNAME}\Uninstall.lnk"
    Delete "$DESKTOP\${APPNAME}.lnk"
    RMDir "$SMPROGRAMS\${COMPANYNAME}"
    
    DetailPrint "Cleaning installation directory..."
    ; Try multiple deletion methods
    RMDir /r /REBOOTOK "$INSTDIR"
    nsExec::ExecToLog 'cmd.exe /c "cd \ && rmdir /s /q "$INSTDIR""'
    
    DetailPrint "Cleaning program data..."
    RMDir /r /REBOOTOK "$PROGRAMDATA\${COMPANYNAME}\${APPNAME}"
    nsExec::ExecToLog 'cmd.exe /c "cd \ && rmdir /s /q "$PROGRAMDATA\${COMPANYNAME}\${APPNAME}""'
    
    DetailPrint "Cleaning AppData..."
    RMDir /r /REBOOTOK "$APPDATA\${COMPANYNAME}\CloudHoneypotClient"
    nsExec::ExecToLog 'cmd.exe /c "cd \ && rmdir /s /q "$APPDATA\${COMPANYNAME}\CloudHoneypotClient""'
    
    ; Remove registry entries
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}"
SectionEnd
