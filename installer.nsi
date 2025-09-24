; Cloud Honeypot Client Installer Script
!include "MUI2.nsh"
!include "FileFunc.nsh"

Name "Cloud Honeypot Client"
OutFile "cloud-client-installer.exe"

!define APPNAME "Cloud Honeypot Client"
!define COMPANYNAME "YesNext"
!define DESCRIPTION "Cloud Honeypot Client - System Security Monitor"
!define VERSIONMAJOR 2
!define VERSIONMINOR 0
!define VERSIONBUILD 0

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
    
    ; Start the application 
    DetailPrint "Starting honeypot client application..."
    Exec '"$INSTDIR\honeypot-client.exe" --minimized'
    
    ; Wait for everything to initialize
    Sleep 2000
SectionEnd

; Windows Service Monitor (Optional but Recommended)
Section "Windows Service Monitor (Recommended)" SEC_SERVICE
    DetailPrint "Installing Cloud Honeypot Monitor Service..."
    
    ; Try multiple methods to install the service
    ExecWait '"$SYSDIR\python.exe" "$INSTDIR\service_wrapper.py" install' $0
    ${If} $0 == 0
        DetailPrint "Service installed successfully using system Python"
    ${Else}
        DetailPrint "System Python failed, trying alternative methods..."
        ; Fallback: Try with Python executable in install dir if available
        ExecWait '"$INSTDIR\python.exe" "$INSTDIR\service_wrapper.py" install' $1
        ${If} $1 == 0
            DetailPrint "Service installed successfully using local Python"
        ${Else}
            ; Try using client script
            ExecWait '"$SYSDIR\python.exe" "$INSTDIR\client.py" --install' $2
            ${If} $2 == 0
                DetailPrint "Service installed successfully using client script"
            ${Else}
                DetailPrint "Service installation failed. You can install it manually later using install_service.bat"
                Goto service_end
            ${EndIf}
        ${EndIf}
    ${EndIf}
    
    DetailPrint "Starting monitor service..."
    ExecWait 'net start CloudHoneypotMonitor' $3
    ${If} $3 == 0
        DetailPrint "Monitor service started successfully - Your client is now protected!"
    ${Else}
        DetailPrint "Service installed but failed to start. It will start automatically on next boot."
    ${EndIf}
    
    service_end:
SectionEnd

; Section Descriptions
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC_MAIN} "Main Cloud Honeypot Client application with all required files"
  !insertmacro MUI_DESCRIPTION_TEXT ${SEC_SERVICE} "Windows Service Monitor provides automatic restart functionality. Highly recommended for production use."
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
