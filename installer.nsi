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
Section "Install"
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
    
    ; Create uninstaller
    WriteUninstaller "$INSTDIR\Uninstall.exe"
    
    ; Start Menu
    CreateDirectory "$SMPROGRAMS\${COMPANYNAME}"
    CreateShortCut "$SMPROGRAMS\${COMPANYNAME}\${APPNAME}.lnk" "$INSTDIR\honeypot-client.exe" "" "$INSTDIR\honeypot-client.exe" 0
    CreateShortCut "$SMPROGRAMS\${COMPANYNAME}\Uninstall.lnk" "$INSTDIR\Uninstall.exe"
    
    ; Desktop Shortcut
    CreateShortCut "$DESKTOP\${APPNAME}.lnk" "$INSTDIR\honeypot-client.exe" "" "$INSTDIR\honeypot-client.exe" 0
    
    ; Registry information for add/remove programs
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "DisplayName" "${APPNAME}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "UninstallString" "$\"$INSTDIR\Uninstall.exe$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "QuietUninstallString" "$\"$INSTDIR\Uninstall.exe$\" /S"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "InstallLocation" "$\"$INSTDIR$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "DisplayIcon" "$\"$INSTDIR\honeypot-client.exe$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "Publisher" "${COMPANYNAME}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${COMPANYNAME} ${APPNAME}" "DisplayVersion" "${VERSIONMAJOR}.${VERSIONMINOR}.${VERSIONBUILD}"
    
    ; Install and start the Windows service
    DetailPrint "Installing service..."
    ExecWait '"$INSTDIR\honeypot-client.exe" install'
    DetailPrint "Starting service..."
    ExecWait 'net start CloudHoneypotClient'
    
    ; Start the application with runas to ensure proper elevation
    DetailPrint "Starting application..."
    Exec '"$INSTDIR\honeypot-client.exe" --minimized=false'
    
    ; Wait a moment for everything to start
    Sleep 1000
SectionEnd

; Uninstaller Section
Section "Uninstall"
    SetShellVarContext all
    
    DetailPrint "Stopping service and processes..."
    nsExec::ExecToLog 'net stop CloudHoneypotClient'
    nsExec::ExecToLog '"$INSTDIR\honeypot-client.exe" remove'
    nsExec::ExecToLog 'taskkill /f /im honeypot-client.exe'
    nsExec::ExecToLog 'taskkill /f /im cloud-client.exe'
    
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
