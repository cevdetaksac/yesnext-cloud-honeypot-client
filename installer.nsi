; Cloud Honeypot Client Installer Script - v2.6.1
; Auto-elevating installer
!include "MUI2.nsh"
!include "FileFunc.nsh"

Name "Cloud Honeypot Client"
OutFile "cloud-client-installer.exe"

!define APPNAME "Cloud Honeypot Client"
!define COMPANYNAME "YesNext"
!define DESCRIPTION "Cloud Honeypot Client - System Security Monitor"
!define VERSIONMAJOR 2
!define VERSIONMINOR 5
!define VERSIONBUILD 8

InstallDir "$PROGRAMFILES64\${COMPANYNAME}\${APPNAME}"
RequestExecutionLevel admin

; Modern UI Configuration
!define MUI_ICON "certs\honeypot.ico"
!define MUI_UNICON "certs\honeypot.ico"
!define MUI_WELCOMEFINISHPAGE_BITMAP "certs\welcome.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "certs\welcome.bmp"

; Interface Settings
!define MUI_ABORTWARNING

; Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES

; Finish page
!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_FINISHPAGE_NOREBOOTSUPPORT
!define MUI_FINISHPAGE_RUN "$INSTDIR\honeypot-client.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Start Cloud Honeypot Client now"
!define MUI_FINISHPAGE_TEXT "Cloud Honeypot Client v2.6.1 installation completed successfully.$\r$\n$\r$\nThe application will configure auto-startup settings on first run.$\r$\n$\r$\nNo system restart required."
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

; Languages
!insertmacro MUI_LANGUAGE "English"

; Admin check function
Function .onInit
    UserInfo::GetAccountType
    Pop $0
    StrCmp $0 "Admin" admin_ok
    MessageBox MB_ICONSTOP "This installation requires administrator privileges.$\r$\nPlease run the installer as Administrator."
    Quit
    admin_ok:
FunctionEnd

; Main Section
Section "Cloud Honeypot Client (Required)" SEC_MAIN
    SectionIn RO
    ; Force compatibility flag so Windows runs the client elevated
    WriteRegStr HKCU "Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" "$INSTDIR\honeypot-client.exe" "~ RUNASADMIN"
    
    DetailPrint "================================================================"
    DetailPrint "CLOUD HONEYPOT CLIENT v2.6.1 INSTALLATION"
    DetailPrint "================================================================"
    
    ; Set output path to the installation directory
    SetOutPath $INSTDIR
    
    ; Install main files
    DetailPrint "Installing application files..."
    File /oname=honeypot-client.exe "dist\honeypot-client.exe"
    File /oname=client_config.json "dist\client_config.json"
    File /oname=client_lang.json "dist\client_lang.json"
    File /oname=LICENSE "dist\LICENSE"
    File /oname=README.md "dist\README.md"
    
    ; Set Windows Defender exclusions
    DetailPrint "Configuring Windows Defender exclusions..."
    nsExec::ExecToLog 'powershell -ExecutionPolicy Bypass -Command "try { Add-MpPreference -ExclusionPath \"$INSTDIR\" -Force; Add-MpPreference -ExclusionProcess \"$INSTDIR\honeypot-client.exe\" -Force; Write-Host \"Defender exclusions added\" } catch { Write-Host \"Could not add defender exclusions\" }"'
    
    ; Create uninstaller
    WriteUninstaller "$INSTDIR\Uninstall.exe"
    
    ; Registry entries for Add/Remove Programs
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayName" "${APPNAME}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "UninstallString" "$\"$INSTDIR\Uninstall.exe$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "QuietUninstallString" "$\"$INSTDIR\Uninstall.exe$\" /S"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "InstallLocation" "$\"$INSTDIR$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayIcon" "$\"$INSTDIR\honeypot-client.exe$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "Publisher" "${COMPANYNAME}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayVersion" "${VERSIONMAJOR}.${VERSIONMINOR}.${VERSIONBUILD}"
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "VersionMajor" ${VERSIONMAJOR}
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "VersionMinor" ${VERSIONMINOR}
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "NoRepair" 1
    
    DetailPrint "Installation completed successfully!"
    DetailPrint "Note: Auto-startup will be configured by the application on first run."
    
SectionEnd

; Uninstaller section
Section "Uninstall"
    ; Remove compatibility flag
    DeleteRegValue HKCU "Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" "$INSTDIR\honeypot-client.exe"
    ; Stop the application if running
    DetailPrint "Stopping Cloud Honeypot Client..."
    nsExec::ExecToLog 'taskkill /f /im honeypot-client.exe'
    Sleep 2000
    
    ; Remove scheduled tasks
    DetailPrint "Removing scheduled tasks..."
    nsExec::ExecToLog 'schtasks /delete /tn "Cloud Honeypot Client" /f'
    nsExec::ExecToLog 'schtasks /delete /tn "HoneypotClientAutostart" /f'
    
    ; Remove Windows Defender exclusions
    DetailPrint "Removing Windows Defender exclusions..."
    nsExec::ExecToLog 'powershell -ExecutionPolicy Bypass -Command "try { Remove-MpPreference -ExclusionPath \"$INSTDIR\" -Force; Remove-MpPreference -ExclusionProcess \"$INSTDIR\honeypot-client.exe\" -Force } catch { }"'
    
    ; Remove files
    DetailPrint "Removing application files..."
    Delete "$INSTDIR\honeypot-client.exe"
    Delete "$INSTDIR\client_config.json"
    Delete "$INSTDIR\client_lang.json"
    Delete "$INSTDIR\LICENSE"
    Delete "$INSTDIR\README.md"
    Delete "$INSTDIR\Uninstall.exe"
    
    ; Remove directory if empty
    RMDir "$INSTDIR"
    
    ; Remove registry entries
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}"
    
    DetailPrint "Cloud Honeypot Client has been completely removed."
SectionEnd

; Section descriptions
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
!insertmacro MUI_DESCRIPTION_TEXT ${SEC_MAIN} "Core Cloud Honeypot Client application and configuration files. This component is required."
!insertmacro MUI_FUNCTION_DESCRIPTION_END
