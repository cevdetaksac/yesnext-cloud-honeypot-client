; Cloud Honeypot Client Installer Script - v2.8.6
; Optimized installer with fast process cleanup
!include "MUI2.nsh"
!include "WinVer.nsh"
!include "LogicLib.nsh"

Name "Cloud Honeypot Client"
OutFile "cloud-client-installer.exe"

!define APPNAME "Cloud Honeypot Client"
!define COMPANYNAME "YesNext"
!define DESCRIPTION "Cloud Honeypot Client - System Security Monitor"
!define VERSIONMAJOR 2
!define VERSIONMINOR 8
!define VERSIONBUILD 6

InstallDir "$PROGRAMFILES64\${COMPANYNAME}\${APPNAME}"

; Auto-elevation - will automatically request UAC
RequestExecutionLevel admin

; Modern UI Configuration
!define MUI_ICON "certs\honeypot_64.ico"
!define MUI_UNICON "certs\honeypot_64.ico"
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

; Finish page - Auto-start configuration
!define MUI_FINISHPAGE_TEXT "Cloud Honeypot Client v2.8.6 installed successfully$\r$\n$\r$\nApplication will start automatically$\r$\nDesktop shortcut has been created$\r$\nSystem is ready for security monitoring$\r$\n$\r$\nInstaller will close automatically..."
;!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

; Languages
!insertmacro MUI_LANGUAGE "English"

; Variables
Var LogFile

; Simple log function
Function WriteLog
    Exch $0  ; Get the text to log
    Push $1
    
    ; Write to log file safely
    ClearErrors
    FileOpen $1 $LogFile a
    IfErrors LogOpenError
    FileWrite $1 "$0$\r$\n"
    FileClose $1
    Goto LogEnd
    LogOpenError:
    DetailPrint "[LOG ERROR] Log file could not be opened: $LogFile"
    LogEnd:
    Pop $1
    Pop $0
FunctionEnd

; Forcefully stop a running process by base name (without .exe) - OPTIMIZED
Function ForceStopProcess
    Exch $0
    Push $1
    
    ; Single force kill - no retries needed with /f /t
    DetailPrint "[PREP] Stopping $0.exe..."
    nsExec::Exec 'taskkill /f /t /im "$0.exe" >nul 2>&1'
    Pop $1
    
    ; Brief wait for process cleanup
    Sleep 500
    
    DetailPrint "[PREP] $0.exe stop command executed."
    
    Pop $1
    Pop $0
FunctionEnd

; Macro for easy logging
!macro LOG text
    Push "${text}"
    Call WriteLog
    DetailPrint "${text}"
!macroend

; Initialization
Function .onInit
    ; Initialize logging to LOCALAPPDATA (always writable)
    StrCpy $LogFile "$LOCALAPPDATA\honeypot-installer.log"
    
    ; Clear previous log
    Delete $LogFile
    
    ; Start logging
    Push "=== CLOUD HONEYPOT CLIENT v2.8.3 INSTALLER ==="
    Call WriteLog
    Push "Installation started with admin privileges"
    Call WriteLog
    Push "Log file location: $LogFile"
    Call WriteLog
FunctionEnd

; Main Section
Section "Cloud Honeypot Client (Required)" SEC_MAIN
    SectionIn RO

    ; =================================================================
    ; PRE-INSTALLATION CLEANUP
    ; =================================================================
    !insertmacro LOG "[PREP] Starting pre-installation cleanup..."
    
    ; Step 0: CRITICAL - Disable watchdog FIRST to prevent respawn
    !insertmacro LOG "[PREP] Disabling watchdog respawn mechanism..."
    ; Write 'stop' token to prevent watchdog from restarting processes
    nsExec::Exec 'cmd /c echo stop > "%TEMP%\honeypot_watchdog_token.txt"'
    nsExec::Exec 'cmd /c echo stop > "%APPDATA%\YesNext\CloudHoneypot\watchdog_token.txt"'
    ; Also create a stop flag in ProgramData
    nsExec::Exec 'cmd /c mkdir "%ProgramData%\YesNext\CloudHoneypot" 2>nul'
    nsExec::Exec 'cmd /c echo stop > "%ProgramData%\YesNext\CloudHoneypot\watchdog_stop.flag"'
    Sleep 1000
    
    ; Step 1: Delete scheduled tasks FIRST (not just stop - DELETE them)
    !insertmacro LOG "[PREP] Deleting scheduled tasks..."
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-Watchdog" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-Background" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-Tray" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-Updater" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-SilentUpdater" /f >nul 2>&1'
    ; Also stop any running instances
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Background" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Tray" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Watchdog" >nul 2>&1'
    Sleep 500

    ; Step 2: Force kill ALL honeypot processes (aggressive - multiple rounds)
    !insertmacro LOG "[PREP] Killing honeypot processes (round 1)..."
    nsExec::Exec 'taskkill /f /t /im "honeypot-client.exe" >nul 2>&1'
    nsExec::Exec 'wmic process where "name=\'honeypot-client.exe\'" delete >nul 2>&1'
    Sleep 1000
    
    !insertmacro LOG "[PREP] Killing honeypot processes (round 2)..."
    nsExec::Exec 'taskkill /f /t /im "honeypot-client.exe" >nul 2>&1'
    nsExec::Exec 'powershell -Command "Get-Process honeypot-client -ErrorAction SilentlyContinue | Stop-Process -Force" >nul 2>&1'
    Sleep 1000
    
    !insertmacro LOG "[PREP] Killing honeypot processes (round 3 - final)..."
    nsExec::Exec 'taskkill /f /t /im "honeypot-client.exe" >nul 2>&1'
    
    ; Step 3: Wait for file handles to be released
    !insertmacro LOG "[PREP] Waiting for file handles to release..."
    Sleep 3000
    
    ; Step 4: One more kill attempt if process is stubborn
    nsExec::Exec 'taskkill /f /t /im "honeypot-client.exe" >nul 2>&1'
    Sleep 500
    
    !insertmacro LOG "[PREP] Pre-installation cleanup finished."

    ; =================================================================
    ; INSTALLATION
    ; =================================================================
    !insertmacro LOG "[INSTALL] Starting main installation..."
    !insertmacro LOG "[INSTALL] Target directory: $INSTDIR"
    SetOutPath $INSTDIR

    ; Install main files
    !insertmacro LOG "[FILES] Installing application files..."
    File /oname=honeypot-client.exe "dist\honeypot-client.exe"
    File /oname=client_config.json "dist\client_config.json"
    File /oname=client_lang.json "dist\client_lang.json"
    File /oname=LICENSE "dist\LICENSE"
    File /oname=README.md "dist\README.md"
    !insertmacro LOG "[FILES] Application files installed successfully."

    ; =================================================================
    ; POST-INSTALLATION CONFIGURATION
    ; =================================================================
    !insertmacro LOG "[CONFIG] Starting post-installation configuration..."

    ; Step 1: Set Windows Defender exclusions (background, non-blocking)
    !insertmacro LOG "[CONFIG] Adding Defender exclusions..."
    nsExec::Exec 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -ExclusionPath \"$INSTDIR\" -Force -ErrorAction SilentlyContinue; Add-MpPreference -ExclusionProcess \"$INSTDIR\honeypot-client.exe\" -Force -ErrorAction SilentlyContinue"'

    ; Step 2: Clean up old Task Scheduler tasks (fast, parallel)
    !insertmacro LOG "[CONFIG] Cleaning up legacy Task Scheduler tasks..."
    nsExec::Exec 'schtasks /delete /tn "Cloud Honeypot Client" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "HoneypotClientAutostart" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-Background" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-Tray" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-Watchdog" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-Updater" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-SilentUpdater" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotTray" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotWatchdog" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotUpdater" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotSilentUpdater" /f >nul 2>&1'
    !insertmacro LOG "[CONFIG] Legacy tasks cleanup finished."

    ; Step 3: Create uninstaller
    !insertmacro LOG "[CONFIG] Creating uninstaller..."
    WriteUninstaller "$INSTDIR\Uninstall.exe"
    !insertmacro LOG "[CONFIG] Uninstaller created successfully."

    ; Step 4: Write registry entries for Add/Remove Programs
    !insertmacro LOG "[CONFIG] Writing registry entries..."
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
    !insertmacro LOG "[CONFIG] Registry entries written."

    ; Step 5: Create shortcuts
    !insertmacro LOG "[CONFIG] Creating shortcuts..."
    CreateShortCut "$DESKTOP\Cloud Honeypot Client.lnk" "$INSTDIR\honeypot-client.exe"
    CreateDirectory "$SMPROGRAMS\${COMPANYNAME}"
    CreateShortCut "$SMPROGRAMS\${COMPANYNAME}\Cloud Honeypot Client.lnk" "$INSTDIR\honeypot-client.exe"
    CreateShortCut "$SMPROGRAMS\${COMPANYNAME}\Uninstall.lnk" "$INSTDIR\Uninstall.exe"
    !insertmacro LOG "[CONFIG] Shortcuts created."

    ; =================================================================
    ; AUTO-START APPLICATION
    ; =================================================================
    !insertmacro LOG "[AUTO-START] Starting application..."
    
    IfFileExists "$INSTDIR\honeypot-client.exe" StartApp NoExe

    StartApp:
        ; Use correct NSIS IfSilent syntax with jump labels
        IfSilent SilentInstall NormalInstall

        SilentInstall:
            !insertmacro LOG "[AUTO-START] Starting application in daemon mode (silent install)..."
            Exec '"$INSTDIR\honeypot-client.exe" --mode=daemon --silent'
            !insertmacro LOG "[AUTO-START] Application started in daemon mode."
            Goto EndAutoStart

        NormalInstall:
            !insertmacro LOG "[AUTO-START] Starting application in GUI mode..."
            Exec '"$INSTDIR\honeypot-client.exe"'
            !insertmacro LOG "[AUTO-START] Application started - tasks will be created on first run."

        EndAutoStart:
        Goto End

    NoExe:
        !insertmacro LOG "[ERROR] Executable not found at $INSTDIR\honeypot-client.exe. Cannot auto-start."

    End:
    !insertmacro LOG "[FINISH] Installation process complete. Check log for details."
SectionEnd

; Uninstaller section
Section "Uninstall"
    ; Remove compatibility flag
    DeleteRegValue HKCU "Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" "$INSTDIR\honeypot-client.exe"
    ; Stop the application if running
    DetailPrint "Stopping Cloud Honeypot Client..."
    nsExec::ExecToLog 'taskkill /f /im honeypot-client.exe'
    Sleep 2000
    
    ; Remove all scheduled tasks (current and legacy names)
    DetailPrint "Removing scheduled tasks..."
    nsExec::ExecToLog 'powershell -ExecutionPolicy Bypass -Command "Get-ScheduledTask | Where-Object { $$_.TaskName -like \"CloudHoneypot*\" } | Unregister-ScheduledTask -Confirm:$$false -ErrorAction SilentlyContinue"'
    nsExec::ExecToLog 'schtasks /delete /tn "Cloud Honeypot Client" /f'
    nsExec::ExecToLog 'schtasks /delete /tn "HoneypotClientAutostart" /f'
    
    ; Remove Windows Defender exclusions
    DetailPrint "Removing Windows Defender exclusions..."
    nsExec::ExecToLog 'powershell -ExecutionPolicy Bypass -Command "try { Remove-MpPreference -ExclusionPath \"$INSTDIR\" -Force; Remove-MpPreference -ExclusionProcess \"$INSTDIR\honeypot-client.exe\" -Force } catch { }"'
    
    ; Remove shortcuts
    DetailPrint "Removing shortcuts..."
    Delete "$DESKTOP\Cloud Honeypot Client.lnk"
    Delete "$SMPROGRAMS\${COMPANYNAME}\Cloud Honeypot Client.lnk"
    Delete "$SMPROGRAMS\${COMPANYNAME}\Uninstall.lnk"
    RMDir "$SMPROGRAMS\${COMPANYNAME}"
    
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

