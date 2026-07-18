; Cloud Honeypot Client Installer Script
; Version is injected by build.ps1 from client_constants.py
!include "MUI2.nsh"
!include "WinVer.nsh"
!include "LogicLib.nsh"

Name "Cloud Honeypot Client"
OutFile "cloud-client-installer.exe"

!define APPNAME "Cloud Honeypot Client"
!define COMPANYNAME "YesNext"
!define DESCRIPTION "Cloud Honeypot Client - System Security Monitor"
!define VERSIONMAJOR 4
!define VERSIONMINOR 5
!define VERSIONBUILD 9

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

; Finish page - "Run after install" checkbox (checked by default)
!define MUI_FINISHPAGE_TITLE "Setup Complete"
!define MUI_FINISHPAGE_TEXT "Cloud Honeypot Client v${VERSIONMAJOR}.${VERSIONMINOR}.${VERSIONBUILD} has been installed successfully.$\r$\n$\r$\nSystem is ready for security monitoring.$\r$\n$\r$\nUse the checkbox below to launch the application now."
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "Launch Cloud Honeypot Client now"
!define MUI_FINISHPAGE_RUN_FUNCTION LaunchAsCurrentUser
!define MUI_FINISHPAGE_RUN_CHECKED
!define MUI_FINISHPAGE_NOREBOOTSUPPORT
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

; Languages
!insertmacro MUI_LANGUAGE "English"

; Variables
Var LogFile

; ===================================================================
; UTILITY FUNCTIONS
; ===================================================================

; Launch app as current (non-elevated) user — ONE onefile start only.
; Never run --create-tasks then --show-gui back-to-back: PyInstaller onefile
; unpacks to %TEMP%\_MEI* and a second launch races → "Failed to load Python DLL".
Function LaunchAsCurrentUser
    SetOutPath "$INSTDIR"

    DetailPrint "[LAUNCH] Stopping leftover honeypot processes before GUI start..."
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Tray" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Background" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Watchdog" >nul 2>&1'
    IfFileExists "$PLUGINSDIR\kill-honeypot.ps1" 0 LaunchKillFallback
        nsExec::Exec 'powershell -NoProfile -ExecutionPolicy Bypass -File "$PLUGINSDIR\kill-honeypot.ps1" -Force'
        Pop $0
        Goto LaunchAfterKill
    LaunchKillFallback:
        IfFileExists "$INSTDIR\scripts\kill-honeypot.ps1" 0 LaunchTaskkill
            nsExec::Exec 'powershell -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\scripts\kill-honeypot.ps1" -Force'
            Pop $0
            Goto LaunchAfterKill
    LaunchTaskkill:
        nsExec::Exec 'taskkill /F /T /IM honeypot-client.exe >nul 2>&1'
        Pop $0
    LaunchAfterKill:
    ; Let previous _MEI* unpack dirs finish deleting
    Sleep 2000

    ; Clear stale update lock so kill/watchdog and GUI are not blocked
    ExpandEnvStrings $R9 "%ProgramData%\YesNext\CloudHoneypotClient\update_in_progress.lock"
    Delete /REBOOTOK "$R9"

    ; Single launch — app __init__ installs Task Scheduler when elevated/needed
    ExecShell "open" "$INSTDIR\honeypot-client.exe" "--show-gui"
FunctionEnd

; Simple log function
Function WriteLog
    Exch $0  ; Get the text to log
    Push $1
    
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

; Macro for easy logging
!macro LOG text
    Push "${text}"
    Call WriteLog
    DetailPrint "${text}"
!macroend

; ===================================================================
; DELETE ALL CLOUDHONEYPOT SCHEDULED TASKS
; Uses PowerShell wildcard to catch ALL task name variants
; ===================================================================
Function DeleteAllHoneypotTasks
    Push $0

    DetailPrint "[TASKS] Stopping all CloudHoneypot scheduled tasks..."
    ; End running task instances first (both naming conventions)
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Background" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Tray" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Watchdog" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Updater" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-SilentUpdater" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-MemoryRestart" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypotClientBoot" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypotClientLogon" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "HoneypotClientGuard" >nul 2>&1'
    nsExec::Exec 'schtasks /change /tn "HoneypotClientGuard" /disable >nul 2>&1'
    Sleep 300

    DetailPrint "[TASKS] Deleting all CloudHoneypot / HoneypotClient tasks..."
    ; PowerShell wildcard - catches CloudHoneypot* AND HoneypotClient* (self-protect guard)
    nsExec::Exec 'powershell -ExecutionPolicy Bypass -Command "Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $$_.TaskName -like ''CloudHoneypot*'' -or $$_.TaskName -like ''HoneypotClient*'' } | ForEach-Object { schtasks /end /tn $$_.TaskName 2>$$null; Unregister-ScheduledTask -TaskName $$_.TaskName -Confirm:$$false -ErrorAction SilentlyContinue }"'
    Pop $0

    ; Fallback: explicit deletion of every known task name (both conventions)
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-Background" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-Tray" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-Watchdog" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-Updater" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-SilentUpdater" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-MemoryRestart" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotClientBoot" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotClientLogon" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "HoneypotClientGuard" /f >nul 2>&1'
    ; Legacy names
    nsExec::Exec 'schtasks /delete /tn "Cloud Honeypot Client" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "HoneypotClientAutostart" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotTray" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotWatchdog" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotUpdater" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotSilentUpdater" /f >nul 2>&1'

    DetailPrint "[TASKS] All CloudHoneypot tasks deleted."
    Pop $0
FunctionEnd

; Uninstaller variant of task deletion
Function un.DeleteAllHoneypotTasks
    Push $0

    DetailPrint "[TASKS] Stopping all CloudHoneypot scheduled tasks..."
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Background" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Tray" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Watchdog" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Updater" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-SilentUpdater" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-MemoryRestart" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypotClientBoot" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypotClientLogon" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "HoneypotClientGuard" >nul 2>&1'
    Sleep 500

    nsExec::Exec 'powershell -ExecutionPolicy Bypass -Command "Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $$_.TaskName -like ''CloudHoneypot*'' -or $$_.TaskName -like ''HoneypotClient*'' } | ForEach-Object { schtasks /end /tn $$_.TaskName 2>$$null; Unregister-ScheduledTask -TaskName $$_.TaskName -Confirm:$$false -ErrorAction SilentlyContinue }"'
    Pop $0

    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-Background" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-Tray" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-Watchdog" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-Updater" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-SilentUpdater" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-MemoryRestart" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotClientBoot" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotClientLogon" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "HoneypotClientGuard" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "Cloud Honeypot Client" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "HoneypotClientAutostart" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotTray" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotWatchdog" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotUpdater" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotSilentUpdater" /f >nul 2>&1'

    DetailPrint "[TASKS] All CloudHoneypot tasks deleted."
    Pop $0
FunctionEnd

; ===================================================================
; FAST PRE-KILL — runs at installer startup (before UI pages)
; Uses kill-honeypot.ps1: QUIT socket + SeDebugPrivilege + task purge
; ===================================================================
Function PreInstallKillFast
    DetailPrint "[PRE-KILL] Extracting kill helper..."
    InitPluginsDir
    SetOutPath "$PLUGINSDIR"
    File "scripts\kill-honeypot.ps1"

    DetailPrint "[PRE-KILL] Stopping tasks + DACL-protected processes..."
    nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$PLUGINSDIR\kill-honeypot.ps1" -Force'
    Pop $0
    DetailPrint "[PRE-KILL] kill-honeypot.ps1 exit code: $0"
FunctionEnd

; ===================================================================
; KILL HONEYPOT PROCESSES WITH VERIFICATION (fast: 1 full kill + short poll)
; ===================================================================
Function KillHoneypotProcesses
    Push $0
    Push $1
    Push $2

    DetailPrint "[KILL] Fast shutdown sequence..."

    ; Skip full script if nothing to kill (e.g. already stopped in .onInit)
    nsExec::ExecToStack 'cmd /c (tasklist /FI "IMAGENAME eq honeypot-client.exe" 2>nul | find /I "honeypot-client.exe" >nul) && (echo RUNNING) || (echo STOPPED)'
    Pop $0
    Pop $1
    StrCmp $1 "STOPPED" KillDone

    Call PreInstallKillFast

    ; Quick verify: max 3 short polls, cheap taskkill retry (no full script loop)
    StrCpy $2 "0"
    KillWaitLoop:
        nsExec::ExecToStack 'cmd /c (tasklist /FI "IMAGENAME eq honeypot-client.exe" 2>nul | find /I "honeypot-client.exe" >nul) && (echo RUNNING) || (echo STOPPED)'
        Pop $0
        Pop $1
        StrCmp $1 "STOPPED" KillDone
        IntOp $2 $2 + 1
        IntCmp $2 3 KillForce KillWaitMore KillForce
        KillWaitMore:
            DetailPrint "[KILL] Still running - quick retry $2..."
            nsExec::Exec 'taskkill /F /T /IM honeypot-client.exe >nul 2>&1'
            Pop $0
            Sleep 150
            Goto KillWaitLoop

    KillForce:
        DetailPrint "[KILL] Final kill pass..."
        Call PreInstallKillFast
        Sleep 150

    KillDone:
    DetailPrint "[KILL] Process shutdown complete."
    nsExec::Exec 'cmd /c del "%TEMP%\honeypot_watchdog_token.txt" 2>nul'
    Sleep 300

    Pop $2
    Pop $1
    Pop $0
FunctionEnd

; Uninstaller variant
Function un.KillHoneypotProcesses
    Push $0
    Push $1

    DetailPrint "[KILL] Uninstall shutdown..."
    Call un.PreInstallKillFast

    nsExec::Exec 'taskkill /f /t /im "honeypot-client.exe" >nul 2>&1'
    Pop $0
    Sleep 300

    nsExec::Exec 'cmd /c del "%TEMP%\honeypot_watchdog_token.txt" 2>nul'
    nsExec::Exec 'cmd /c del "%ProgramData%\YesNext\CloudHoneypot\watchdog_stop.flag" 2>nul'

    Pop $1
    Pop $0
FunctionEnd

Function un.PreInstallKillFast
    DetailPrint "[PRE-KILL] Uninstall stop sequence..."
    nsExec::Exec 'cmd /c echo stop > "%TEMP%\honeypot_watchdog_token.txt"'
    nsExec::Exec 'cmd /c echo stop > "%APPDATA%\YesNext\CloudHoneypot\watchdog_token.txt"'
    nsExec::Exec 'cmd /c mkdir "%ProgramData%\YesNext\CloudHoneypot" 2>nul'
    nsExec::Exec 'cmd /c echo stop > "%ProgramData%\YesNext\CloudHoneypot\watchdog_stop.flag"'
    nsExec::Exec 'cmd /c echo stop > "%APPDATA%\YesNext\CloudHoneypotClient\watchdog.token"'
    nsExec::Exec 'schtasks /end /tn "HoneypotClientGuard" >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "HoneypotClientGuard" /f >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Watchdog" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Background" >nul 2>&1'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Tray" >nul 2>&1'

    ; Prefer installed kill helper (SeDebugPrivilege)
    IfFileExists "$INSTDIR\scripts\kill-honeypot.ps1" 0 UnKillFallback
        nsExec::ExecToLog 'powershell -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\scripts\kill-honeypot.ps1" -Force'
        Pop $0
        Goto UnKillDone

    UnKillFallback:
        ; QUIT + WMI terminate (admin) fallback when script missing
        nsExec::Exec 'powershell -NoProfile -ExecutionPolicy Bypass -Command "try{$$c=New-Object Net.Sockets.TcpClient;$$iar=$$c.BeginConnect(\"127.0.0.1\",58632,$$null,$$null);$$iar.AsyncWaitHandle.WaitOne(800)|Out-Null;if($$c.Connected){$$b=[Text.Encoding]::ASCII.GetBytes(\"QUIT`n\");$$c.GetStream().Write($$b,0,$$b.Length)};$$c.Close()}catch{}"'
        Pop $0
        Sleep 500
        nsExec::Exec 'powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-CimInstance Win32_Process -Filter \"Name=''honeypot-client.exe''\" | ForEach-Object { $$_.Terminate() }; taskkill /F /T /IM honeypot-client.exe 2>$$null"'
        Pop $0
        Sleep 400

    UnKillDone:
    Sleep 150
FunctionEnd

; ===================================================================
; INITIALIZATION
; ===================================================================
Function .onInit
    StrCpy $LogFile "$LOCALAPPDATA\honeypot-installer.log"
    Delete $LogFile

    Push "=== CLOUD HONEYPOT CLIENT v${VERSIONMAJOR}.${VERSIONMINOR}.${VERSIONBUILD} INSTALLER ==="
    Call WriteLog
    Push "Installation started with admin privileges"
    Call WriteLog
    Push "Log file location: $LogFile"
    Call WriteLog

    ; Kill running client instances before installer UI appears
    Call PreInstallKillFast
FunctionEnd

; ===================================================================
; MAIN INSTALL SECTION
; ===================================================================
Section "Cloud Honeypot Client (Required)" SEC_MAIN
    SectionIn RO

    ; =================================================================
    ; PHASE 1: PRE-INSTALLATION CLEANUP
    ; =================================================================
    !insertmacro LOG "[PHASE 1] Starting pre-installation cleanup..."

    ; Step 1: Delete ALL scheduled tasks FIRST (prevents respawn)
    !insertmacro LOG "[PREP] Step 1 - Deleting all scheduled tasks..."
    Call DeleteAllHoneypotTasks
    Sleep 200

    ; Step 2: Kill all honeypot processes with verification
    !insertmacro LOG "[PREP] Step 2 - Killing honeypot processes..."
    Call KillHoneypotProcesses

    !insertmacro LOG "[PHASE 1] Pre-installation cleanup complete."

    ; =================================================================
    ; PHASE 2: FILE INSTALLATION
    ; =================================================================
    !insertmacro LOG "[PHASE 2] Starting file installation..."
    !insertmacro LOG "[INSTALL] Target directory: $INSTDIR"
    SetOutPath $INSTDIR

    ; Install main files
    !insertmacro LOG "[FILES] Installing application files..."
    File /oname=honeypot-client.exe "dist\honeypot-client.exe"
    File /oname=client_config.json "dist\client_config.json"
    File /oname=client_lang.json "dist\client_lang.json"
    File /oname=LICENSE "dist\LICENSE"
    File /oname=README.md "dist\README.md"
    CreateDirectory "$INSTDIR\scripts"
    File /oname=scripts\kill-honeypot.ps1 "scripts\kill-honeypot.ps1"
    File /oname=scripts\update-and-install.ps1 "scripts\update-and-install.ps1"
    File /oname=scripts\memory_restart.ps1 "memory_restart.ps1"
    !insertmacro LOG "[FILES] Application files installed."

    ; =================================================================
    ; PHASE 3: POST-INSTALLATION CONFIGURATION
    ; =================================================================
    !insertmacro LOG "[PHASE 3] Starting post-installation configuration..."

    ; Windows Defender exclusions (non-blocking)
    !insertmacro LOG "[CONFIG] Adding Defender exclusions..."
    nsExec::Exec 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -ExclusionPath \"$INSTDIR\" -Force -ErrorAction SilentlyContinue; Add-MpPreference -ExclusionProcess \"$INSTDIR\honeypot-client.exe\" -Force -ErrorAction SilentlyContinue"'

    ; Create uninstaller
    !insertmacro LOG "[CONFIG] Creating uninstaller..."
    WriteUninstaller "$INSTDIR\Uninstall.exe"

    ; Registry entries for Add/Remove Programs
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

    ; Start Menu shortcuts (always)
    !insertmacro LOG "[CONFIG] Creating Start Menu shortcuts..."
    CreateDirectory "$SMPROGRAMS\${COMPANYNAME}"
    CreateShortCut "$SMPROGRAMS\${COMPANYNAME}\Cloud Honeypot Client.lnk" "$INSTDIR\honeypot-client.exe" "--show-gui"
    CreateShortCut "$SMPROGRAMS\${COMPANYNAME}\Uninstall.lnk" "$INSTDIR\Uninstall.exe"

    ; =================================================================
    ; PHASE 4: AUTO-START (silent install only — normal install uses finish page checkbox)
    ; =================================================================
    IfSilent 0 InteractiveOnboarding
        !insertmacro LOG "[AUTO-START] Silent install - starting daemon mode..."
        IfFileExists "$INSTDIR\honeypot-client.exe" SilentStart SkipAutoStart
        SilentStart:
            ; ONE onefile launch only (daemon __init__ creates scheduled tasks).
            ; Back-to-back --create-tasks + daemon caused _MEI python312.dll failures.
            Sleep 1500
            Exec '"$INSTDIR\honeypot-client.exe" --mode=daemon --silent'
            !insertmacro LOG "[AUTO-START] Daemon started (single launch)."
        Goto SkipAutoStart
    InteractiveOnboarding:
        ; Force visible GUI until user registers / links account (no tray hide)
        ; Use %ProgramData% — reliable on all NSIS versions ($COMMONPROGRAMDATA may be empty)
        ExpandEnvStrings $1 "%ProgramData%\YesNext\CloudHoneypotClient"
        CreateDirectory "$1"
        FileOpen $0 "$1\force_gui_onboarding.flag" w
        FileWrite $0 "interactive_install$\r$\n"
        FileClose $0
        !insertmacro LOG "[ONBOARDING] force_gui_onboarding.flag written — GUI will stay visible"
        ; End tray/daemon so finish-page --show-gui is not killed by singleton
        nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Tray" >nul 2>&1'
        nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Background" >nul 2>&1'
    SkipAutoStart:

    !insertmacro LOG "[FINISH] Installation complete."
SectionEnd

; Optional Components-page checkbox (UNCHECKED by default — user must opt in).
; Start Menu shortcut is always created in SEC_MAIN.
Section /o "Desktop Shortcut" SEC_DESKTOP
    !insertmacro LOG "[CONFIG] Creating desktop shortcut..."
    CreateShortCut "$DESKTOP\Cloud Honeypot Client.lnk" "$INSTDIR\honeypot-client.exe" "--show-gui"
SectionEnd

; ===================================================================
; UNINSTALLER SECTION
; ===================================================================
Section "Uninstall"
    ; Remove compatibility flag
    DeleteRegValue HKCU "Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers" "$INSTDIR\honeypot-client.exe"

    ; Phase 1: Stop everything
    DetailPrint "Phase 1: Stopping all services..."
    Call un.DeleteAllHoneypotTasks
    Call un.KillHoneypotProcesses

    ; Phase 2: Remove Windows Defender exclusions
    DetailPrint "Removing Windows Defender exclusions..."
    nsExec::ExecToLog 'powershell -ExecutionPolicy Bypass -Command "try { Remove-MpPreference -ExclusionPath \"$INSTDIR\" -Force; Remove-MpPreference -ExclusionProcess \"$INSTDIR\honeypot-client.exe\" -Force } catch { }"'

    ; Phase 3: Remove shortcuts
    DetailPrint "Removing shortcuts..."
    Delete "$DESKTOP\Cloud Honeypot Client.lnk"
    Delete "$SMPROGRAMS\${COMPANYNAME}\Cloud Honeypot Client.lnk"
    Delete "$SMPROGRAMS\${COMPANYNAME}\Uninstall.lnk"
    RMDir "$SMPROGRAMS\${COMPANYNAME}"

    ; Phase 4: Remove files
    DetailPrint "Removing application files..."
    Delete "$INSTDIR\honeypot-client.exe"
    Delete "$INSTDIR\client_config.json"
    Delete "$INSTDIR\client_lang.json"
    Delete "$INSTDIR\LICENSE"
    Delete "$INSTDIR\README.md"
    Delete "$INSTDIR\scripts\kill-honeypot.ps1"
    Delete "$INSTDIR\scripts\update-and-install.ps1"
    Delete "$INSTDIR\scripts\memory_restart.ps1"
    RMDir "$INSTDIR\scripts"
    Delete "$INSTDIR\Uninstall.exe"
    RMDir "$INSTDIR"

    ; Phase 5: Remove registry entries
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}"

    ; Phase 6: Clean up app data
    DetailPrint "Cleaning up watchdog tokens..."
    nsExec::Exec 'cmd /c del "%APPDATA%\YesNext\CloudHoneypot\watchdog_token.txt" 2>nul'
    nsExec::Exec 'cmd /c del "%ProgramData%\YesNext\CloudHoneypot\watchdog_stop.flag" 2>nul'

    DetailPrint "Cloud Honeypot Client has been completely removed."
SectionEnd

; Section descriptions
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
!insertmacro MUI_DESCRIPTION_TEXT ${SEC_MAIN} "Core Cloud Honeypot Client application and configuration files. This component is required."
!insertmacro MUI_DESCRIPTION_TEXT ${SEC_DESKTOP} "Optional: create a desktop shortcut. Off by default — check to enable."
!insertmacro MUI_FUNCTION_DESCRIPTION_END
