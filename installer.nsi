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
!define VERSIONMAJOR 3
!define VERSIONMINOR 0
!define VERSIONBUILD 0

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
!define MUI_FINISHPAGE_TEXT "Cloud Honeypot Client v${VERSIONMAJOR}.${VERSIONMINOR}.${VERSIONBUILD} has been installed successfully.$\r$\n$\r$\nDesktop shortcut has been created.$\r$\nSystem is ready for security monitoring.$\r$\n$\r$\nCheck the box below to launch the application now."
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

; Launch app as current (non-elevated) user via explorer shell
Function LaunchAsCurrentUser
    ; Use explorer.exe to launch as the logged-in user (de-elevated)
    Exec '"$WINDIR\explorer.exe" "$INSTDIR\honeypot-client.exe"'
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
    Sleep 500

    DetailPrint "[TASKS] Deleting all CloudHoneypot scheduled tasks..."
    ; PowerShell wildcard - catches ANY CloudHoneypot* task
    nsExec::Exec 'powershell -ExecutionPolicy Bypass -Command "Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $$_.TaskName -like ''CloudHoneypot*'' } | ForEach-Object { schtasks /end /tn $$_.TaskName 2>$$null; Unregister-ScheduledTask -TaskName $$_.TaskName -Confirm:$$false -ErrorAction SilentlyContinue }"'
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
    Sleep 500

    nsExec::Exec 'powershell -ExecutionPolicy Bypass -Command "Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $$_.TaskName -like ''CloudHoneypot*'' } | ForEach-Object { schtasks /end /tn $$_.TaskName 2>$$null; Unregister-ScheduledTask -TaskName $$_.TaskName -Confirm:$$false -ErrorAction SilentlyContinue }"'
    Pop $0

    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-Background" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-Tray" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-Watchdog" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-Updater" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-SilentUpdater" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-MemoryRestart" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotClientBoot" /f >nul 2>&1'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotClientLogon" /f >nul 2>&1'
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
; KILL HONEYPOT PROCESSES WITH VERIFICATION
; Uses taskkill + PowerShell fallback, verifies process is dead
; ===================================================================
Function KillHoneypotProcesses
    Push $0
    Push $1

    ; Write watchdog stop tokens to prevent respawn
    DetailPrint "[KILL] Setting watchdog stop flags..."
    nsExec::Exec 'cmd /c echo stop > "%TEMP%\honeypot_watchdog_token.txt"'
    nsExec::Exec 'cmd /c echo stop > "%APPDATA%\YesNext\CloudHoneypot\watchdog_token.txt"'
    nsExec::Exec 'cmd /c mkdir "%ProgramData%\YesNext\CloudHoneypot" 2>nul'
    nsExec::Exec 'cmd /c echo stop > "%ProgramData%\YesNext\CloudHoneypot\watchdog_stop.flag"'
    Sleep 500

    ; Round 1: taskkill with force and tree kill
    DetailPrint "[KILL] Round 1 - taskkill /f /t..."
    nsExec::Exec 'taskkill /f /t /im "honeypot-client.exe" >nul 2>&1'
    Pop $0
    Sleep 1000

    ; Check if process is still running
    nsExec::ExecToStack 'powershell -ExecutionPolicy Bypass -Command "if (Get-Process -Name honeypot-client -ErrorAction SilentlyContinue) { Write-Output RUNNING } else { Write-Output STOPPED }"'
    Pop $0  ; exit code
    Pop $1  ; stdout
    StrCmp $1 "STOPPED" KillDone

    ; Round 2: PowerShell Stop-Process
    DetailPrint "[KILL] Round 2 - PowerShell Stop-Process..."
    nsExec::Exec 'powershell -ExecutionPolicy Bypass -Command "Get-Process -Name honeypot-client -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue"'
    Pop $0
    Sleep 1500

    ; Verify again
    nsExec::ExecToStack 'powershell -ExecutionPolicy Bypass -Command "if (Get-Process -Name honeypot-client -ErrorAction SilentlyContinue) { Write-Output RUNNING } else { Write-Output STOPPED }"'
    Pop $0
    Pop $1
    StrCmp $1 "STOPPED" KillDone

    ; Round 3: taskkill again (in case task respawned between checks)
    DetailPrint "[KILL] Round 3 - final taskkill..."
    nsExec::Exec 'taskkill /f /t /im "honeypot-client.exe" >nul 2>&1'
    Pop $0
    Sleep 2000

    ; Final verification
    nsExec::ExecToStack 'powershell -ExecutionPolicy Bypass -Command "if (Get-Process -Name honeypot-client -ErrorAction SilentlyContinue) { Write-Output RUNNING } else { Write-Output STOPPED }"'
    Pop $0
    Pop $1
    StrCmp $1 "STOPPED" KillDone
    DetailPrint "[KILL] WARNING: Process may still be running. Continuing anyway..."

    KillDone:
    ; Wait for file handles to release
    DetailPrint "[KILL] Waiting for file handles to release..."
    Sleep 2000

    ; Clean up watchdog stop flags
    nsExec::Exec 'cmd /c del "%TEMP%\honeypot_watchdog_token.txt" 2>nul'
    nsExec::Exec 'cmd /c del "%ProgramData%\YesNext\CloudHoneypot\watchdog_stop.flag" 2>nul'

    Pop $1
    Pop $0
FunctionEnd

; Uninstaller variant
Function un.KillHoneypotProcesses
    Push $0
    Push $1

    DetailPrint "[KILL] Setting watchdog stop flags..."
    nsExec::Exec 'cmd /c echo stop > "%TEMP%\honeypot_watchdog_token.txt"'
    nsExec::Exec 'cmd /c echo stop > "%APPDATA%\YesNext\CloudHoneypot\watchdog_token.txt"'
    nsExec::Exec 'cmd /c mkdir "%ProgramData%\YesNext\CloudHoneypot" 2>nul'
    nsExec::Exec 'cmd /c echo stop > "%ProgramData%\YesNext\CloudHoneypot\watchdog_stop.flag"'
    Sleep 500

    DetailPrint "[KILL] Stopping honeypot-client.exe..."
    nsExec::Exec 'taskkill /f /t /im "honeypot-client.exe" >nul 2>&1'
    Pop $0
    Sleep 1000

    nsExec::ExecToStack 'powershell -ExecutionPolicy Bypass -Command "if (Get-Process -Name honeypot-client -ErrorAction SilentlyContinue) { Write-Output RUNNING } else { Write-Output STOPPED }"'
    Pop $0
    Pop $1
    StrCmp $1 "STOPPED" UnKillDone

    nsExec::Exec 'powershell -ExecutionPolicy Bypass -Command "Get-Process -Name honeypot-client -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue"'
    Pop $0
    Sleep 1500

    nsExec::Exec 'taskkill /f /t /im "honeypot-client.exe" >nul 2>&1'
    Pop $0
    Sleep 2000

    UnKillDone:
    nsExec::Exec 'cmd /c del "%TEMP%\honeypot_watchdog_token.txt" 2>nul'
    nsExec::Exec 'cmd /c del "%ProgramData%\YesNext\CloudHoneypot\watchdog_stop.flag" 2>nul'

    Pop $1
    Pop $0
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
    Sleep 1000

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

    ; Shortcuts
    !insertmacro LOG "[CONFIG] Creating shortcuts..."
    CreateShortCut "$DESKTOP\Cloud Honeypot Client.lnk" "$INSTDIR\honeypot-client.exe"
    CreateDirectory "$SMPROGRAMS\${COMPANYNAME}"
    CreateShortCut "$SMPROGRAMS\${COMPANYNAME}\Cloud Honeypot Client.lnk" "$INSTDIR\honeypot-client.exe"
    CreateShortCut "$SMPROGRAMS\${COMPANYNAME}\Uninstall.lnk" "$INSTDIR\Uninstall.exe"

    ; =================================================================
    ; PHASE 4: AUTO-START (silent install only — normal install uses finish page checkbox)
    ; =================================================================
    IfSilent 0 SkipAutoStart
        !insertmacro LOG "[AUTO-START] Silent install - starting daemon mode..."
        IfFileExists "$INSTDIR\honeypot-client.exe" SilentStart SkipAutoStart
        SilentStart:
            nsExec::Exec '"$INSTDIR\honeypot-client.exe" --create-tasks'
            Sleep 2000
            Exec '"$INSTDIR\honeypot-client.exe" --mode=daemon --silent'
            !insertmacro LOG "[AUTO-START] Daemon started with tasks pre-created."
    SkipAutoStart:

    !insertmacro LOG "[FINISH] Installation complete."
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
!insertmacro MUI_FUNCTION_DESCRIPTION_END
