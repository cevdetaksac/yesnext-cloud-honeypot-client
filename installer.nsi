; Cloud Honeypot Client Installer Script - v2.8.3
; Enhanced installer process cleanup + GUI state preservation
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
!define VERSIONBUILD 3

InstallDir "$PROGRAMFILES64\${COMPANYNAME}\${APPNAME}"

!define MAX_PROCESS_KILL_ATTEMPTS 5

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
!define MUI_FINISHPAGE_TEXT "Cloud Honeypot Client v2.8.3 installed successfully$\r$\n$\r$\nApplication will start automatically$\r$\nDesktop shortcut has been created$\r$\nSystem is ready for security monitoring$\r$\n$\r$\nInstaller will close automatically..."
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

; Forcefully stop a running process by base name (without .exe)
Function ForceStopProcess
    Exch $0
    Push $1
    Push $2
    Push $3
    Push $4
    Push $5
    StrCpy $1 0
    StrCpy $2 "$0.exe"
ForceStopRetry:
    IntOp $3 $1 + 1
    StrCpy $5 "[PREP] Attempting to stop $2 (attempt $3/${MAX_PROCESS_KILL_ATTEMPTS})..."
    Push $5
    Call WriteLog
    DetailPrint $5
    
    ; First try gentle termination
    nsExec::Exec 'taskkill /t /im "$2" >nul 2>&1'
    Sleep 2000
    
    ; Check if still running
    nsExec::Exec 'powershell -ExecutionPolicy Bypass -Command "if (Get-Process -Name `"$0`" -ErrorAction SilentlyContinue) { exit 1 } else { exit 0 }"'
    Pop $4
    StrCmp $4 "0" ForceStopOkay 0
    
    ; Force kill if still running
    nsExec::Exec 'taskkill /f /t /im "$2" >nul 2>&1'
    Sleep 2000
    
    ; Final check
    nsExec::Exec 'powershell -ExecutionPolicy Bypass -Command "if (Get-Process -Name `"$0`" -ErrorAction SilentlyContinue) { exit 1 } else { exit 0 }"'
    Pop $4
    StrCmp $4 "0" ForceStopOkay 0
    
    IntOp $1 $1 + 1
    IntCmp $1 ${MAX_PROCESS_KILL_ATTEMPTS} ForceStopFailed ForceStopRetry ForceStopRetry
ForceStopOkay:
    StrCpy $5 "[PREP] $2 confirmed stopped."
    Push $5
    Call WriteLog
    DetailPrint $5
    Goto ForceStopDone
ForceStopFailed:
    StrCpy $5 "[PREP][WARNING] Failed to stop $2 after ${MAX_PROCESS_KILL_ATTEMPTS} attempts. It may still be running."
    Push $5
    Call WriteLog
    DetailPrint $5
ForceStopDone:
    Pop $5
    Pop $4
    Pop $3
    Pop $2
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
    
    ; Step 1: Stop all running honeypot tasks
    !insertmacro LOG "[PREP] Stopping all CloudHoneypot scheduled tasks..."
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Background"'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Tray"'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Watchdog"'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-Updater"'
    nsExec::Exec 'schtasks /end /tn "CloudHoneypot-SilentUpdater"'
    Sleep 1000

    ; Step 2: Terminate running honeypot processes
    !insertmacro LOG "[PREP] Terminating running honeypot processes..."
    
    ; Stop all related processes with comprehensive approach
    Push "honeypot-client"
    Call ForceStopProcess
    
    ; Also check for any Python processes running our script
    !insertmacro LOG "[PREP] Checking for Python processes running honeypot client..."
    nsExec::Exec 'powershell -ExecutionPolicy Bypass -Command "Get-Process | Where-Object { $_.ProcessName -eq \"python\" -or $_.ProcessName -eq \"pythonw\" } | Where-Object { $_.MainModule.FileName -like \"*honeypot*\" -or $_.CommandLine -like \"*client.py*\" } | Stop-Process -Force -ErrorAction SilentlyContinue"'
    
    ; Additional cleanup for any remaining honeypot processes
    nsExec::Exec 'powershell -ExecutionPolicy Bypass -Command "Get-Process | Where-Object { $_.ProcessName -like \"*honeypot*\" } | Stop-Process -Force -ErrorAction SilentlyContinue"'
    
    ; Wait for processes to fully terminate
    Sleep 3000
    
    ; Final verification
    !insertmacro LOG "[PREP] Verifying all honeypot processes are stopped..."
    nsExec::Exec 'powershell -ExecutionPolicy Bypass -Command "if (Get-Process -Name \"honeypot-client\" -ErrorAction SilentlyContinue) { Write-Host \"WARNING: honeypot-client still running\" } else { Write-Host \"OK: honeypot-client stopped\" }"'
    
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

    ; Step 1: Set Windows Defender exclusions
    !insertmacro LOG "[CONFIG] Adding Defender exclusions..."
    nsExec::ExecToLog 'powershell -ExecutionPolicy Bypass -Command "Add-MpPreference -ExclusionPath \"$INSTDIR\" -Force; Add-MpPreference -ExclusionProcess \"$INSTDIR\honeypot-client.exe\" -Force"'
    Pop $0
    !insertmacro LOG "[CONFIG] Defender exclusion exit code: $0"

    ; Step 2: Clean up old Task Scheduler tasks
    !insertmacro LOG "[CONFIG] Cleaning up legacy Task Scheduler tasks..."
    nsExec::Exec 'schtasks /delete /tn "Cloud Honeypot Client" /f'
    nsExec::Exec 'schtasks /delete /tn "HoneypotClientAutostart" /f'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypot-Background" /f'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotTray" /f'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotWatchdog" /f'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotUpdater" /f'
    nsExec::Exec 'schtasks /delete /tn "CloudHoneypotSilentUpdater" /f'
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

