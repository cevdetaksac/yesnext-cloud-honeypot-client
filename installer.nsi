; NSIS installer script for modern Windows Service deployment
; This script installs the client to Program Files, registers as a service, and creates shortcuts

Name "Cloud Client Service"
OutFile "dist\\cloud-client-installer.exe"
InstallDir "$PROGRAMFILES\CloudClient"
RequestExecutionLevel admin

Page directory
Page instfiles

Section "Install"
  ; Stop existing service and processes first
  nsExec::ExecToLog 'sc stop CloudHoneypotClientService'
  Sleep 2000 ; Give some time for service to stop
  
  ; Kill all running client processes (more reliable than taskkill)
  nsExec::ExecToLog 'powershell -NoProfile -Command "Stop-Process -Name client-onedir -Force -ErrorAction SilentlyContinue"'
  Sleep 2000 ; Give more time for all processes to be fully terminated
  
  SetOutPath "$INSTDIR"
  File "dist\\client-onedir.exe"

  ; Register Windows Service silently (no GUI)
  ExecWait '"$INSTDIR\client-onedir.exe" --install-service-silent'

  ; Start service
  nsExec::ExecToLog 'sc start CloudHoneypotClientService'
  Sleep 2000 ; Give service time to start

  ; Start GUI in background AFTER service is started (no CMD window)
  ExecShell "open" "$INSTDIR\client-onedir.exe" "" SW_NORMAL

  ; Create shortcut on Desktop
  CreateShortCut "$DESKTOP\CloudClient.lnk" "$INSTDIR\client-onedir.exe"

  ; Write uninstall info
  WriteUninstaller "$INSTDIR\Uninstall.exe"
SectionEnd

Section "Uninstall"
  ; Stop service and processes before uninstalling
  nsExec::ExecToLog 'sc stop CloudHoneypotClientService'
  Sleep 2000
  ; Kill all processes (more reliable than taskkill)
  nsExec::ExecToLog 'powershell -NoProfile -Command "Stop-Process -Name client-onedir -Force -ErrorAction SilentlyContinue"'
  Sleep 2000
  
  ; Remove service
  nsExec::ExecToLog 'sc delete CloudHoneypotClientService'
  Sleep 1000
  
  Delete "$INSTDIR\client-onedir.exe"
  Delete "$DESKTOP\CloudClient.lnk"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
SectionEnd
