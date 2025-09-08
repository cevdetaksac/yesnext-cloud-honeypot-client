; NSIS installer script for modern Windows Service deployment
; This script installs the client to Program Files, registers as a service, and creates shortcuts

Name "Cloud Client Service"
OutFile "dist\\cloud-client-installer.exe"
InstallDir "$PROGRAMFILES\CloudClient"
RequestExecutionLevel admin

Page directory
Page instfiles

Section "Install"
  SetOutPath "$INSTDIR"
  File "dist\\client-onedir.exe"

  ; Register Windows Service (calls exe with service install param)
  ExecWait '"$INSTDIR\client-onedir.exe" --install-service'

  ; Start GUI in background (no CMD window)
  ExecShell "open" "$INSTDIR\client-onedir.exe"

  ; Create shortcut on Desktop
  CreateShortCut "$DESKTOP\CloudClient.lnk" "$INSTDIR\client-onedir.exe"

  ; Write uninstall info
  WriteUninstaller "$INSTDIR\Uninstall.exe"
SectionEnd

Section "Uninstall"
  Delete "$INSTDIR\client-onedir.exe"
  Delete "$DESKTOP\CloudClient.lnk"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
SectionEnd
