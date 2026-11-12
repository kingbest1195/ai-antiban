!macro NSIS_HOOK_PREUNINSTALL
  InitPluginsDir
  CopyFiles /SILENT "$INSTDIR\${MAINBINARYNAME}.exe" "$PLUGINSDIR\zastava-cleanup.exe"
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ${If} ${FileExists} "$PLUGINSDIR\zastava-cleanup.exe"
    ; The cleanup restores only what Zastava itself changed (from the ownership journal; legacy
    ; leftovers by the Zastava gateway signature), so a user's own settings survive.
    Push $0
    ExecWait '"$PLUGINSDIR\zastava-cleanup.exe" --cleanup' $0
    ${If} $0 <> 0
      DetailPrint "Zastava cleanup exited with code $0"
    ${EndIf}
    Pop $0
    Delete "$PLUGINSDIR\zastava-cleanup.exe"
  ${EndIf}
  ; No unconditional WinINet reset here: AutoConfigURL / ProxyEnable are restored by --cleanup
  ; from the ownership journal, and only if Zastava changed them (a user's own PAC survives).
  ; Broadcast WM_SETTINGCHANGE ("Environment") so explorer.exe reloads environment immediately without reboot
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=2000
!macroend
