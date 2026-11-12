!macro NSIS_HOOK_PREUNINSTALL
  InitPluginsDir
  CopyFiles /SILENT "$INSTDIR\${MAINBINARYNAME}.exe" "$PLUGINSDIR\zastava-cleanup.exe"
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ${If} ${FileExists} "$PLUGINSDIR\zastava-cleanup.exe"
    ; The cleanup removes only what Zastava itself wrote (HKCU\Environment values are matched by
    ; the Zastava gateway signature), so a user's own TZ / LANG / *_PROXY variables survive.
    Push $0
    ExecWait '"$PLUGINSDIR\zastava-cleanup.exe" --cleanup' $0
    ${If} $0 <> 0
      DetailPrint "Zastava cleanup exited with code $0"
    ${EndIf}
    Pop $0
    Delete "$PLUGINSDIR\zastava-cleanup.exe"
  ${EndIf}
  ; WinINet PAC settings are Zastava's own: remove the PAC URL and switch the proxy off
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Internet Settings" "AutoConfigURL"
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Internet Settings" "ProxyEnable" 0
  ; Broadcast WM_SETTINGCHANGE ("Environment") so explorer.exe reloads environment immediately without reboot
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=2000
!macroend
