; Order of the Tauri NSIS uninstaller (tauri-bundler 2.x installer.nsi, `Section Uninstall`):
;   1. NSIS_HOOK_PREUNINSTALL
;   2. CheckIfAppIsRunning (asks to close the app, then RmShutdown)
;   3. delete $INSTDIR files, shortcuts, registry
;   4. "Delete app data" checkbox: RmDir /r "$APPDATA\${BUNDLEID}" and "$LOCALAPPDATA\${BUNDLEID}"
;   5. NSIS_HOOK_POSTUNINSTALL
; The ownership journal lives in that app data directory, so a cleanup in POSTUNINSTALL runs
; after the checkbox has erased it and could only guess by signature. The cleanup therefore runs
; in PREUNINSTALL, right after the app has been closed.

!macro NSIS_HOOK_PREUNINSTALL
  ; The template checks for the running app only after this hook. `--cleanup` leaves a running app
  ; alone (it restores its own settings), so close it first, exactly as the template does.
  !insertmacro CheckIfAppIsRunning "$INSTDIR\${MAINBINARYNAME}.exe" "${PRODUCTNAME}"

  ; The cleanup restores only what Zastava itself changed (from the ownership journal; legacy
  ; leftovers by the Zastava gateway signature), so a user's own settings survive. The exe is
  ; still in $INSTDIR here and the call returns before the template deletes it. Exit codes:
  ; 0 ok, 1 something could not be restored yet, 2 journal busy or unusable (nothing was changed).
  ; Anything but 0 is repeated for about ten seconds (a journal lock held by the app that is
  ; still shutting down), then reported.
  Push $0
  Push $1
  StrCpy $1 0
  ${Do}
    ExecWait '"$INSTDIR\${MAINBINARYNAME}.exe" --cleanup' $0
    ${If} $0 == "error"
      ${ExitDo}
    ${EndIf}
    ${If} $0 = 0
      ${ExitDo}
    ${EndIf}
    IntOp $1 $1 + 1
    ${If} $1 >= 5
      ${ExitDo}
    ${EndIf}
    Sleep 2000
  ${Loop}
  ${If} $0 == "error"
    DetailPrint "Zastava cleanup could not be started"
  ${ElseIf} $0 <> 0
    DetailPrint "Zastava cleanup did not finish (code $0, attempts $1)"
  ${EndIf}
  Pop $1
  Pop $0

  ; Clean up OS autostart entry and CoworkVMService boot-guard scheduled task if installed.
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "Zastava"
  ExecWait '"$SYSDIR\schtasks.exe" /Delete /TN "\Zastava\CoworkVMServiceManualGuard" /F'
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ; No unconditional WinINet reset here: AutoConfigURL / ProxyEnable are restored by --cleanup
  ; (PREUNINSTALL) from the ownership journal, and only if Zastava changed them (a user's own PAC
  ; survives).
  ; Broadcast WM_SETTINGCHANGE ("Environment") so explorer.exe reloads environment immediately without reboot
  SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=2000
!macroend
