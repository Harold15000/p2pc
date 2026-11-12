; SPDX-License-Identifier: Apache-2.0
;
; The NSIS hooks of the P2PC installer (H2 spec 8.7), included by Tauri's installer template through
; bundle.windows.nsis.installerHooks. src/capabilities.rs pins what follows.
;
; An app update is never an uninstall: Tauri's installer runs the old uninstaller with /UPDATE (it sets $UpdateMode),
; and then nothing here runs. The cleanup would otherwise delete the distro, its state and, on the hub PC, the cloud.

; Before the app's files are removed: the cleanup, which asks for confirmation, then removes the node (section 8.7
; steps 1 to 7). It exits 0 when done; any other code (cancelled, or a step that must not be skipped failed) stops the
; uninstall here, before anything of the app is removed. A broken install without the app's executable cannot run the
; cleanup: the uninstall then goes on without it.
!macro NSIS_HOOK_PREUNINSTALL
  ${If} $UpdateMode <> 1
    ; A running instance first: it would take the cleanup's start for a second start and keep it from running.
    !insertmacro CheckIfAppIsRunning "$INSTDIR\${MAINBINARYNAME}.exe" "${PRODUCTNAME}"
    ${If} ${FileExists} "$INSTDIR\${MAINBINARYNAME}.exe"
      ClearErrors
      ExecWait '"$INSTDIR\${MAINBINARYNAME}.exe" --uninstall-cleanup' $0
      ${If} ${Errors}
        StrCpy $0 1
      ${EndIf}
      ${If} $0 <> 0
        SetErrorLevel 1
        Abort "P2PC was not removed: the cleanup was cancelled or could not finish. Its log is in %TEMP% (p2pc-uninstall-*.log)."
      ${EndIf}
    ${EndIf}
  ${EndIf}
!macroend

; After the app's files are removed (the app has exited): its data folders once more, for files its webview still held
; while the cleanup ran, and the RunOnce value of first run's reboot. Never %LOCALAPPDATA%\P2PC: the cleanup deleted
; it with its backup rule, and a backup it kept must stay.
!macro NSIS_HOOK_POSTUNINSTALL
  ${If} $UpdateMode <> 1
    SetShellVarContext current
    RmDir /r "$APPDATA\${BUNDLEID}"
    RmDir /r "$LOCALAPPDATA\${BUNDLEID}"
    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\RunOnce" "${PRODUCTNAME}"
  ${EndIf}
!macroend
