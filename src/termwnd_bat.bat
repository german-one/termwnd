:: Copyright (c) Steffen Illhardt
:: Licensed under the MIT license.

:: Min. req.: PowerShell v.5.1

@echo off &setlocal

call :init_TermWnd
call :init_FadeWnd

setlocal EnableDelayedExpansion
for /l %%i in () do (
  %TermWnd%
  if not errorlevel 1 goto :eof
  set "wnd=!errorlevel!"
  echo Term HWND:  0X!=exitcode!
  echo(

  %FadeWnd% 0 1 100 1 !wnd!
  %FadeWnd% 100 -1 0 1 !wnd!

  REM [Terminal version >= 1.18] Gives you some time to move the tab out or attach it to another window.
  >nul timeout /t 5 /nobreak
)
goto :eof

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:init_TermWnd
setlocal DisableDelayedExpansion
:: prefer PowerShell Core if installed
for %%i in ("pwsh.exe") do if "%%~$PATH:i"=="" (set "ps=powershell") else set "ps=pwsh"

:: - BRIEF -
::  Get the main window handle of the terminal which is connected to the batch process.
::   The HWND is returned as errorlevel value.
::   NOTE: Only console host and Windows Terminal are supported.
:: - SYNTAX -
::  %TermWnd%
:: - EXAMPLES -
::  Get the HWND of the terminal window:
::    %TermWnd%
::    echo HWND: %errorlevel%
set TermWnd=^
%=% %ps%.exe -nop -ep Bypass -c ^"^
%===% try { Add-Type -EA SilentlyContinue -TypeDefinition '^
%=====% using System;^
%=====% using System.Diagnostics;^
%=====% using System.IO;^
%=====% using System.Runtime.ConstrainedExecution;^
%=====% using System.Runtime.InteropServices;^
%=====% using System.Text;^
%=====% using System.Threading;^
%=====% public static class WinTerm {^
%=======% private static class NativeMethods {^
%=========% [DllImport(\"kernel32.dll\")]^
%=========% internal static extern int CloseHandle(IntPtr Hndl);^
%=========% [DllImport(\"kernelbase.dll\")]^
%=========% internal static extern int CompareObjectHandles(IntPtr hFirst, IntPtr hSecond);^
%=========% [DllImport(\"kernel32.dll\")]^
%=========% internal static extern int DuplicateHandle(IntPtr SrcProcHndl, IntPtr SrcHndl, IntPtr TrgtProcHndl, out IntPtr TrgtHndl, int Acc, int Inherit, int Opts);^
%=========% [DllImport(\"user32.dll\")]^
%=========% [return: MarshalAs(UnmanagedType.Bool)]^
%=========% internal static extern bool EnumWindows(EnumWindowsProc enumFunc, IntPtr param);^
%=========% [DllImport(\"user32.dll\")]^
%=========% internal static extern IntPtr GetAncestor(IntPtr hWnd, int flgs);^
%=========% [DllImport(\"kernel32.dll\")]^
%=========% internal static extern IntPtr GetConsoleWindow();^
%=========% [DllImport(\"kernel32.dll\")]^
%=========% internal static extern IntPtr GetCurrentProcess();^
%=========% [DllImport(\"user32.dll\")]^
%=========% internal static extern IntPtr GetWindow(IntPtr hWnd, int cmd);^
%=========% [DllImport(\"user32.dll\")]^
%=========% internal static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint procId);^
%=========% [DllImport(\"ntdll.dll\")]^
%=========% internal static extern int NtQuerySystemInformation(int SysInfClass, IntPtr SysInf, int SysInfLen, out int RetLen);^
%=========% [DllImport(\"kernel32.dll\")]^
%=========% internal static extern IntPtr OpenProcess(int Acc, int Inherit, uint ProcId);^
%=========% [DllImport(\"kernel32.dll\", CharSet = CharSet.Unicode)]^
%=========% internal static extern int QueryFullProcessImageNameW(IntPtr Proc, int Flgs, StringBuilder Name, ref int Size);^
%=========% [DllImport(\"user32.dll\")]^
%=========% internal static extern IntPtr SendMessageW(IntPtr hWnd, int Msg, IntPtr wParam, IntPtr lParam);^
%=======% }^
%=======% private static readonly IntPtr conWnd = NativeMethods.GetConsoleWindow();^
%=======% public static IntPtr hWnd = IntPtr.Zero;^
%=======% public static uint pid = 0;^
%=======% public static uint tid = 0;^
%=======% public static string baseName = string.Empty;^
%=======% private class SafeRes : CriticalFinalizerObject, IDisposable {^
%=========% internal enum ResType { MemoryPointer, Handle }^
%=========% private IntPtr raw = IntPtr.Zero;^
%=========% private readonly ResType resourceType = ResType.MemoryPointer;^
%=========% internal IntPtr Raw { get { return raw; } }^
%=========% internal bool IsInvalid { get { return raw == IntPtr.Zero ^^^|^^^| raw == new IntPtr(-1); } }^
%=========% internal SafeRes(IntPtr raw, ResType resourceType) {^
%===========% this.raw = raw;^
%===========% this.resourceType = resourceType;^
%=========% }^
%=========% ~SafeRes() { Dispose(false); }^
%=========% public void Dispose() {^
%===========% Dispose(true);^
%===========% GC.SuppressFinalize(this);^
%=========% }^
%=========% protected virtual void Dispose(bool disposing) {^
%===========% if (IsInvalid) { return; }^
%===========% if (resourceType == ResType.MemoryPointer) {^
%=============% Marshal.FreeHGlobal(raw);^
%=============% raw = IntPtr.Zero;^
%=============% return;^
%===========% }^
%===========% if ((NativeMethods.CloseHandle(raw) == 0) == false) { raw = new IntPtr(-1); }^
%=========% }^
%=========% internal virtual void Reset(IntPtr raw) {^
%===========% Dispose();^
%===========% this.raw = raw;^
%=========% }^
%=======% }^
%=======% [StructLayout(LayoutKind.Sequential)]^
%=======% private struct SystemHandle {^
%=========% internal readonly uint ProcId;^
%=========% internal readonly byte ObjTypeId;^
%=========% internal readonly byte Flgs;^
%=========% internal readonly ushort Handle;^
%=========% internal readonly IntPtr pObj;^
%=========% internal readonly uint Acc;^
%=======% }^
%=======% private static string GetProcBaseName(SafeRes sHProc) {^
%=========% int size = 1024;^
%=========% StringBuilder nameBuf = new StringBuilder(size);^
%=========% return NativeMethods.QueryFullProcessImageNameW(sHProc.Raw, 0, nameBuf, ref size) == 0 ? \"\" : Path.GetFileNameWithoutExtension(nameBuf.ToString(0, size));^
%=======% }^
%=======% private static uint GetPidOfNamedProcWithOpenProcHandle(string searchProcName, uint findOpenProcId) {^
%=========% const int PROCESS_DUP_HANDLE = 0x0040,^
%===================% PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,^
%===================% STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xc0000004),^
%===================% SystemHandleInformation = 16;^
%=========% const byte OB_TYPE_INDEX_JOB = 7;^
%=========% int status, infSize = 0x200000, len;^
%=========% using (SafeRes sPSysHndlInf = new SafeRes(Marshal.AllocHGlobal(infSize), SafeRes.ResType.MemoryPointer)) {^
%===========% while ((status = NativeMethods.NtQuerySystemInformation(SystemHandleInformation, sPSysHndlInf.Raw, infSize, out len)) == STATUS_INFO_LENGTH_MISMATCH) {^
%=============% sPSysHndlInf.Reset(Marshal.AllocHGlobal(infSize = len + 0x1000));^
%===========% }^
%===========% if (status ^^^< 0) { return 0; }^
%===========% using (SafeRes sHFindOpenProc = new SafeRes(NativeMethods.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, findOpenProcId), SafeRes.ResType.Handle)) {^
%=============% if (sHFindOpenProc.IsInvalid) { return 0; }^
%=============% uint foundPid = 0, curPid = 0;^
%=============% IntPtr hThis = NativeMethods.GetCurrentProcess();^
%=============% int sysHndlSize = Marshal.SizeOf(typeof(SystemHandle));^
%=============% using (SafeRes sHCur = new SafeRes(IntPtr.Zero, SafeRes.ResType.Handle)) {^
%===============% for (IntPtr pSysHndl = (IntPtr)((long)sPSysHndlInf.Raw + IntPtr.Size), pEnd = (IntPtr)((long)pSysHndl + Marshal.ReadInt32(sPSysHndlInf.Raw) * sysHndlSize);^
%====================% (pSysHndl == pEnd) == false;^
%====================% pSysHndl = (IntPtr)((long)pSysHndl + sysHndlSize)) {^
%=================% SystemHandle sysHndl = (SystemHandle)Marshal.PtrToStructure(pSysHndl, typeof(SystemHandle));^
%=================% if ((sysHndl.ObjTypeId == OB_TYPE_INDEX_JOB) == false) { continue; }^
%=================% if ((curPid == sysHndl.ProcId) == false) {^
%===================% curPid = sysHndl.ProcId;^
%===================% sHCur.Reset(NativeMethods.OpenProcess(PROCESS_DUP_HANDLE ^^^| PROCESS_QUERY_LIMITED_INFORMATION, 0, curPid));^
%=================% }^
%=================% IntPtr hCurOpenDup;^
%=================% if (sHCur.IsInvalid ^^^|^^^|^
%=====================% NativeMethods.DuplicateHandle(sHCur.Raw, (IntPtr)sysHndl.Handle, hThis, out hCurOpenDup, PROCESS_QUERY_LIMITED_INFORMATION, 0, 0) == 0) {^
%===================% continue;^
%=================% }^
%=================% using (SafeRes sHCurOpenDup = new SafeRes(hCurOpenDup, SafeRes.ResType.Handle)) {^
%===================% if ((NativeMethods.CompareObjectHandles(sHCurOpenDup.Raw, sHFindOpenProc.Raw) == 0) == false ^^^&^^^&^
%=======================% searchProcName == GetProcBaseName(sHCur)) {^
%=====================% foundPid = curPid;^
%=====================% break;^
%===================% }^
%=================% }^
%===============% }^
%=============% }^
%=============% return foundPid;^
%===========% }^
%=========% }^
%=======% }^
%=======% private static uint findPid;^
%=======% private static IntPtr foundHWnd;^
%=======% private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);^
%=======% private static bool GetOpenConWndCallback(IntPtr hWnd, IntPtr lParam) {^
%=========% uint thisPid;^
%=========% uint thisTid = NativeMethods.GetWindowThreadProcessId(hWnd, out thisPid);^
%=========% if (thisTid == 0 ^^^|^^^| (thisPid == findPid) == false) { return true; }^
%=========% foundHWnd = hWnd;^
%=========% return false;^
%=======% }^
%=======% private static IntPtr GetOpenConWnd(uint termPid) {^
%=========% if (termPid == 0) { return IntPtr.Zero; }^
%=========% findPid = termPid;^
%=========% foundHWnd = IntPtr.Zero;^
%=========% NativeMethods.EnumWindows(new EnumWindowsProc(GetOpenConWndCallback), IntPtr.Zero);^
%=========% return foundHWnd;^
%=======% }^
%=======% private static IntPtr GetTermWnd(ref bool terminalExpected) {^
%=========% const int WM_GETICON = 0x007F,^
%===================% GW_OWNER = 4,^
%===================% GA_ROOTOWNER = 3;^
%=========% terminalExpected = NativeMethods.SendMessageW(conWnd, WM_GETICON, IntPtr.Zero, IntPtr.Zero) == IntPtr.Zero;^
%=========% if (terminalExpected == false) { return conWnd; }^
%=========% IntPtr conOwner = IntPtr.Zero;^
%=========% for (int i = 0; i ^^^< 200 ^^^&^^^& conOwner == IntPtr.Zero; ++i) {^
%===========% Thread.Sleep(5);^
%===========% conOwner = NativeMethods.GetWindow(conWnd, GW_OWNER);^
%=========% }^
%=========% if (conOwner == IntPtr.Zero) { return IntPtr.Zero; }^
%=========% uint shellPid;^
%=========% uint shellTid = NativeMethods.GetWindowThreadProcessId(conWnd, out shellPid);^
%=========% if (shellTid == 0) { return IntPtr.Zero; }^
%=========% uint openConPid = GetPidOfNamedProcWithOpenProcHandle(\"OpenConsole\", shellPid);^
%=========% if (openConPid == 0) { return IntPtr.Zero; }^
%=========% IntPtr openConWnd = GetOpenConWnd(openConPid);^
%=========% if (openConWnd == IntPtr.Zero) { return IntPtr.Zero; }^
%=========% return NativeMethods.GetAncestor(openConWnd, GA_ROOTOWNER);^
%=======% }^
%=======% static WinTerm() {^
%=========% const int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;^
%=========% bool terminalExpected = false;^
%=========% hWnd = GetTermWnd(ref terminalExpected);^
%=========% if (hWnd == IntPtr.Zero)^
%===========% throw new InvalidOperationException();^
%=========% tid = NativeMethods.GetWindowThreadProcessId(hWnd, out pid);^
%=========% if (tid == 0) { throw new InvalidOperationException(); }^
%=========% using (SafeRes sHProc = new SafeRes(NativeMethods.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid), SafeRes.ResType.Handle)) {^
%===========% if (sHProc.IsInvalid) { throw new InvalidOperationException(); }^
%===========% baseName = GetProcBaseName(sHProc);^
%=========% }^
%=========% if (string.IsNullOrEmpty(baseName) ^^^|^^^| (terminalExpected ^^^&^^^& (baseName == \"WindowsTerminal\") == false))^
%===========% throw new InvalidOperationException();^
%=======% }^
%=====% }^
%===% ' } catch {};^
%===% $hWnd = if ('WinTerm' -as [type]) { [WinTerm]::hWnd } else { [IntPtr]::Zero };^
%===% exit [Int32]$hWnd;^
%=% ^"

endlocal &set "TermWnd=%TermWnd%"
exit /b
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:init_FadeWnd
setlocal DisableDelayedExpansion
:: prefer PowerShell Core if installed
for %%i in ("pwsh.exe") do if "%%~$PATH:i"=="" (set "ps=powershell") else set "ps=pwsh"

:: - BRIEF -
::  Use alpha blending to fade the window in or out.
:: - SYNTAX -
::  %FadeWnd% start step end delay [hwnd]
::    start  percentage of transparency to begin with where 0 is for opaque,
::            and 100 is for limpid
::    step   number of percents the current value is advanced in each iteration
::    end    percentage of transparency to end with
::    delay  milliseconds to wait in each iteration to control the speed
::    hwnd   (optional) handle of a main window to be faded
::   To immediately set the window to a certain transparency, specify the same
::    value for both the start and end arguments.
:: - EXAMPLES -
::  Fade out the window to full transparency:
::    %FadeWnd% 0 1 100 1
::  Fade in the window to full opacity:
::    %FadeWnd% 100 -1 0 1
::  Instantly set window transprency to 30%:
::    %FadeWnd% 30 0 30 0
set FadeWnd=for %%# in (1 2) do if %%#==2 (for /f "tokens=1-5" %%- in ("^^!args^^! x x x x x") do^
%=% %ps%.exe -nop -ep Bypass -c ^"^
%===% $w=Add-Type -Name WAPI -PassThru -MemberDefinition '^
%=====% [DllImport(\"kernel32.dll\")]^
%=======% public static extern IntPtr GetConsoleWindow();^
%=====% [DllImport(\"user32.dll\")]^
%=======% public static extern int GetWindowLongW(IntPtr wnd, int idx);^
%=====% [DllImport(\"user32.dll\")]^
%=======% public static extern void SetWindowLongW(IntPtr wnd, int idx, int newLong);^
%=====% [DllImport(\"user32.dll\")]^
%=======% public static extern int SetLayeredWindowAttributes(IntPtr wnd, int color, int alpha, int flags);^
%===% ';^
%===% $start=0; $step=0; $end=0; $delay=0; $twnd=0;^
%===% if (-not [Int32]::TryParse('%%~-', [ref]$start) -or^
%=====% -not [Int32]::TryParse('%%~.', [ref]$step) -or^
%=====% -not [Int32]::TryParse('%%~/', [ref]$end) -or^
%=====% -not [Int32]::TryParse('%%~0', [ref]$delay) -or^
%=====% $start -lt 0 -or $start -gt 100 -or^
%=====% $end -lt 0 -or $end -gt 100 -or^
%=====% $delay -lt 0^
%===% ) {exit 1}^
%===% $GWL_EXSTYLE=-20;^
%===% $WS_EX_LAYERED=0x80000;^
%===% if ([Int32]::TryParse('%%~1', [ref]$twnd)) {^
%=====% $wnd=[IntPtr]$twnd;^
%===% } else {^
%=====% $wnd=$w::GetConsoleWindow();^
%===% }^
%===   legacy console and Windows Terminal need to be turned into a layered window   =% ^
%===% $w::SetWindowLongW($wnd, $GWL_EXSTYLE, $w::GetWindowLongW($wnd, $GWL_EXSTYLE) -bOr $WS_EX_LAYERED);^
%===% $LWA_ALPHA=2;^
%===% if (($start -lt $end) -and ($step -gt 0)) { %= fade out =%^
%=====% for ($i=$start; $i -lt $end; $i+=$step) {^
%=======% $null=$w::SetLayeredWindowAttributes($wnd, 0, [math]::Round(255 - 2.55 * $i), $LWA_ALPHA);^
%=======% [Threading.Thread]::Sleep($delay);^
%=====% }^
%===% } elseif (($start -gt $end) -and ($step -lt 0)) { %= fade in =%^
%=====% for ($i=$start; $i -gt $end; $i+=$step) {^
%=======% $null=$w::SetLayeredWindowAttributes($wnd, 0, [math]::Round(255 - 2.55 * $i), $LWA_ALPHA);^
%=======% [Threading.Thread]::Sleep($delay);^
%=====% }^
%===% } elseif ($start -ne $end) {exit 1} %= reject remaining inconclusive values =%^
%===   always use the 'end' value even if the distance between 'start' and 'end' is not a multiple of 'step'   =% ^
%===% exit [int]($w::SetLayeredWindowAttributes($wnd, 0, [math]::Round(255 - 2.55 * $end), $LWA_ALPHA) -eq 0);^
%=% ^" ^&endlocal) else setlocal EnableDelayedExpansion ^&set args=

endlocal &set "FadeWnd=%FadeWnd%"
if !!# neq # set "FadeWnd=%FadeWnd:^^=%"
exit /b
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
