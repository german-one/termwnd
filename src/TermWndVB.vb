' Copyright (c) Steffen Illhardt
' Licensed under the MIT license.

' Min. req.: .NET Framework 4.5

Option Explicit On
Option Infer On
Option Strict On

Imports System.Diagnostics.CodeAnalysis
Imports System.Globalization
Imports System.IO
Imports System.Runtime.ConstrainedExecution
Imports System.Runtime.InteropServices
Imports System.Text
Imports System.Threading

Namespace TerminalProcess
  ' provides properties identifying the terminal window the current console application is running in
  Public Module WinTerm
    ' imports the used Windows API functions
    Private NotInheritable Class NativeMethods
      Private Sub New() : End Sub
      <DllImport("kernel32.dll")>
      Friend Shared Function CloseHandle(ByVal Hndl As IntPtr) As Integer : End Function
      <DllImport("kernelbase.dll")>
      Friend Shared Function CompareObjectHandles(ByVal hFirst As IntPtr, ByVal hSecond As IntPtr) As Integer : End Function
      <DllImport("kernel32.dll")>
      Friend Shared Function DuplicateHandle(ByVal SrcProcHndl As IntPtr, ByVal SrcHndl As IntPtr, ByVal TrgtProcHndl As IntPtr, <Out> ByRef TrgtHndl As IntPtr, ByVal Acc As Integer, ByVal Inherit As Integer, ByVal Opts As Integer) As Integer : End Function
      <DllImport("user32.dll")>
      Friend Shared Function EnumWindows(ByVal enumFunc As EnumWindowsProc, ByVal lparam As IntPtr) As <MarshalAs(UnmanagedType.Bool)> Boolean : End Function
      <DllImport("user32.dll")>
      Friend Shared Function GetAncestor(ByVal hWnd As IntPtr, ByVal flgs As Integer) As IntPtr : End Function
      <DllImport("kernel32.dll")>
      Friend Shared Function GetConsoleWindow() As IntPtr : End Function
      <DllImport("kernel32.dll")>
      Friend Shared Function GetCurrentProcess() As IntPtr : End Function
      <DllImport("user32.dll")>
      Friend Shared Function GetWindow(ByVal hWnd As IntPtr, ByVal cmd As Integer) As IntPtr : End Function
      <DllImport("user32.dll")>
      Friend Shared Function GetWindowThreadProcessId(ByVal hWnd As IntPtr, <Out> ByRef procId As UInteger) As UInteger : End Function
      <DllImport("ntdll.dll")>
      Friend Shared Function NtQuerySystemInformation(ByVal SysInfClass As Integer, ByVal SysInf As IntPtr, ByVal SysInfLen As Integer, <Out> ByRef RetLen As Integer) As Integer : End Function
      <DllImport("kernel32.dll")>
      Friend Shared Function OpenProcess(ByVal Acc As Integer, ByVal Inherit As Integer, ByVal ProcId As UInteger) As IntPtr : End Function
      <DllImport("kernel32.dll", CharSet:=CharSet.Unicode)>
      Friend Shared Function QueryFullProcessImageNameW(ByVal Proc As IntPtr, ByVal Flgs As Integer, ByVal Name As StringBuilder, ByRef Size As Integer) As Integer : End Function
      <DllImport("user32.dll")>
      Friend Shared Function SendMessageW(ByVal hWnd As IntPtr, ByVal Msg As Integer, ByVal wParam As IntPtr, ByVal lParam As IntPtr) As IntPtr : End Function
    End Class

    Private ReadOnly Property ConWnd As IntPtr = NativeMethods.GetConsoleWindow()

    Friend ReadOnly Property HWnd As IntPtr ' window handle
      Get
        Return _hWnd : End Get
    End Property

    Friend ReadOnly Property Pid As UInteger ' process id
      Get
        Return _pid : End Get
    End Property

    Friend ReadOnly Property Tid As UInteger ' thread id
      Get
        Return _tid : End Get
    End Property

    Friend ReadOnly Property BaseName As String ' process name without .exe extension
      Get
        Return _baseName : End Get
    End Property

#If Not DEBUG AndAlso CODE_ANALYSIS Then
#Disable Warning IDE0079
    <SuppressMessage("Microsoft.Reliability", "CA2006:UseSafeHandleToEncapsulateNativeResources")>
    Private _hWnd As IntPtr = IntPtr.Zero ' even though this is a "Native Resource" we never want to dispose it 
#Enable Warning IDE0079
#Else
    Private _hWnd As IntPtr = IntPtr.Zero
#End If
    Private _pid As UInteger = 0
    Private _tid As UInteger = 0
    Private _baseName As String = String.Empty

    ' owns an unmanaged resource
    ' the ctor qualifies a SafeRes object to manage either a pointer received from Marshal.AllocHGlobal(), or a handle
    Private Class SafeRes
      Inherits CriticalFinalizerObject
      Implements IDisposable

      ' resource type of a SafeRes object
      Friend Enum ResType
        MemoryPointer
        Handle
      End Enum

      Private _raw As System.IntPtr = IntPtr.Zero
      Private ReadOnly _resourceType As ResType = ResType.MemoryPointer

      Friend ReadOnly Property Raw As IntPtr
        Get
          Return _raw
        End Get
      End Property

      Friend ReadOnly Property IsInvalid As Boolean
        Get
          Return _raw = IntPtr.Zero OrElse _raw = New IntPtr(-1)
        End Get
      End Property

      ' constructs a SafeRes object from an unmanaged resource specified by parameter raw
      ' the resource must be either a pointer received from Marshal.AllocHGlobal() (specify resourceType ResType.MemoryPointer),
      ' or a handle (specify resourceType ResType.Handle)
      Friend Sub New(ByVal raw As IntPtr, ByVal resourceType As ResType)
        _raw = raw
        _resourceType = resourceType
      End Sub

      Protected Overrides Sub Finalize()
        Dispose(False)
      End Sub

      Public Sub Dispose() Implements IDisposable.Dispose
        Dispose(True)
        GC.SuppressFinalize(Me)
      End Sub

      Protected Overridable Sub Dispose(ByVal disposing As Boolean)
        If IsInvalid Then Exit Sub

        If _resourceType = ResType.MemoryPointer Then
          Marshal.FreeHGlobal(_raw)
          _raw = IntPtr.Zero
          Exit Sub
        End If

        If NativeMethods.CloseHandle(_raw) <> 0 Then _raw = New IntPtr(-1)
      End Sub

      Friend Overridable Sub Reset(ByVal raw As IntPtr)
        Dispose()
        _raw = raw
      End Sub
    End Class

    ' undocumented SYSTEM_HANDLE structure, SYSTEM_HANDLE_TABLE_ENTRY_INFO might be the actual name
    <StructLayout(LayoutKind.Sequential)>
    Private Structure SystemHandle
      Friend ReadOnly ProcId As UInteger ' PID of the process the SYSTEM_HANDLE belongs to
      Friend ReadOnly ObjTypeId As Byte ' identifier of the object
      Friend ReadOnly Flgs As Byte
      Friend ReadOnly Handle As UShort ' value representing an opened handle in the process
      Friend ReadOnly pObj As IntPtr
      Friend ReadOnly Acc As UInteger
    End Structure

    Private Function GetProcBaseName(ByRef sHProc As SafeRes) As String
      Dim size = 1024, nameBuf = New StringBuilder(size)
      Return If(NativeMethods.QueryFullProcessImageNameW(sHProc.Raw, 0, nameBuf, size) = 0, "", Path.GetFileNameWithoutExtension(nameBuf.ToString(0, size)))
    End Function

    ' Enumerate the opened handles in each process, select those that refer to the same process as findOpenProcId.
    ' Return the ID of the process that opened the handle if its name is the same as searchProcName,
    ' Return 0 if no such process is found.
    Private Function GetPidOfNamedProcWithOpenProcHandle(ByVal searchProcName As String, ByVal findOpenProcId As UInteger) As UInteger
      Const PROCESS_DUP_HANDLE = &H40, ' access right to duplicate handles
            PROCESS_QUERY_LIMITED_INFORMATION = &H1000, ' access right to retrieve certain process information
            STATUS_INFO_LENGTH_MISMATCH = &HC0000004%, ' NTSTATUS returned if we still didn't allocate enough memory
            SystemHandleInformation = 16, ' one of the SYSTEM_INFORMATION_CLASS values
            OB_TYPE_INDEX_JOB As Byte = 7 ' one of the SYSTEM_HANDLE.ObjTypeId values
      Dim status As Integer, ' retrieves the NTSTATUS return value
          infSize = &H200000, ' initially allocated memory size for the SYSTEM_HANDLE_INFORMATION object
          len = 0
      ' allocate some memory representing an undocumented SYSTEM_HANDLE_INFORMATION object, which can't be meaningfully declared in C# code
      Using sPSysHndlInf As New SafeRes(Marshal.AllocHGlobal(infSize), SafeRes.ResType.MemoryPointer)
        Do ' try to get an array of all available SYSTEM_HANDLE objects, allocate more memory if necessary
          status = NativeMethods.NtQuerySystemInformation(SystemHandleInformation, sPSysHndlInf.Raw, infSize, len)
          If status <> STATUS_INFO_LENGTH_MISMATCH Then Exit Do
          infSize = len + &H1000
          sPSysHndlInf.Reset(Marshal.AllocHGlobal(infSize))
        Loop

        If status < 0 Then Return 0

        Using sHFindOpenProc As New SafeRes(NativeMethods.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, findOpenProcId), SafeRes.ResType.Handle) ' intentionally after NtQuerySystemInformation() was called to exclude it from the found open handles
          If sHFindOpenProc.IsInvalid Then Return 0
          Dim foundPid As UInteger = 0, curPid As UInteger = 0
          Dim hThis = NativeMethods.GetCurrentProcess()
          Dim sysHndlSize = Marshal.SizeOf(GetType(SystemHandle))
          Using sHCur As New SafeRes(IntPtr.Zero, SafeRes.ResType.Handle)
            ' iterate over the array of SYSTEM_HANDLE objects, which begins at an offset of pointer size in the SYSTEM_HANDLE_INFORMATION object
            ' the number of SYSTEM_HANDLE objects is specified in the first 32 bits of the SYSTEM_HANDLE_INFORMATION object
            Dim pSysHndl = sPSysHndlInf.Raw + IntPtr.Size, pEnd = pSysHndl + (Marshal.ReadInt32(sPSysHndlInf.Raw) * sysHndlSize)
            While pSysHndl <> pEnd
              ' get one SYSTEM_HANDLE at a time
              Dim sysHndl = DirectCast(Marshal.PtrToStructure(pSysHndl, GetType(SystemHandle)), SystemHandle)
              ' shortcut; OB_TYPE_INDEX_JOB is the identifier we are looking for, any other SYSTEM_HANDLE object is immediately ignored at this point
              If sysHndl.ObjTypeId <> OB_TYPE_INDEX_JOB Then
                pSysHndl += sysHndlSize
                Continue While
              End If

              ' every time the process changes, the previous handle needs to be closed and we open a new handle to the current process
              If curPid <> sysHndl.ProcId Then
                curPid = sysHndl.ProcId
                sHCur.Reset(NativeMethods.OpenProcess(PROCESS_DUP_HANDLE Or PROCESS_QUERY_LIMITED_INFORMATION, 0, curPid))
              End If

              ' if the process has not been opened, or
              ' if duplicating the current one of its open handles fails, continue with the next SYSTEM_HANDLE object
              ' the duplicated handle is necessary to get information about the object (e.g. the process) it points to
              Dim hCurOpenDup = IntPtr.Zero
              If sHCur.IsInvalid OrElse NativeMethods.DuplicateHandle(sHCur.Raw, CType(sysHndl.Handle, IntPtr), hThis, hCurOpenDup, PROCESS_QUERY_LIMITED_INFORMATION, 0, 0) = 0 Then
                pSysHndl += sysHndlSize
                Continue While
              End If

              Using sHCurOpenDup As New SafeRes(hCurOpenDup, SafeRes.ResType.Handle)
                If NativeMethods.CompareObjectHandles(sHCurOpenDup.Raw, sHFindOpenProc.Raw) <> 0 AndAlso _ ' both the handle of the open process and the currently duplicated handle must refer to the same kernel object
                    searchProcName = GetProcBaseName(sHCur) Then ' the process name of the currently found process must meet the process name we are looking for
                  foundPid = curPid
                  Exit While
                End If
              End Using

              pSysHndl += sysHndlSize
            End While
          End Using

          Return foundPid
        End Using
      End Using
    End Function

    Private _findPid As UInteger
    Private _foundHWnd As IntPtr

    Private Delegate Function EnumWindowsProc(ByVal hWnd As IntPtr, ByVal lParam As IntPtr) As Boolean

    Private Function GetOpenConWndCallback(ByVal hWnd As IntPtr, ByVal lParam As IntPtr) As Boolean
      Dim thisPid As UInteger = 0
      Dim thisTid = NativeMethods.GetWindowThreadProcessId(hWnd, thisPid)
      If thisTid = 0 OrElse thisPid <> _findPid Then Return True

      _foundHWnd = hWnd
      Return False
    End Function

    Private Function GetOpenConWnd(ByVal termPid As UInteger) As IntPtr
      If termPid = 0 Then Return IntPtr.Zero

      _findPid = termPid
      _foundHWnd = IntPtr.Zero
      NativeMethods.EnumWindows(New EnumWindowsProc(AddressOf GetOpenConWndCallback), IntPtr.Zero)
      Return _foundHWnd
    End Function

    Private Function GetTermWnd(ByRef terminalExpected As Boolean) As IntPtr
      Const WM_GETICON = &H7F,
            GW_OWNER = 4,
            GA_ROOTOWNER = 3

      ' We don't have a proper way to figure out to what terminal app the Shell process
      ' Is connected on the local machine:
      ' https//github.com/microsoft/terminal/issues/7434
      ' We're getting around this assuming we don't get an icon handle from the
      ' invisible Conhost window when the Shell Is connected to Windows Terminal.
      terminalExpected = NativeMethods.SendMessageW(ConWnd, WM_GETICON, IntPtr.Zero, IntPtr.Zero) = IntPtr.Zero
      If Not terminalExpected Then Return ConWnd

      ' Polling because it may take some milliseconds for Terminal to create its window And take ownership of the hidden ConPTY window.
      Dim i = 0
      Dim conOwner = IntPtr.Zero ' FWIW this receives the terminal window our tab is created in, but it gets never updated if the tab is moved to another window.
      While (i < 200 AndAlso conOwner = IntPtr.Zero)
        Thread.Sleep(5)
        conOwner = NativeMethods.GetWindow(ConWnd, GW_OWNER)
        i += 1
      End While

      ' Something went wrong if polling did Not succeed within 1 second (e.g. it's not Windows Terminal).
      If conOwner = IntPtr.Zero Then Return IntPtr.Zero

      ' Get the ID of the Shell process that spawned the Conhost process.
      Dim shellPid As UInteger = 0
      Dim shellTid = NativeMethods.GetWindowThreadProcessId(ConWnd, shellPid)
      If shellTid = 0 Then Return IntPtr.Zero

      ' Get the ID of the OpenConsole process spawned for the Shell process.
      Dim openConPid = GetPidOfNamedProcWithOpenProcHandle("OpenConsole", shellPid)
      If openConPid = 0 Then Return IntPtr.Zero

      ' Get the hidden window of the OpenConsole process
      Dim openConWnd = GetOpenConWnd(openConPid)
      If openConWnd = IntPtr.Zero Then Return IntPtr.Zero

      ' The root owner window Is the Terminal window.
      Return NativeMethods.GetAncestor(openConWnd, GA_ROOTOWNER)
    End Function

#If Not DEBUG AndAlso CODE_ANALYSIS Then
#Disable Warning IDE0079
    <SuppressMessage("Microsoft.Performance", "CA1810:InitializeReferenceTypeStaticFieldsInline")>
    Sub New()
#Enable Warning IDE0079
#Else
    Sub New()
#End If
      Refresh()
    End Sub

    ' used to initially get or to update the properties if a terminal tab is moved to another window
    Sub Refresh()
      Const PROCESS_QUERY_LIMITED_INFORMATION = &H1000
      Dim terminalExpected = False
      _hWnd = GetTermWnd(terminalExpected)
      If _hWnd = IntPtr.Zero Then Throw New InvalidOperationException()

      _tid = NativeMethods.GetWindowThreadProcessId(_hWnd, _pid)
      If _tid = 0 Then Throw New InvalidOperationException()

      Using sHProc = New SafeRes(NativeMethods.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, _pid), SafeRes.ResType.Handle)
        If sHProc.IsInvalid Then Throw New InvalidOperationException()
        _baseName = GetProcBaseName(sHProc)
      End Using

      If String.IsNullOrEmpty(_baseName) OrElse (terminalExpected AndAlso _baseName <> "WindowsTerminal") Then _
          Throw New InvalidOperationException()
    End Sub
  End Module

  Friend Class Program
#If Not DEBUG AndAlso CODE_ANALYSIS Then
#Disable Warning IDE0079
    <SuppressMessage("Microsoft.Globalization", "CA1303:DoNotPassLiteralsAsLocalizedParameters")> ' WriteLine()
    Public Shared Function Main() As Integer
#Enable Warning IDE0079
#Else
    Public Shared Function Main() As Integer
#End If
      Try
        While True
          Console.WriteLine("Term proc: {0}" & vbLf & "Term PID:  {1}" & vbLf & "Term TID:  {2}" & vbLf & "Term HWND: 0X{3}" & vbLf,
                          WinTerm.BaseName,
                          WinTerm.Pid.ToString(CultureInfo.CurrentCulture),
                          WinTerm.Tid.ToString(CultureInfo.CurrentCulture),
                          WinTerm.HWnd.ToString("X8"))

          Test.Fade(WinTerm.HWnd, Test.FadeMode.Out)
          Test.Fade(WinTerm.HWnd, Test.FadeMode.In)

          Thread.Sleep(5000) ' [Terminal version >= 1.18] Gives you some time to move the tab out or attach it to another window.
          WinTerm.Refresh()
        End While
        Return 0
      Catch
        Return 1
      End Try
    End Function
  End Class
End Namespace

Namespace Test
  ' for the second parameter of the Fader.Fade() method
  Public Enum FadeMode
    Out
    [In]
  End Enum

  ' provides the .Fade() method for fading out or fading in a window, used to prove that we found the right terminal process
  Public Module Fader
    Private NotInheritable Class NativeMethods
      Private Sub New() : End Sub
      <DllImport("user32.dll")>
      Friend Shared Function GetWindowLongW(ByVal wnd As IntPtr, ByVal idx As Integer) As Integer : End Function
      <DllImport("user32.dll")>
      Friend Shared Function SetLayeredWindowAttributes(ByVal wnd As IntPtr, ByVal color As Integer, ByVal alpha As Integer, ByVal flags As Integer) As Integer : End Function
      <DllImport("user32.dll")>
      Friend Shared Function SetWindowLongW(ByVal wnd As IntPtr, ByVal idx As Integer, ByVal newLong As Integer) As Integer : End Function
    End Class

    ' use alpha blending to fade the window
    Public Sub Fade(ByVal hWnd As IntPtr, ByVal mode As FadeMode)
      If hWnd = IntPtr.Zero Then Exit Sub

      Const GWL_EXSTYLE = -20, WS_EX_LAYERED = &H80000, LWA_ALPHA = 2

      If NativeMethods.SetWindowLongW(hWnd, GWL_EXSTYLE, NativeMethods.GetWindowLongW(hWnd, GWL_EXSTYLE) Or WS_EX_LAYERED) = 0 Then Exit Sub

      If mode = FadeMode.Out Then
        For alpha = 255 To 0 Step -3
          If NativeMethods.SetLayeredWindowAttributes(hWnd, 0, alpha, LWA_ALPHA) = 0 Then Exit Sub
          Thread.Sleep(1)
        Next
        Exit Sub
      End If

      For alpha = 0 To 255 Step 3
        If NativeMethods.SetLayeredWindowAttributes(hWnd, 0, alpha, LWA_ALPHA) = 0 Then Exit Sub
        Thread.Sleep(1)
      Next
    End Sub
  End Module
End Namespace
