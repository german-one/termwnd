// Copyright (c) Steffen Illhardt
// Licensed under the MIT license.

// Min. req.: C99

#if defined(NDEBUG) && defined(__clang__)
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wreserved-macro-identifier"
#endif
#ifdef _CRTBLD
#  undef _CRTBLD
#endif
#define _CRTBLD 1
#ifdef _WIN32_WINNT
#  undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0A00
#if defined(NDEBUG) && defined(__clang__)
#  pragma GCC diagnostic pop
#endif
#ifdef WIN32_LEAN_AND_MEAN
#  undef WIN32_LEAN_AND_MEAN
#endif
#define WIN32_LEAN_AND_MEAN 1
#include <Windows.h>
#include <SubAuth.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <wchar.h>

typedef struct
{
  HWND hwnd;
  DWORD pid;
  DWORD tid;
  wchar_t basename[MAX_PATH];
} winterm_t;

bool GetWinterm(winterm_t *pWinterm);

typedef enum
{
  FadeOut,
  FadeIn
} FadeMode;

// for fading out or fading in a window, used to prove that we found the right terminal process
void Fade(const HWND hWnd, const FadeMode mode);

#ifdef NDEBUG
#  if defined(__GNUC__) || defined(__clang__)
#    pragma GCC diagnostic push
#    pragma GCC diagnostic ignored "-Wcast-align"
#    pragma GCC diagnostic ignored "-Wcast-function-type"
#    pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
#  elif defined(_MSC_VER)
#    pragma warning(push)
#    pragma warning(                                                                                   \
      disable : 4191 /* unsafe conversion (function types) */                                          \
      4706 /* assignment within conditional expression */                                              \
      4710 /* function not inline */                                                                   \
      4711 /* function selected for inline expansion */                                                \
      4820 /* padding added */                                                                         \
      5045 /* compiler will insert Spectre mitigation for memory load if /Qspectre switch specified */ \
    )
#  endif
#endif

int main(void)
{
  for (winterm_t winterm;;)
  {
    if (!GetWinterm(&winterm))
      return 1;

    wprintf_s(L"Term proc: %s\nTerm PID:  %lu\nTerm TID:  %lu\nTerm HWND: 0X%08IX\n\n", winterm.basename, winterm.pid, winterm.tid, (intptr_t)(void *)winterm.hwnd);

    Fade(winterm.hwnd, FadeOut);
    Fade(winterm.hwnd, FadeIn);

    Sleep(5000); // [Terminal version >= 1.18] Gives you some time to move the tab out or attach it to another window.
  }
}

// Get the name of the process from the process handle.
// Returns a pointer to the buffer containing the name of the process.
// If the function fails, a zero-length string will be returned.
static wchar_t *GetProcBaseName(const HANDLE hProc, wchar_t *const baseBuf, const size_t bufSiz)
{
  *baseBuf = L'\0';
  if (!hProc)
    return baseBuf;

  wchar_t nameBuf[1024] = { 0 };
  DWORD size = ARRAYSIZE(nameBuf);
  if (QueryFullProcessImageNameW(hProc, 0, nameBuf, &size))
    _wsplitpath_s(nameBuf, NULL, 0, NULL, 0, baseBuf, bufSiz, NULL, 0);

  return baseBuf;
}

// undocumented SYSTEM_HANDLE structure, SYSTEM_HANDLE_TABLE_ENTRY_INFO might be the actual name
typedef struct
{
  const DWORD ProcId; // PID of the process the SYSTEM_HANDLE belongs to
  const BYTE ObjTypeId; // identifier of the object
  const BYTE Flgs;
  const WORD Handle; // value representing an opened handle in the process
  const PVOID pObj;
  const DWORD Acc;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

// Enumerate the opened handles in each process, select those that refer to the same process as findOpenProcId.
// Return the ID of the process that opened the handle if its name is the same as searchProcName,
// Return 0 if no such process is found.
static DWORD GetPidOfNamedProcWithOpenProcHandle(const wchar_t *const searchProcName, const DWORD findOpenProcId)
{
  typedef NTSTATUS(__stdcall * NtQuerySystemInformation_t)(int SysInfClass, PVOID SysInf, DWORD SysInfLen, PDWORD RetLen);
  typedef BOOL(__stdcall * CompareObjectHandles_t)(HANDLE hFirst, HANDLE hSecond);

  static const NTSTATUS STATUS_INFO_LENGTH_MISMATCH = (NTSTATUS)0xc0000004; // NTSTATUS returned if we still didn't allocate enough memory
  static const int SystemHandleInformation = 16; // one of the SYSTEM_INFORMATION_CLASS values
  static const BYTE OB_TYPE_INDEX_JOB = 7; // one of the SYSTEM_HANDLE.ObjTypeId values

  NtQuerySystemInformation_t NtQuerySystemInformation;
  CompareObjectHandles_t CompareObjectHandles;

  HMODULE hModule = GetModuleHandleA("ntdll.dll");
  if (!hModule || !(NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(hModule, "NtQuerySystemInformation")))
    return 0;

  hModule = GetModuleHandleA("kernelbase.dll");
  if (!hModule || !(CompareObjectHandles = (CompareObjectHandles_t)GetProcAddress(hModule, "CompareObjectHandles")))
    return 0;

  // allocate some memory representing an undocumented SYSTEM_HANDLE_INFORMATION object, which can't be meaningfully declared in C# code
  DWORD infSize = 0x200000;
  PBYTE pSysHndlInf = GlobalAlloc(GMEM_FIXED, infSize);
  if (!pSysHndlInf)
    return 0;

  DWORD len;
  NTSTATUS status;
  // try to get an array of all available SYSTEM_HANDLE objects, allocate more memory if necessary
  while ((status = NtQuerySystemInformation(SystemHandleInformation, (PVOID)pSysHndlInf, infSize, &len)) == STATUS_INFO_LENGTH_MISMATCH)
  {
    GlobalFree(pSysHndlInf);
    infSize = len + 0x1000;
    pSysHndlInf = GlobalAlloc(GMEM_FIXED, infSize);
    if (!pSysHndlInf)
      return 0;
  }

  HANDLE hFindOpenProc;
  if (!NT_SUCCESS(status) ||
      !(hFindOpenProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, findOpenProcId))) // intentionally after NtQuerySystemInformation() was called to exclude it from the found open handles
  {
    GlobalFree(pSysHndlInf);
    return 0;
  }

  const HANDLE hThis = GetCurrentProcess();
  DWORD curPid = 0, foundPid = 0;
  HANDLE hCur = NULL;
  wchar_t baseBuf[MAX_PATH] = { 0 };
  // iterate over the array of SYSTEM_HANDLE objects, which begins at an offset of pointer size in the SYSTEM_HANDLE_INFORMATION object
  // the number of SYSTEM_HANDLE objects is specified in the first 32 bits of the SYSTEM_HANDLE_INFORMATION object
  for (const SYSTEM_HANDLE *pSysHndl = (PSYSTEM_HANDLE)(pSysHndlInf + sizeof(intptr_t)),
                           *const pEnd = pSysHndl + *(DWORD *)pSysHndlInf;
       !foundPid && pSysHndl < pEnd;
       ++pSysHndl)
  {
    // shortcut; OB_TYPE_INDEX_JOB is the identifier we are looking for, any other SYSTEM_HANDLE object is immediately ignored at this point
    if (pSysHndl->ObjTypeId != OB_TYPE_INDEX_JOB)
      continue;

    // every time the process changes, the previous handle needs to be closed and we open a new handle to the current process
    if (curPid != pSysHndl->ProcId)
    {
      curPid = pSysHndl->ProcId;
      if (hCur)
        CloseHandle(hCur);

      hCur = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, curPid);
    }

    HANDLE hCurOpenDup;
    // if the process has not been opened, or
    // if duplicating the current one of its open handles fails, continue with the next SYSTEM_HANDLE object
    // the duplicated handle is necessary to get information about the object (e.g. the process) it points to
    if (!hCur ||
        !DuplicateHandle(hCur, (HANDLE)(intptr_t)pSysHndl->Handle, hThis, &hCurOpenDup, PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0))
      continue;

    if (CompareObjectHandles(hCurOpenDup, hFindOpenProc) && // both the handle of the open process and the currently duplicated handle must refer to the same kernel object
        0 == lstrcmpW(GetProcBaseName(hCur, baseBuf, ARRAYSIZE(baseBuf)), searchProcName)) // the process name of the currently found process must meet the process name we are looking for
      foundPid = curPid;

    CloseHandle(hCurOpenDup);
  }

  if (hCur)
    CloseHandle(hCur);

  GlobalFree(pSysHndlInf);
  CloseHandle(hFindOpenProc);
  return foundPid;
}

typedef struct
{
  const DWORD pid;
  HWND hWnd;
} WND_CALLBACK_DAT, *PWND_CALLBACK_DAT;

static BOOL __stdcall GetOpenConWndCallback(HWND hWnd, LPARAM lParam)
{
  const PWND_CALLBACK_DAT pSearchDat = (PWND_CALLBACK_DAT)lParam;
  DWORD pid = 0;
  GetWindowThreadProcessId(hWnd, &pid);
  if (pid != pSearchDat->pid)
    return TRUE;

  pSearchDat->hWnd = hWnd;
  return FALSE;
}

static HWND GetOpenConWnd(const DWORD termPid)
{
  if (!termPid)
    return NULL;

  WND_CALLBACK_DAT searchDat = { termPid, NULL };
  EnumWindows(GetOpenConWndCallback, (LPARAM)&searchDat);
  return searchDat.hWnd;
}

static HWND GetTermWnd(bool *const pTerminalExpected)
{
  const HWND conWnd = GetConsoleWindow();
  // We don't have a proper way to figure out to what terminal app the Shell process
  // is connected on the local machine:
  // https://github.com/microsoft/terminal/issues/7434
  // We're getting around this assuming we don't get an icon handle from the
  // invisible Conhost window when the Shell is connected to Windows Terminal.
  *pTerminalExpected = SendMessageW(conWnd, WM_GETICON, 0, 0) == 0;
  if (!*pTerminalExpected)
    return conWnd;

  // Polling because it may take some milliseconds for Terminal to create its window and take ownership of the hidden ConPTY window.
  HWND conOwner = NULL; // FWIW this receives the terminal window our tab is created in, but it gets never updated if the tab is moved to another window.
  for (int i = 0; i < 200 && conOwner == NULL; ++i)
  {
    Sleep(5);
    conOwner = GetWindow(conWnd, GW_OWNER);
  }

  // Something went wrong if polling did not succeed within 1 second (e.g. it's not Windows Terminal).
  if (conOwner == NULL)
    return NULL;

  // Get the ID of the Shell process that spawned the Conhost process.
  DWORD shellPid = 0;
  const DWORD shellTid = GetWindowThreadProcessId(conWnd, &shellPid);
  if (shellTid == 0)
    return NULL;

  // Get the ID of the OpenConsole process spawned for the Shell process.
  const DWORD openConPid = GetPidOfNamedProcWithOpenProcHandle(L"OpenConsole", shellPid);
  if (openConPid == 0)
    return NULL;

  // Get the hidden window of the OpenConsole process
  const HWND openConWnd = GetOpenConWnd(openConPid);
  if (openConWnd == NULL)
    return NULL;

  // The root owner window is the Terminal window.
  return GetAncestor(openConWnd, GA_ROOTOWNER);
}

bool GetWinterm(winterm_t *pWinterm)
{
  bool terminalExpected = false;
  pWinterm->hwnd = GetTermWnd(&terminalExpected);
  if (pWinterm->hwnd == NULL)
    return false;

  pWinterm->tid = GetWindowThreadProcessId(pWinterm->hwnd, &(pWinterm->pid));
  if (pWinterm->tid == 0)
    return false;

  const HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pWinterm->pid);
  if (hProc == NULL)
    return false;

  GetProcBaseName(hProc, pWinterm->basename, ARRAYSIZE(pWinterm->basename));
  CloseHandle(hProc);

  return *(pWinterm->basename) != L'\0' && (!terminalExpected || wcscmp(pWinterm->basename, L"WindowsTerminal") == 0);
}

void Fade(const HWND hWnd, const FadeMode mode)
{
  SetWindowLongW(hWnd, GWL_EXSTYLE, GetWindowLongW(hWnd, GWL_EXSTYLE) | WS_EX_LAYERED);

  if (mode == FadeOut)
  {
    for (int alpha = 255; alpha >= 0; alpha -= 3)
    {
      SetLayeredWindowAttributes(hWnd, 0, (BYTE)alpha, LWA_ALPHA);
      Sleep(1);
    }

    return;
  }

  for (int alpha = 0; alpha <= 255; alpha += 3)
  {
    SetLayeredWindowAttributes(hWnd, 0, (BYTE)alpha, LWA_ALPHA);
    Sleep(1);
  }
}

#ifdef NDEBUG
#  if defined(__GNUC__) || defined(__clang__)
#    pragma GCC diagnostic pop
#  elif defined(_MSC_VER)
#    pragma warning(pop)
#  endif
#endif
