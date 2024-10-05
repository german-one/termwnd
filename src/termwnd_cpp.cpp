// Copyright (c) Steffen Illhardt
// Licensed under the MIT license.

// Min. req.: C++20

#if defined(NDEBUG) && defined(__clang__)
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Wreserved-macro-identifier"
#endif
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
#include <array>
#include <filesystem>
#include <format>
#include <iostream>
#include <memory>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#ifdef NDEBUG
#  if defined(__GNUC__) || defined(__clang__)
#    pragma GCC diagnostic push
#    pragma GCC diagnostic ignored "-Wcast-function-type"
#    pragma GCC diagnostic ignored "-Weffc++"
#    if defined(__clang__)
#      pragma GCC diagnostic ignored "-Wc++98-compat"
#    endif
#  elif defined(_MSC_VER)
#    pragma warning(push)
#    pragma warning(disable : 4191 4623 4626 4706 4710 4711 4820 5027 26472 26481 26490 26821)
#  endif
#endif

namespace saferes
{
  namespace detail
  {
    // having these in a "detail" namespace may protect you from using the ctors directly because there's a high risk for omitting the deleter as second argument
    // use the Make... lambdas (along with the auto keyword for variable declarations)
    constexpr inline auto HandleDeleter{ [](const HANDLE hndl) noexcept { if (hndl && hndl != INVALID_HANDLE_VALUE) ::CloseHandle(hndl); } };
    using _handle_t = std::unique_ptr<void, decltype(HandleDeleter)>;

    constexpr inline auto GlobMemDeleter{ [](BYTE *const ptr) noexcept { if (ptr) ::GlobalFree(ptr); } };
    using _loclmem_t = std::unique_ptr<BYTE, decltype(GlobMemDeleter)>;
  }

  // only use for HANDLE values that need to be released using CloseHandle()
  // don't rely on operator bool(), use the IsInvalidHandle lambda instead
  constexpr inline auto MakeHandle{ [](const HANDLE hndl = nullptr) noexcept { return detail::_handle_t{ hndl, detail::HandleDeleter }; } };
  constexpr inline auto IsInvalidHandle{ [](const detail::_handle_t &safeHndl) noexcept { return !safeHndl || safeHndl.get() == INVALID_HANDLE_VALUE; } };

  // only use for pointers that GlobalAlloc() returned
  constexpr inline auto MakeGlobMem{ [](BYTE *const ptr = nullptr) noexcept { return detail::_loclmem_t{ ptr, detail::GlobMemDeleter }; } };
}

namespace termproc
{
  namespace detail
  {
    // undocumented SYSTEM_HANDLE structure, SYSTEM_HANDLE_TABLE_ENTRY_INFO might be the actual name
    struct SYSTEM_HANDLE
    {
      const DWORD ProcId; // PID of the process the SYSTEM_HANDLE belongs to
      const BYTE ObjTypeId; // identifier of the object
      const BYTE Flgs;
      const WORD Handle; // value representing an opened handle in the process
      const PVOID pObj;
      const DWORD Acc;
    };
  }

  // provides properties identifying the terminal window the current console application is running in
  class winterm
  {
  private:
    HWND m_conWnd{ ::GetConsoleWindow() };
    HWND m_hWnd{};
    DWORD m_pid{};
    DWORD m_tid{};
    std::wstring m_baseName{};

    std::wstring GetProcBaseName(const HANDLE hProc, std::span<wchar_t> nameBuf)
    {
      auto size{ static_cast<DWORD>(nameBuf.size()) };
      return ::QueryFullProcessImageNameW(hProc, 0, nameBuf.data(), &size) ? std::filesystem::path{ { nameBuf.data(), size } }.stem().wstring() : std::wstring{};
    }

    DWORD GetPidOfNamedProcWithOpenProcHandle(std::wstring_view searchProcName, const DWORD findOpenProcId)
    {
      using NtQuerySystemInformation_t = NTSTATUS(__stdcall *)(int SysInfClass, PVOID SysInf, DWORD SysInfLen, PDWORD RetLen);
      using CompareObjectHandles_t = BOOL(__stdcall *)(HANDLE hFirst, HANDLE hSecond);

      static constexpr auto STATUS_INFO_LENGTH_MISMATCH{ static_cast<NTSTATUS>(0xc0000004) }; // NTSTATUS returned if we still didn't allocate enough memory
      static constexpr auto SystemHandleInformation{ 16 }; // one of the SYSTEM_INFORMATION_CLASS values
      static constexpr BYTE OB_TYPE_INDEX_JOB{ 7 }; // one of the SYSTEM_HANDLE.ObjTypeId values

      NtQuerySystemInformation_t NtQuerySystemInformation{};
      CompareObjectHandles_t CompareObjectHandles{};

      HMODULE hModule{ ::GetModuleHandleA("ntdll.dll") };
      if (!hModule || !(NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformation_t>(::GetProcAddress(hModule, "NtQuerySystemInformation"))))
        return {};

      hModule = ::GetModuleHandleA("kernelbase.dll");
      if (!hModule || !(CompareObjectHandles = reinterpret_cast<CompareObjectHandles_t>(::GetProcAddress(hModule, "CompareObjectHandles"))))
        return {};

      // allocate some memory representing an undocumented SYSTEM_HANDLE_INFORMATION object, which can't be meaningfully declared in C# code
      DWORD infSize{ 0x200000 };
      auto sPSysHandlInf{ saferes::MakeGlobMem(static_cast<BYTE *>(::GlobalAlloc(GMEM_FIXED, infSize))) };
      if (!sPSysHandlInf)
        return {};

      DWORD len;
      NTSTATUS status;
      // try to get an array of all available SYSTEM_HANDLE objects, allocate more memory if necessary
      while ((status = NtQuerySystemInformation(SystemHandleInformation, sPSysHandlInf.get(), infSize, &len)) == STATUS_INFO_LENGTH_MISMATCH)
      {
        infSize = len + 0x1000;
        sPSysHandlInf.reset(static_cast<BYTE *>(::GlobalAlloc(GMEM_FIXED, infSize)));
        if (!sPSysHandlInf)
          return {};
      }

      if (!NT_SUCCESS(status))
        return {};

      const auto sHFindOpenProc{ saferes::MakeHandle(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, findOpenProcId)) }; // intentionally after NtQuerySystemInformation() was called to exclude it from the found open handles
      if (saferes::IsInvalidHandle(sHFindOpenProc))
        return {};

      const HANDLE hThis{ GetCurrentProcess() };
      DWORD curPid{};
      auto sHCur{ saferes::MakeHandle() };
      std::array<wchar_t, 1024> nameBuf{};
      // iterate over the array of SYSTEM_HANDLE objects, which begins at an offset of pointer size in the SYSTEM_HANDLE_INFORMATION object
      // the number of SYSTEM_HANDLE objects is specified in the first 32 bits of the SYSTEM_HANDLE_INFORMATION object
      for (const auto &sysHandle :
           std::span{ reinterpret_cast<detail::SYSTEM_HANDLE *>(sPSysHandlInf.get() + sizeof(intptr_t)), *reinterpret_cast<DWORD *>(sPSysHandlInf.get()) })
      {
        // shortcut; OB_TYPE_INDEX_JOB is the identifier we are looking for, any other SYSTEM_HANDLE object is immediately ignored at this point
        if (sysHandle.ObjTypeId != OB_TYPE_INDEX_JOB)
          continue;

        // every time the process changes, the previous handle needs to be closed and we open a new handle to the current process
        if (curPid != sysHandle.ProcId)
        {
          curPid = sysHandle.ProcId;
          sHCur.reset(::OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, curPid));
        }

        HANDLE hCurOpenDup{};
        // if the process has not been opened, or
        // if duplicating the current one of its open handles fails, continue with the next SYSTEM_HANDLE object
        // the duplicated handle is necessary to get information about the object (e.g. the process) it points to
        if (saferes::IsInvalidHandle(sHCur) ||
            !::DuplicateHandle(sHCur.get(), reinterpret_cast<HANDLE>(sysHandle.Handle), hThis, &hCurOpenDup, PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0))
          continue;

        const auto sHCurOpenDup{ saferes::MakeHandle(hCurOpenDup) };
        if (CompareObjectHandles(sHCurOpenDup.get(), sHFindOpenProc.get()) && // both the handle of the open process and the currently duplicated handle must refer to the same kernel object
            searchProcName == GetProcBaseName(sHCur.get(), nameBuf)) // the process name of the currently found process must meet the process name we are looking for
          return curPid;
      }

      return {};
    }

    using wnd_callback_dat_t = std::pair<const DWORD, HWND>;
    static BOOL __stdcall GetTermWndCallback(HWND hWnd, LPARAM lParam) noexcept
    {
      const auto pSearchDat{ reinterpret_cast<wnd_callback_dat_t *>(lParam) };
      DWORD pid{};
      ::GetWindowThreadProcessId(hWnd, &pid);
      if (pid != pSearchDat->first || !::IsWindowVisible(hWnd) || ::GetWindow(hWnd, GW_OWNER))
        return TRUE;

      pSearchDat->second = hWnd;
      return FALSE;
    }

    HWND GetTermWnd(bool &terminalExpected)
    {
      const auto conWnd{ ::GetConsoleWindow() };
      // We don't have a proper way to figure out to what terminal app the Shell process
      // is connected on the local machine:
      // https://github.com/microsoft/terminal/issues/7434
      // We're getting around this assuming we don't get an icon handle from the
      // invisible Conhost window when the Shell is connected to Windows Terminal.
      terminalExpected = ::SendMessageW(conWnd, WM_GETICON, 0, 0) == 0;
      if (!terminalExpected)
        return conWnd;

      // Polling because it may take some milliseconds for Terminal to create its window and take ownership of the hidden ConPTY window.
      HWND conOwner = nullptr;
      for (int i = 0; i < 100 && conOwner == nullptr; ++i)
      {
        ::Sleep(5);
        conOwner = ::GetWindow(conWnd, GW_OWNER);
      }

      if (conOwner != nullptr)
        return conOwner; // This is the terminal window hosting our process if it has been an existing window.

      // In case the terminal process has been newly created for us ...
      // Get the ID of the Shell process that spawned the Conhost process.
      DWORD shellPid = 0;
      if (::GetWindowThreadProcessId(conWnd, &shellPid) == 0)
        return nullptr;

      // Try to figure out which of WindowsTerminal processes has a handle to the Shell process open.
      const auto termPid = GetPidOfNamedProcWithOpenProcHandle(L"WindowsTerminal", shellPid);
      if (termPid == 0)
        return nullptr;

      wnd_callback_dat_t searchDat{ termPid, nullptr };
      ::EnumWindows(GetTermWndCallback, reinterpret_cast<LPARAM>(&searchDat));
      return searchDat.second;
    }

  public:
    winterm() noexcept
    {
      refresh();
    }

    // used to initially get or to update the properties if a terminal tab is moved to another window
    void refresh() noexcept
    {
      try
      {
        bool terminalExpected = false;
        m_hWnd = GetTermWnd(terminalExpected);
        if (m_hWnd == nullptr)
          throw std::exception{};

        m_tid = ::GetWindowThreadProcessId(m_hWnd, &(m_pid));
        if (m_tid == 0)
          throw std::exception{};

        const auto sHProc{ saferes::MakeHandle(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, m_pid)) };
        if (saferes::IsInvalidHandle(sHProc))
          throw std::exception{};

        std::array<wchar_t, 1024> nameBuf{};
        m_baseName = GetProcBaseName(sHProc.get(), nameBuf);
        if (m_baseName.empty() || (terminalExpected && m_baseName != L"WindowsTerminal"))
          throw std::exception{};
      }
      catch (...)
      {
      }
    }

    constexpr HWND hwnd() const noexcept // window handle
    {
      return m_hWnd;
    }

    constexpr DWORD pid() const noexcept // process id
    {
      return m_pid;
    }

    constexpr DWORD tid() const noexcept // thread id
    {
      return m_tid;
    }

    constexpr std::wstring_view basename() const noexcept // process name without .exe extension
    {
      return m_baseName;
    }
  };
}

namespace test
{
  enum class FadeMode
  {
    Out,
    In
  };

  // for fading out or fading in a window, used to prove that we found the right terminal process
  void Fade(const HWND hWnd, const FadeMode mode) noexcept;
}

int main()
{
  try
  {
    auto winterm{ termproc::winterm{} };
    while (true)
    {
      std::wcout << L"Term proc: " << winterm.basename()
                 << L"\nTerm PID:  " << winterm.pid()
                 << L"\nTerm TID:  " << winterm.tid()
                 << L"\nTerm HWND: " << std::format(L"{:#010X}\n", reinterpret_cast<intptr_t>(winterm.hwnd())) << std::endl;

      test::Fade(winterm.hwnd(), test::FadeMode::Out);
      test::Fade(winterm.hwnd(), test::FadeMode::In);

      ::Sleep(5000); // [Terminal version >= 1.18] Gives you some time to move the tab out or attach it to another window.
      winterm.refresh();
    }
  }
  catch (...)
  {
    return 1;
  }
}

void test::Fade(const HWND hWnd, const FadeMode mode) noexcept
{
  ::SetWindowLongW(hWnd, GWL_EXSTYLE, ::GetWindowLongW(hWnd, GWL_EXSTYLE) | WS_EX_LAYERED);

  constexpr std::ranges::iota_view rng{ 0, 86 };
  if (mode == FadeMode::Out)
  {
    for (const auto alpha : std::ranges::reverse_view{ rng })
    {
      ::SetLayeredWindowAttributes(hWnd, 0, static_cast<BYTE>(alpha * 3), LWA_ALPHA);
      ::Sleep(1);
    }

    return;
  }

  for (const auto alpha : rng)
  {
    ::SetLayeredWindowAttributes(hWnd, 0, static_cast<BYTE>(alpha * 3), LWA_ALPHA);
    ::Sleep(1);
  }
}

#ifdef NDEBUG
#  if defined(__GNUC__) || defined(__clang__)
#    pragma GCC diagnostic pop
#  elif defined(_MSC_VER)
#    pragma warning(pop)
#  endif
#endif
