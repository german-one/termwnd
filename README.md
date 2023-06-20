## **TermWnd**  

The purpose of the code in this repository is both to distinguish between Conhost and Windows Terminal processes and to determine which terminal window hosts the current console process. Third-party terminal apps are not supported.  
The source files are transcriptions of pretty much the same core code in different programming languages.  
<br>
### **Minimum requirements to compile/run the code:**  

Source files in `Windows Batch`, `C`, `C++`, `C#.Net`, `PowerShell`, and `VB.Net` are published in the [src](./src) folder. They all depend on Windows being the target operating system. Also, this code relies on the hidden ConPTY window being owned by the Terminal window. Presumably this has been first implemented in Windows Terminal v1.14. Other specific dependencies are listed below.  

| **File** | **Requirement** |
| :--- | :--- |
| `*.bat` | *Windows PowerShell 5.1* |
| `*.c` | *C99* |
| `*.cpp` | *C++20* |
| `*.cs` | *.NET Framework 4.5* |
| `*.ps1` | *Windows PowerShell 2* |
| `*.vb` | *.NET Framework 4.5* |

<br>

### **Relevant code:**  

The source files in this repository contain fully functional code that demonstrates how to use the search procedure. However, if you intend to use it in your own code, it might be useful to know which essential pieces of code you need to include.  

| **File** | **Code of interest** | **Value of interest** |
| :--- | :--- | :--- |
| `*.bat` | *`TermWnd`* macro defined in the `:init_TermWnd` routine | the errorlevel returned by the *`TermWnd`* macro is the handle of the hosting terminal window (`0` if an error occurred) |
| `*.c` | *`GetWinterm`* function, along with structure type `winterm_t` and related code | if the *`GetWinterm`* function returns `true`, the referenced object of type `winterm_t` is filled with properties of the hosting terminal window (`false` is returned if an error occurred) |
| `*.cpp` | everything in namespace *`termproc`*, along with namespace `saferes` | the values returned by the class methods *`winterm::hwnd()`*, *`winterm::pid()`*, *`winterm::tid()`*, and *`winterm::basename()`* (exception if an error occurred) <br>use the *`winterm::refresh()`* method to update the values after the tab has been moved to another window |
| `*.cs` | class *`WinTerm`* | the values of properties *`WinTerm.HWnd`*, *`WinTerm.Pid`*, *`WinTerm.Tid`*, and *`WinTerm.BaseName`*  (exception if an error occurred) <br>use the *`WinTerm.Refresh()`* method to update the values after the tab has been moved to another window |
| `*.ps1` | Type referencing class *`WinTerm`* | the values of properties *`[WinTerm]::HWnd`* *`[WinTerm]::Pid`* *`[WinTerm]::Tid`* *`[WinTerm]::BaseName`* (type `WinTerm` not defined if an error occurred) <br>use the *`[WinTerm]::Refresh()`* method to update the values after the tab has been moved to another window |
| `*.vb` | Module *`WinTerm`* | the values of properties *`WinTerm.HWnd`*, *`WinTerm.Pid`*, *`WinTerm.Tid`*, and *`WinTerm.BaseName`*  (exception if an error occurred) <br>use the *`WinTerm.Refresh()`* method to update the values after the tab has been moved to another window |

<br>

### **Background:**  
A few years ago Microsoft began to develop a new terminal application - [Windows Terminal](https://github.com/microsoft/terminal). The installation is available for Windows 10, and Windows 11 already ships with it. By an update in October '22 Microsoft turned it into the default terminal app on Windows 11.  
As of now, Windows Terminal coexists with the good old Conhost. Users are able to choose which is taken as their default terminal app.  

In the past, it has been easy to figure out which terminal window hosts the shell/console application. Behind the scenes it was always the Conhost window. The `GetConsoleWindow()` function returned its window handle.  
However, if the Windows Terminal hosts our app, `GetConsoleWindow()` returns the handle to the hidden ConPTY window.  
Beginning with Windows Terminal version 1.18, all terminal windows run in only one process and tabs can be moved from one window to another. This makes it even more complicated to find the right window.

I tried to write a piece of code to find the window even if the tab has been moved out or attached to another window. This requires to involve some undocumented API. I left a couple of comments in the code that roughly explain how this all works.  

In each file is also a piece of unrelated code that fades the window out and in again. I found it an impressive way of proving that the right window had been found.  

### **Example output:**  
Note the updated thread id (TID) and window handle (HWND) in the newly written lines after moving the tab to another window.  
![example output](./termwnd.gif)  

<br>
