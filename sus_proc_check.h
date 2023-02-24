#ifndef SUSPICIOUS_PROCESS_CHECKER_H
#define SUSPICIOUS_PROCESS_CHECKER_H

#include <windows.h>

#include <tlhelp32.h>

bool checkForSuspiciousIndicators(DWORD processId) {
    bool isSuspicious = false;
  
    // Get a handle to the process
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
  
    // Check if the process is suspended
    if (hProcess != NULL) {
      DWORD processStatus;
      if (GetExitCodeProcess(hProcess, & processStatus) && processStatus == STILL_ACTIVE) {
        DWORD suspendCount = SuspendThread(hProcess);
        ResumeThread(hProcess);
        if (suspendCount > 0) {
          isSuspicious = true;
        }
      }
      CloseHandle(hProcess);
    }
  
    // Check for API calls to hide from debugger
    HMODULE kernel32 = GetModuleHandle("kernel32.dll");
    FARPROC pIsDebuggerPresent = GetProcAddress(kernel32, "IsDebuggerPresent");
    FARPROC pCheckRemoteDebuggerPresent = GetProcAddress(kernel32, "CheckRemoteDebuggerPresent");
    FARPROC pOutputDebugStringA = GetProcAddress(kernel32, "OutputDebugStringA");
    FARPROC pOutputDebugStringW = GetProcAddress(kernel32, "OutputDebugStringW");
    FARPROC pOutputDebugString = GetProcAddress(kernel32, "OutputDebugString");
    FARPROC pDebugActiveProcess = GetProcAddress(kernel32, "DebugActiveProcess");
    FARPROC pDebugActiveProcessStop = GetProcAddress(kernel32, "DebugActiveProcessStop");
    FARPROC pDebugBreak = GetProcAddress(kernel32, "DebugBreak");
    FARPROC pDebugBreakProcess = GetProcAddress(kernel32, "DebugBreakProcess");
    FARPROC pDebugPrint = GetProcAddress(kernel32, "DebugPrint");
    FARPROC pDbgBreakPoint = GetProcAddress(kernel32, "DbgBreakPoint");
    FARPROC pDbgUserBreakPoint = GetProcAddress(kernel32, "DbgUserBreakPoint");
    FARPROC pRtlSetProcessIsCritical = GetProcAddress(kernel32, "RtlSetProcessIsCritical");
    FARPROC pIsProcessCritical = GetProcAddress(kernel32, "IsProcessCritical");
    FARPROC pCheckElevation = GetProcAddress(kernel32, "CheckElevation");
  
    if (pIsDebuggerPresent || pCheckRemoteDebuggerPresent || pOutputDebugStringA || pOutputDebugStringW || pOutputDebugString || pDebugActiveProcess || pDebugActiveProcessStop || pDebugBreak || pDebugBreakProcess || pDebugPrint || pDbgBreakPoint || pDbgUserBreakPoint || pRtlSetProcessIsCritical || pIsProcessCritical || pCheckElevation) {
      isSuspicious = true;
    }
  
    // Check for API calls to DllRegisterServer
    HMODULE ole32 = GetModuleHandle("ole32.dll");
    FARPROC pDllRegisterServer = GetProcAddress(ole32, "DllRegisterServer");
    FARPROC pDllRegisterServerEx = GetProcAddress(ole32, "DllRegisterServerEx");
  
    if (pDllRegisterServer || pDllRegisterServerEx) {
      isSuspicious = true;
    }
  
    // Check for API calls to SuspendThread
    HMODULE kernelbase = GetModuleHandle("kernelbase.dll");
    FARPROC pSuspendThread = GetProcAddress(kernelbase, "SuspendThread");
  
    if (pSuspendThread) {
      isSuspicious = true;
    }
  
    // Check for API calls to ShellExecute and related functions
    HMODULE shell32 = GetModuleHandle("shell32.dll");
    FARPROC pShellExecute = GetProcAddress(shell32, "ShellExecuteA");
    FARPROC pShellExecuteW = GetProcAddress(shell32, "ShellExecuteW");
    FARPROC pShellExecuteEx = GetProcAddress(shell32, "ShellExecuteExA");
  
    if (pShellExecute || pShellExecuteW || pShellExecuteEx) {
      isSuspicious = true;
    }
  
    // Check for API calls to ZwLoadDriver
    HMODULE ntdll = GetModuleHandle("ntdll.dll");
    FARPROC pZwLoadDriver = GetProcAddress(ntdll, "ZwLoadDriver");
  
    if (pZwLoadDriver) {
      isSuspicious = true;
    }
  
    // Check for API calls to MapViewOfFile
    HMODULE kernelbase2 = GetModuleHandle("kernelbase.dll");
    FARPROC pMapViewOfFile = GetProcAddress(kernelbase2, "MapViewOfFile");
  
    if (pMapViewOfFile) {
      isSuspicious = true;
    }
  
    // Check for API calls to GetAsyncKeyState
    HMODULE user32 = GetModuleHandle("user32.dll");
    FARPROC pGetAsyncKeyState = GetProcAddress(user32, "GetAsyncKeyState");
  
    if (pGetAsyncKeyState) {
      isSuspicious = true;
    }
  
    // Check for API calls to SetWindowsHookEx
    FARPROC pSetWindowsHookEx = GetProcAddress(user32, "SetWindowsHookExA");
  
    if (pSetWindowsHookEx) {
      isSuspicious = true;
    }
  
    // Check for API calls to GetForegroundWindow
    FARPROC pGetForegroundWindow = GetProcAddress(user32, "GetForegroundWindow");
  
    if (pGetForegroundWindow) {
      isSuspicious = true;
    }
  
    // Check for API calls to WSASocket and related functions
    HMODULE ws2_32 = GetModuleHandle("ws2_32.dll");
    FARPROC pWSASocket = GetProcAddress(ws2_32, "WSASocketA");
    FARPROC pWSAStartup = GetProcAddress(ws2_32, "WSAStartup");
    FARPROC pbind = GetProcAddress(ws2_32, "bind");
    FARPROC pconnect = GetProcAddress(ws2_32, "connect");
    FARPROC pInternetOpenUrl = GetProcAddress(ws2_32, "InternetOpenUrlA");
  
    if (pWSASocket || pWSAStartup || pbind || pconnect || pInternetOpenUrl) {
      isSuspicious = true;
    }
  
    // Check for API calls to URLDownloadToFileA
    HMODULE urlmon = GetModuleHandle("urlmon.dll");
    FARPROC pURLDownloadToFileA = GetProcAddress(urlmon, "URLDownloadToFileA");
  
    if (pURLDownloadToFileA) {
      isSuspicious = true;
    }
  
    // Check for API calls to InternetOpen and InternetConnect
    FARPROC pInternetOpen = GetProcAddress(urlmon, "InternetOpenA");
    FARPROC pInternetConnect = GetProcAddress(urlmon, "InternetConnectA");
  
    if (pInternetOpen || pInternetConnect) {
      isSuspicious = true;
    }
  
    // Check for API calls to WriteProcessMemory
    FARPROC pWriteProcessMemory = GetProcAddress(kernel32, "WriteProcessMemory");
  
    if (pWriteProcessMemory) {
      isSuspicious = true;
    }
  
    // Check for API calls to GetTickCount and GetEIP
    FARPROC pGetTickCount = GetProcAddress(kernel32, "GetTickCount");
    FARPROC pGetEIP = GetProcAddress(kernel32, "GetEIP");
  
    if (pGetTickCount || pGetEIP) {
      isSuspicious = true;
    }
  
    // Check for API calls to free
    FARPROC pFree = GetProcAddress(kernel32, "free");
  
    if (pFree) {
      isSuspicious = true;
    }
  
    // Check for API calls to WinExec
    FARPROC pWinExec = GetProcAddress(kernel32, "WinExec");
  
    if (pWinExec) {
      isSuspicious = true;
    }
  
    // Check for API calls to UnhookWindowsHookEx
    FARPROC pUnhookWindowsHookEx = GetProcAddress(user32, "UnhookWindowsHookEx");
  
    if (pUnhookWindowsHookEx) {
      isSuspicious = true;
    }
  
    // Check for API calls to WinHttpOpen
    HMODULE winhttp = GetModuleHandle("winhttp.dll");
    FARPROC pWinHttpOpen = GetProcAddress(winhttp, "WinHttpOpen");
  
    if (pWinHttpOpen) {
      isSuspicious = true;
    }
  
    // Check for memory regions with RWX or RX protections that do not map to a file on disk
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
  
    if (hSnapshot != INVALID_HANDLE_VALUE) {
      MODULEENTRY32 moduleEntry;
      moduleEntry.dwSize = sizeof(moduleEntry);
      if (Module32First(hSnapshot, & moduleEntry)) {
        do {
          MEMORY_BASIC_INFORMATION memInfo;
          SIZE_T numBytes = VirtualQueryEx(hProcess, moduleEntry.modBaseAddr, & memInfo, sizeof(memInfo));
  
          if (numBytes == sizeof(memInfo)) {
            DWORD pageProtect = memInfo.Protect;
            DWORD pageState = memInfo.State;
            bool isMappedToFile = ((memInfo.Type & MEM_MAPPED) == MEM_MAPPED) || ((memInfo.Type & MEM_IMAGE) == MEM_IMAGE);
  
            if (!isMappedToFile && (pageProtect == PAGE_EXECUTE_READ || pageProtect == PAGE_EXECUTE_READWRITE || pageProtect == PAGE_EXECUTE_WRITECOPY || pageProtect == PAGE_READWRITE)) {
              isSuspicious = true;
              break;
            }
          }
        } while (Module32Next(hSnapshot, & moduleEntry));
      }
  
      CloseHandle(hSnapshot);
    }
  
    return isSuspicious;
  }
  
  #endif // SUSPICIOUS_PROCESS_CHECKER_H