#ifndef SUSPICIOUS_PROCESS_CHECKER_H
#define SUSPICIOUS_PROCESS_CHECKER_H

#include <windows.h>
#include <tlhelp32.h>
#include <vector>

bool checkForSuspiciousIndicators(DWORD processId) {
    bool isSuspicious = false;
  
    // Get a handle to the process
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
  
    // Check if the process is suspended
    if (hProcess != NULL) {
        DWORD processStatus;
        if (GetExitCodeProcess(hProcess, &processStatus) && processStatus == STILL_ACTIVE) {
            DWORD suspendCount = SuspendThread(hProcess);
            ResumeThread(hProcess);
            if (suspendCount > 0) {
                isSuspicious = true;
            }
        }
        CloseHandle(hProcess);
    }
  
    // List of API functions to check
    std::vector<const char*> apiFunctions = {
        "IsDebuggerPresent",
        "CheckRemoteDebuggerPresent",
        "OutputDebugStringA",
        "OutputDebugStringW",
        "OutputDebugString",
        "DebugActiveProcess",
        "DebugActiveProcessStop",
        "DebugBreak",
        "DebugBreakProcess",
        "DebugPrint",
        "DbgBreakPoint",
        "DbgUserBreakPoint",
        "RtlSetProcessIsCritical",
        "IsProcessCritical",
        "CheckElevation",
        "DllRegisterServer",
        "DllRegisterServerEx",
        "SuspendThread",
        "ShellExecuteA",
        "ShellExecuteW",
        "ShellExecuteExA",
        "ZwLoadDriver",
        "MapViewOfFile",
        "GetAsyncKeyState",
        "SetWindowsHookExA",
        "GetForegroundWindow",
        "WSASocketA",
        "WSAStartup",
        "bind",
        "connect",
        "InternetOpenUrlA",
        "URLDownloadToFileA",
        "InternetOpenA",
        "InternetConnectA",
        "WriteProcessMemory",
        "GetTickCount",
        "GetEIP",
        "free",
        "WinExec",
        "UnhookWindowsHookEx",
        "WinHttpOpen"
    };
  
    // Check for API calls in the list
    for (const char* functionName : apiFunctions) {
        HMODULE module = GetModuleHandle("kernel32.dll");
        FARPROC function = GetProcAddress(module, functionName);
        if (function != NULL) {
            isSuspicious = true;
            break;
        }
  
        module = GetModuleHandle("ole32.dll");
        function = GetProcAddress(module, functionName);
        if (function != NULL) {
            isSuspicious = true;
            break;
        }
  
        module = GetModuleHandle("kernelbase.dll");
        function = GetProcAddress(module, functionName);
        if (function != NULL) {
            isSuspicious = true;
            break;
        }
  
        module = GetModuleHandle("user32.dll");
        function = GetProcAddress(module, functionName);
        if (function != NULL) {
            isSuspicious = true;
            break;
        }
  
        module = GetModuleHandle("ws2_32.dll");
        function = GetProcAddress(module, functionName);
        if (function != NULL) {
            isSuspicious = true;
            break;
        }
  
        module = GetModuleHandle("urlmon.dll");
        function = GetProcAddress(module, functionName);
        if (function != NULL) {
            isSuspicious = true;
            break;
        }
  
        module = GetModuleHandle("winhttp.dll");
        function = GetProcAddress(module, functionName);
            if (function != NULL) {
            isSuspicious = true;
            break;
            }
            }
            // Check for memory regions with RWX or RX protections that do not map to a file on disk
                HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
                
                if (hSnapshot != INVALID_HANDLE_VALUE) {
                    MODULEENTRY32 moduleEntry;
                    moduleEntry.dwSize = sizeof(moduleEntry);
                    if (Module32First(hSnapshot, &moduleEntry)) {
                        do {
                            MEMORY_BASIC_INFORMATION memInfo;
                            SIZE_T numBytes = VirtualQueryEx(hProcess, moduleEntry.modBaseAddr, &memInfo, sizeof(memInfo));
                
                            if (numBytes == sizeof(memInfo)) {
                                DWORD pageProtect = memInfo.Protect;
                                DWORD pageState = memInfo.State;
                                bool isMappedToFile = ((memInfo.Type & MEM_MAPPED) == MEM_MAPPED) || ((memInfo.Type & MEM_IMAGE) == MEM_IMAGE);
                
                                if (!isMappedToFile && (pageProtect == PAGE_EXECUTE_READ || pageProtect == PAGE_EXECUTE_READWRITE || pageProtect == PAGE_EXECUTE_WRITECOPY || pageProtect == PAGE_READWRITE)) {
                                    isSuspicious = true;
                                    break;
                                }
                            }
                        } while (Module32Next(hSnapshot, &moduleEntry));
                    }
                
                    CloseHandle(hSnapshot);
                }
                
                return isSuspicious;
            }

            #endif // SUSPICIOUS_PROCESS_CHECKER_H
