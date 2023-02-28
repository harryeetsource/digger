#include <Windows.h>
#include <tchar.h>
#include <iostream>
#include <vector>
#include <string>
#include <unordered_set>
#include <algorithm>
#include <urlmon.h>
#include <dbghelp.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include "sus_proc_check.h"
#include "stackwalker.h"
#include "Symbol_Downloader.h"
#include "memdump.h"
#include "injected_code_check.h"
#include "process_enumerator.h"
#include <wchar.h>
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "Wininet.lib")
#pragma comment(lib, "psapi.lib")

int main() {
    // Enumerate all processes
    std::vector<DWORD> processIds = ProcessEnumerator::getProcessIds();
    std::vector<std::string> apiFunctions = {
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
    std::unordered_set<DWORD> dumpedPids;
    for (const auto& processId : processIds) {
        try {
            if (processId == GetCurrentProcessId() || dumpedPids.count(processId) > 0) {
                continue; // ignore self and already dumped processes
            }

            // Check for suspicious indicators
            if (checkForSuspiciousIndicators({ processId })) {
                std::cout << "Suspicious indicators found in process " << processId << std::endl;
                SymbolDownloader::download_symbols(apiFunctions, processId);
                MemDumper::dump_process_memory(processId);
                dumpedPids.insert(processId);
            }

            // Check for injection
            if (isInjectedProcess({ processId })) {
                std::cout << "Injection found in process " << processId << std::endl;
                SymbolDownloader::download_symbols(apiFunctions, processId);
                MemDumper::dump_process_memory(processId);
                dumpedPids.insert(processId);
            }

            // Walk the stack for suspicious processes
            ProcessStackwalkChecker stackwalkChecker({ processId });
            if (stackwalkChecker.checkStackForSuspiciousCalls()) {
                std::cout << "Suspicious calls found in process " << processId << std::endl;
                SymbolDownloader::download_symbols(apiFunctions, processId);
                MemDumper::dump_process_memory(processId);
                dumpedPids.insert(processId);
            }
        }
                catch (const std::runtime_error& e) {
            std::cerr << "Error processing process " << processId << ": " << e.what() << std::endl;
        }
    }

    return 0;
}
