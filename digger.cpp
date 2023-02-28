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

#include "injected_code_check.h"

#include "process_enumerator.h"

#include <wchar.h>

#include "dumpmemory.h"

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "Wininet.lib")
#pragma comment(lib, "psapi.lib")

std::vector < DWORD > findProcessesWithSuspiciousIndicators() {
  // Enumerate all processes
  std::vector<DWORD> processIdsVector = ProcessEnumerator::getProcessIds();
    std::set<DWORD> processIds(processIdsVector.begin(), processIdsVector.end());

  std::vector < std::string > apiFunctions = {
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
  std::vector < DWORD > suspiciousProcesses;
  std::unordered_set < DWORD > dumpedPids;
  for (const auto & processId: processIds) {
    try {
      if (processId == GetCurrentProcessId() || dumpedPids.count(processId) > 0) {
        continue; // ignore self and already dumped processes
      }

      // Check for suspicious indicators
      if (checkForSuspiciousIndicators({
          processId
        })) {
        std::cout << "Suspicious indicators found in process " << processId << std::endl;
        SymbolDownloader::download_symbols(apiFunctions, processId);
        suspiciousProcesses.push_back(processId);
      }

      // Check for injection
      if (isInjectedProcess({
          processId
        })) {
        std::cout << "Injection found in process " << processId << std::endl;
        SymbolDownloader::download_symbols(apiFunctions, processId);
        suspiciousProcesses.push_back(processId);
      }

      // Walk the stack for suspicious processes
      ProcessStackwalkChecker stackwalkChecker({
        processId
      });
      if (stackwalkChecker.checkStackForSuspiciousCalls()) {
        std::cout << "Suspicious calls found in process " << processId << std::endl;
        SymbolDownloader::download_symbols(apiFunctions, processId);
        suspiciousProcesses.push_back(processId);
      }
    } catch (const std::runtime_error & e) {
      std::cerr << "Error processing process " << processId << ": " <<
        e.what() << std::endl;
    }
    // Dump the process memory if it hasn't been dumped yet
    if (dumpedPids.count(processId) == 0) {
      std::wstring dumpFilePath = L"process_" + std::to_wstring(processId) + L"_dump.bin";
       dumpMemoryOfProcesses({ processId });
    std::cout << "Process memory dumped for process " << processId << std::endl;
    dumpedPids.insert(processId);

      }
    }
  
  return suspiciousProcesses;
}

int main() {
  std::vector < DWORD > suspiciousProcesses = findProcessesWithSuspiciousIndicators();
  if (suspiciousProcesses.empty()) {
    std::cout << "No suspicious processes found." << std::endl;
  } else {
    std::cout << "The following processes have been identified as suspicious:" << std::endl;
    for (const auto & processId: suspiciousProcesses) {
      std::cout << processId << std::endl;
    }
  }
  return 0;
}
