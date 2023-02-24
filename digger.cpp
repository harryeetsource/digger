#include <iostream>

#include <vector>

#include <string>

#include <unordered_set>

#include <algorithm>

#include <urlmon.h>

#include <dbghelp.h>

#include "sus_proc_check.h"

#include "stackwalker.h"

#include "Symbol_Downloader.h"

#include "memdump.h"

#include "injected_code_check.h"

#include "process_enumerator.h"

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "dbghelp.lib")

bool isProcessSelf(const DWORD processId) {
  HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
  if (hProcess == NULL) {
    return false;
  }

  WCHAR path[MAX_PATH];
  DWORD length = MAX_PATH;
  if (QueryFullProcessImageNameW(hProcess, 0, path, & length) == FALSE) {
    CloseHandle(hProcess);
    return false;
  }

  CloseHandle(hProcess);
  return (wcscmp(path, L "") == 0 || wcsicmp(path, L "Unknown") == 0);
}

void download_symbols(DWORD processId) {
  std::vector < std::string > moduleNames = ProcessEnumerator::EnumerateProcessModules(processId);
  std::vector < std::string > apiFunctions = ProcessEnumerator::GetProcessApiFunctions(processId);

  // Check for PDB files in the same directory as the module
  for (const auto & moduleName: moduleNames) {
    std::wstring moduleNameW(moduleName.begin(), moduleName.end());
    std::wstring pdbNameW = SymbolDownloader::get_file_version(moduleNameW) + L ".pdb";
    std::wstring pdbUrl = L "http://msdl.microsoft.com/download/symbols/" + moduleNameW + L "/" + pdbNameW;
    std::wstring pdbPath = moduleNameW + L "\\" + pdbNameW;

    if (URLDownloadToFile(NULL, std::string(pdbUrl.begin(), pdbUrl.end()).c_str(), std::string(pdbPath.begin(), pdbPath.end()).c_str(), 0, NULL) == S_OK) {
      std::wcout << L "PDB file for " << moduleNameW << L " downloaded successfully" << std::endl;
    }
  }

  // Download symbols for all API functions
  SymbolDownloader::download_symbols(apiFunctions);
}

int main() {
  // Enumerate all processes
  std::vector < DWORD > processIds = ProcessEnumerator::getProcessIds();
  std::unordered_set < DWORD > dumpedPids;

  for (const auto & processId: processIds) {
    if (isProcessSelf(processId)) {
      continue;
    }

    bool suspiciousProcess = false;

    // Check for suspicious indicators
    if (checkForSuspiciousIndicators(processId)) {
      std::cout << "Suspicious indicators found in process " << processId << std::endl;
      suspiciousProcess = true;
    }

    // Check for injection
    if (isInjectedProcess(processId)) {
      std::cout << "Injection found in process " << processId << std::endl;
      suspiciousProcess = true;
    }

    // Download symbols for suspicious processes
    if (suspiciousProcess) {
      download_symbols(processId);
    }

    // Walk the stack for suspicious processes
    ProcessStackwalkChecker stackwalkChecker(processId);
    if (stackwalkChecker.checkStackForSuspiciousCalls()) {
      std::cout << "Suspicious calls found in process " << processId << std::endl;
      suspiciousProcess = true;
    }

    // Dump memory for suspicious processes
    if (suspiciousProcess && dumpedPids.count(processId) == 0) {
      HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
      if (processHandle != NULL) {
        dump_memory(processHandle); {
          std::cout << "Memory dumped for process " << processId << std::endl;
          dumpedPids.insert(processId);
        }
        CloseHandle(processHandle);
      }
    }
  }
  return 0;
}
