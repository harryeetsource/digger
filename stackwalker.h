#ifndef PROCESS_STACKWALK_CHECKER_H
#define PROCESS_STACKWALK_CHECKER_H

#include <windows.h>

#include <memory>
#include <dbghelp.h>

#include <tlhelp32.h>

bool checkForSuspiciousIndicators(DWORD processId);

class ProcessStackwalkChecker {
  public: ProcessStackwalkChecker(DWORD processId): m_processId(processId) {
      // Initialize the symbol engine
      SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES | SYMOPT_UNDNAME | SYMOPT_INCLUDE_32BIT_MODULES);
      if (!SymInitialize(GetCurrentProcess(), NULL, TRUE))
        throw std::runtime_error("Failed to initialize symbol engine");

      // Initialize the stack walking context
      CONTEXT context;
      ZeroMemory( & context, sizeof(CONTEXT));
      context.ContextFlags = CONTEXT_FULL;
      HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, GetProcessMainThreadId(processId));
      if (!hThread)
        throw std::runtime_error("Failed to open thread handle for process main thread");
      if (!GetThreadContext(hThread, & context))
        throw std::runtime_error("Failed to get thread context for process main thread");
      m_stackwalkContext = std::make_unique < STACKFRAME64 > ();
      ZeroMemory(m_stackwalkContext.get(), sizeof(STACKFRAME64));
      m_stackwalkContext -> AddrPC.Offset = context.Rip;
      m_stackwalkContext -> AddrPC.Mode = AddrModeFlat;
      m_stackwalkContext -> AddrFrame.Offset = context.Rbp;
      m_stackwalkContext -> AddrFrame.Mode = AddrModeFlat;
      m_stackwalkContext -> AddrStack.Offset = context.Rsp;
      m_stackwalkContext -> AddrStack.Mode = AddrModeFlat;

      // Initialize the module list
      HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
      if (hSnapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 moduleEntry;
        moduleEntry.dwSize = sizeof(moduleEntry);
        if (Module32First(hSnapshot, & moduleEntry)) {
          do {
            IMAGEHLP_MODULE64 moduleInfo;
            ZeroMemory( & moduleInfo, sizeof(moduleInfo));
            moduleInfo.SizeOfStruct = sizeof(moduleInfo);
            if (SymGetModuleInfo64(GetCurrentProcess(), reinterpret_cast<DWORD64>(moduleEntry.modBaseAddr), & moduleInfo)) {

              m_modules.emplace_back(std::make_pair(moduleInfo.BaseOfImage, moduleInfo.ImageSize));
            }
          } while (Module32Next(hSnapshot, & moduleEntry));
        }
        CloseHandle(hSnapshot);
      }
    }

    ~ProcessStackwalkChecker() {
      SymCleanup(GetCurrentProcess());
    }

  bool checkStackForSuspiciousCalls() {
    while (StackWalk64(IMAGE_FILE_MACHINE_AMD64, GetCurrentProcess(), GetCurrentThread(), m_stackwalkContext.get(), & m_stackwalkFrame, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
      if (m_stackwalkContext -> AddrPC.Offset == 0) {
        // End of stack
        break;
      }

      for (const auto & module: m_modules) {
        if (m_stackwalkContext -> AddrPC.Offset >= module.first && m_stackwalkContext -> AddrPC.Offset < (module.first + module.second)) {
          // This instruction is in the module's memory range
          if (checkForSuspiciousIndicators(m_processId)) {
            return true;
          }
          break;
        }
      }
    }

    return false;
  }

  private: 
  DWORD m_processId;
  std::vector < std::pair < DWORD64,
  DWORD >> m_modules;
  std::unique_ptr < STACKFRAME64 > m_stackwalkContext;
  DWORD m_stackwalkFrame = 0;
  DWORD GetProcessMainThreadId(DWORD processId) {
    // Get a handle to the process
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess)
      throw std::runtime_error("Failed to open process handle");

    // Get a snapshot of the process's threads
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, processId);
    if (hSnapshot == INVALID_HANDLE_VALUE)
      throw std::runtime_error("Failed to create thread snapshot");

    // Find the thread with the earliest creation time (i.e. the main thread)
    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(threadEntry);
    DWORD earliestCreationTime = INFINITE;
    DWORD mainThreadId = 0;
    if (Thread32First(hSnapshot, & threadEntry)) {
      do {
        if (threadEntry.th32OwnerProcessID == processId) {
          HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadEntry.th32ThreadID);
          if (hThread) {
            FILETIME creationTime, exitTime, kernelTime, userTime;
            if (GetThreadTimes(hThread, & creationTime, & exitTime, & kernelTime, & userTime)) {
              ULARGE_INTEGER creationTimeULI;
              creationTimeULI.LowPart = creationTime.dwLowDateTime;
              creationTimeULI.HighPart = creationTime.dwHighDateTime;
              DWORD creationTimeMS = static_cast < DWORD > (creationTimeULI.QuadPart / 10000);
              if (creationTimeMS < earliestCreationTime) {
                earliestCreationTime = creationTimeMS;
                mainThreadId = threadEntry.th32ThreadID;
              }
            }
            CloseHandle(hThread);
          }
        }
      } while (Thread32Next(hSnapshot, & threadEntry));
    }
    CloseHandle(hSnapshot);

    return mainThreadId;
  }
};

#endif // PROCESS_STACKWALK_CHECKER_H