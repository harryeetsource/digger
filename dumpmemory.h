#ifndef MEMORY_DUMPER_H
#define MEMORY_DUMPER_H

#include <Windows.h>
#include <Psapi.h>
#include <set>
#include <dbghelp.h>
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

void dumpMemoryOfProcesses(const std::set<DWORD>& processIds) {
    // Loop through all specified process IDs
    for (DWORD processId : processIds) {
        // Ignore this process
        if (processId == GetCurrentProcessId()) {
            continue;
        }

        // Open a handle to the process
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (hProcess == NULL) {
            std::cerr << "Error: could not open process " << processId << std::endl;
            continue;
        }

        // Get the name of the process
        TCHAR processName[MAX_PATH];
        if (GetModuleFileNameEx(hProcess, NULL, processName, MAX_PATH) == 0) {
            std::cerr << "Error: could not get process name for process " << processId << std::endl;
            CloseHandle(hProcess);
            continue;
        }
        PathStripPath(processName);
        // Dump the memory of the process
        std::string dumpFilePath = std::string(processName) + "_" + std::to_string(processId) + ".dmp";
        HANDLE hFile = CreateFile(dumpFilePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            std::cerr << "Error: could not create memory dump file for process " << processId << std::endl;
            CloseHandle(hProcess);
            continue;
        }
        if (MiniDumpWriteDump(hProcess, processId, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL) == FALSE) {
            std::cerr << "Error: could not dump memory for process " << processId << std::endl;
            CloseHandle(hProcess);
            CloseHandle(hFile);
            DeleteFile(dumpFilePath.c_str());
            continue;
        }

        // Close the file and process handles
        CloseHandle(hFile);
        CloseHandle(hProcess);

        std::cout << "Memory of process " << processId << " dumped to file " << dumpFilePath << std::endl;
    }
}

#endif // MEMORY_DUMPER_H
