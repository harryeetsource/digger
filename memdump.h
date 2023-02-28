#ifndef MEMDUMP_H
#define MEMDUMP_H

#include <Windows.h>
#include <Psapi.h>
#include <iostream>
#include <string>
#include <set>

class MemDumper {
public:
    static void dump_process_memory(DWORD processId) {
        // Check if we've already dumped the memory of this process
        if (dumpedPids.count(processId)) {
            std::cout << "Memory of process " << processId << " already dumped, skipping..." << std::endl;
            return;
        }

        // Open a handle to the process
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (hProcess == NULL) {
            std::cerr << "Error: could not open process " << processId << std::endl;
            return;
        }

        // Get the name of the process
        TCHAR processName[MAX_PATH];
        if (GetModuleFileNameEx(hProcess, NULL, processName, MAX_PATH) == 0) {
            std::cerr << "Error: could not get process name for process " << processId << std::endl;
            CloseHandle(hProcess);
            return;
        }

        // Dump the memory of the process
        std::string dumpFilePath = std::string(processName) + "_" + std::to_string(processId) + ".dmp";
        HANDLE hFile = CreateFile(dumpFilePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            std::cerr << "Error: could not create memory dump file for process " << processId << std::endl;
            CloseHandle(hProcess);
            return;
        }
        if (MiniDumpWriteDump(hProcess, processId, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL) == FALSE) {
            std::cerr << "Error: could not dump memory for process " << processId << std::endl;
            CloseHandle(hProcess);
            CloseHandle(hFile);
            DeleteFile(dumpFilePath.c_str());
            return;
        }

        // Close the file and process handles
        CloseHandle(hFile);
        CloseHandle(hProcess);

        std::cout << "Memory of process " << processId << " dumped to file " << dumpFilePath << std::endl;
        dumpedPids.insert(processId);
    }

private:
    static std::set<DWORD> dumpedPids;
};

std::set<DWORD> MemDumper::dumpedPids;

#endif // MEMDUMP_H
