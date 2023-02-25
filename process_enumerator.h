#ifndef PROCESS_ENUMERATOR_H
#define PROCESS_ENUMERATOR_H

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <vector>
#include <string>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")

class ProcessEnumerator {
public:
    static std::vector<DWORD> getProcessIds();
    static std::vector<std::string> enumerateProcessModules(DWORD processId);
    static std::vector<std::string> getProcessApiFunctions(DWORD processId);
};

std::vector<DWORD> ProcessEnumerator::getProcessIds() {
    std::vector<DWORD> processIds;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 processEntry = {};
        processEntry.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &processEntry)) {
            do {
                processIds.push_back(processEntry.th32ProcessID);
            } while (Process32Next(hSnapshot, &processEntry));
        }
        CloseHandle(hSnapshot);
    }
    return processIds;
}

std::vector<std::string> ProcessEnumerator::enumerateProcessModules(DWORD processId) {
    std::vector<std::string> moduleNames;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        return moduleNames;
    }

    // Enumerate the modules of the process
    HMODULE hModules[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
        for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            // Get the module name
            char moduleName[MAX_PATH];
            if (GetModuleBaseNameA(hProcess, hModules[i], moduleName, sizeof(moduleName)) > 0) {
                moduleNames.push_back(moduleName);
            }
        }
    }

    CloseHandle(hProcess);

    return moduleNames;
}

std::vector<std::string> ProcessEnumerator::getProcessApiFunctions(DWORD processId) {
    std::vector<std::string> apiFunctions;
    SIZE_T bytesRead = 0;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        return apiFunctions;
    }

    // Read the PEB of the process
    PROCESS_BASIC_INFORMATION pbi;
    ULONG pbiSize = sizeof(pbi);
    if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, pbiSize, NULL) != 0) {
        CloseHandle(hProcess);
        return apiFunctions;
    }

    // Enumerate the modules of the process
    PEB peb;
    ULONG pebSize = sizeof(peb);
    if (ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, pebSize, NULL) == FALSE) {
        CloseHandle(hProcess);
        return apiFunctions;
    }
    // Traverse the InMemoryOrderModuleList to get the loaded modules
    PEB_LDR_DATA pebLdrData;
    if (ReadProcessMemory(hProcess, peb.Ldr, &pebLdrData, sizeof(pebLdrData), NULL) == FALSE) {
        CloseHandle(hProcess);
        return apiFunctions;
    }

    for (LIST_ENTRY* listEntry = pebLdrData.InMemoryOrderModuleList.Flink; listEntry != &pebLdrData.InMemoryOrderModuleList; listEntry = listEntry->Flink) {
        LDR_DATA_TABLE_ENTRY ldrDataEntry;
        if (ReadProcessMemory(hProcess, listEntry, &ldrDataEntry, sizeof(ldrDataEntry), &bytesRead) && ldrDataEntry.DllBase != NULL) {
            // Read the IMAGE_NT_HEADERS struct from the process's memory
            IMAGE_NT_HEADERS ntHeader;
            if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(reinterpret_cast<ULONG_PTR>(ldrDataEntry.DllBase) + reinterpret_cast<IMAGE_DOS_HEADER*>(ldrDataEntry.DllBase)->e_lfanew), &ntHeader, sizeof(ntHeader), NULL) == FALSE) {
                continue;
            }

            // Get the size of the export directory
            const DWORD exportDirSize = ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

            // Allocate memory to hold the export directory
            PIMAGE_EXPORT_DIRECTORY exportDir = static_cast<PIMAGE_EXPORT_DIRECTORY>(VirtualAlloc(NULL, exportDirSize, MEM_COMMIT, PAGE_READWRITE));
            if (exportDir == NULL) {
                continue;
            }

            // Read the export directory from the process's memory
            if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(reinterpret_cast<ULONG_PTR>(ldrDataEntry.DllBase) + ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress), exportDir, exportDirSize, NULL) == FALSE) {
                VirtualFree(exportDir, 0, MEM_RELEASE);
                continue;
            }

            // Get the arrays of function names, function addresses, and function ordinals
PDWORD nameArray = reinterpret_cast<PDWORD>(reinterpret_cast<ULONG_PTR>(ldrDataEntry.DllBase) + exportDir->AddressOfNames);
PDWORD addressArray = reinterpret_cast<PDWORD>(reinterpret_cast<ULONG_PTR>(ldrDataEntry.DllBase) + exportDir->AddressOfFunctions);
PWORD ordinalArray = reinterpret_cast<PWORD>(reinterpret_cast<ULONG_PTR>(ldrDataEntry.DllBase) + exportDir->AddressOfNameOrdinals);
        // Iterate over the names array to get the function names and their addresses
        for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
            // Get the name of the function
            LPSTR functionName = nullptr;
            if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(reinterpret_cast<ULONG_PTR>(ldrDataEntry.DllBase) + nameArray[i]), &functionName, sizeof(functionName), NULL) == FALSE || functionName == nullptr) {
                continue;
            }

            // Get the ordinal of the function
            WORD functionOrdinal = ordinalArray[i];

            // Get the address of the function
            DWORD functionAddress = addressArray[functionOrdinal];
            if (functionAddress < ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress || functionAddress >= ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + exportDirSize) {
                // The function address is not inside the export directory
                continue;
            }

            // Add the function name to the vector
            apiFunctions.emplace_back(functionName);

            // Free the memory used to hold the function name
            VirtualFree(functionName, 0, MEM_RELEASE);
        }

        // Free the memory used to hold the export directory
        VirtualFree(exportDir, 0, MEM_RELEASE);
    }
}

CloseHandle(hProcess);
return apiFunctions;
}

#endif // PROCESS_ENUMERATOR_H


