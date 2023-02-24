#ifndef INJECTED_CODE_CHECK_H
#define INJECTED_CODE_CHECK_H

#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <vector>
#include <stdexcept>

#pragma comment(lib, "ntdll.lib")

bool isInjectedProcess(DWORD processId) {
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!processHandle) {
        throw std::runtime_error("Failed to open process handle.");
    }

    NTSTATUS status;
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    status = NtQueryInformationProcess(processHandle, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
    if (!NT_SUCCESS(status)) {
        CloseHandle(processHandle);
        throw std::runtime_error("Failed to query process information.");
    }

    PEB peb;
    if (!ReadProcessMemory(processHandle, pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
        CloseHandle(processHandle);
        throw std::runtime_error("Failed to read process memory.");
    }

    PEB_LDR_DATA pebLdrData;
    if (!ReadProcessMemory(processHandle, peb.Ldr, &pebLdrData, sizeof(pebLdrData), NULL)) {
        CloseHandle(processHandle);
        throw std::runtime_error("Failed to read process memory.");
    }

    for (LIST_ENTRY *moduleList = pebLdrData.InMemoryOrderModuleList.Flink; moduleList != &pebLdrData.InMemoryOrderModuleList; moduleList = moduleList->Flink) {
        LDR_DATA_TABLE_ENTRY module;
        if (!ReadProcessMemory(processHandle, CONTAINING_RECORD(moduleList, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks), &module, sizeof(module), NULL)) {
            CloseHandle(processHandle);
            throw std::runtime_error("Failed to read process memory.");
        }
        if (module.FullDllName.Buffer) {
            std::wstring dllName(module.FullDllName.Buffer, module.FullDllName.Length / 2);
            if (dllName.find(L"ext.dll") != std::wstring::npos) {
                CloseHandle(processHandle);
                return true;
            }
        }
    }

    CloseHandle(processHandle);
    return false;
}

#endif // INJECTED_CODE_CHECK_H
