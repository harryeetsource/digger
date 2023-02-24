#ifndef PROCESS_ENUMERATOR_H
#define PROCESS_ENUMERATOR_H

#include <windows.h>
#include <tlhelp32.h>
#include <vector>

class ProcessEnumerator
{
public:
    static std::vector<DWORD> getProcessIds();
};

std::vector<DWORD> ProcessEnumerator::getProcessIds()
{
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

#endif // PROCESS_ENUMERATOR_H
