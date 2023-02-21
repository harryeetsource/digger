#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <cstring>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <unordered_set>
#include <set>
#include <wchar.h>
#include <winternl.h>
#include <dbghelp.h>
#pragma comment(lib, "ntdll.lib")
#define L(x) L##x
using namespace std;

struct MemoryRegion {
    void* BaseAddress;
    size_t RegionSize;
    DWORD allocation_type;
    DWORD state;
    DWORD protect;
    DWORD allocation_protect;
};

// Declare function prototypes
void dump_process(DWORD process_id, set<DWORD>& dumped_processes);
MemoryRegion to_memory_region(const MEMORY_BASIC_INFORMATION& memory_info);
bool is_memory_suspicious(const MemoryRegion& region, DWORD process_id);


// Define the list of suspicious API functions
const char* suspicious_api_functions[] = {
    "CreateRemoteThread",
    "HideThreadFromDebugger",
    "DllRegisterServer",
    "SuspendThread",
    "ShellExecute",
    "ShellExecuteW",
    "ShellExecuteEx",
    "ZwLoadDriver",
    "MapViewOfFile",
    "GetAsyncKeyState",
    "SetWindowsHookEx",
    "GetForegroundWindow",
    "WSASocket",
    "bind",
    "URLDownloadToFileA",
    "InternetOpen",
    "InternetConnect",
    "WriteProcessMemory",
    "GetTickCount",
    "GetEIP",
    "free",
    "WinExec",
    "UnhookWindowsHookEx",
    "WinHttpOpen"
};
const int num_suspicious_api_functions = sizeof(suspicious_api_functions) / sizeof(char*);

// Scan for suspicious processes
void scan_processes(bool dump_if_debug_registers_set) {
    set<DWORD> dumped_processes;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(snapshot, &entry) == TRUE) {
        do {
            // Check if the process has already been dumped
            if (dumped_processes.count(entry.th32ProcessID) > 0) {
                continue;
            }
            // Check if the process has a non-existent parent
            HANDLE parent_process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, entry.th32ParentProcessID);
            if (parent_process == NULL && entry.th32ParentProcessID != 0) {
                cout << "Found suspicious process with non-existent parent: " << entry.szExeFile << endl;
                dump_process(entry.th32ProcessID, dumped_processes);
            }
            CloseHandle(parent_process);

            // Check if the process is being debugged
            HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, entry.th32ProcessID);
            if (process != NULL) {
                DWORD_PTR peb_address = 0;
                // Get the PEB address
                PROCESS_BASIC_INFORMATION pbi;
                if (NtQueryInformationProcess(process, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL) == 0) {
                    peb_address = (DWORD_PTR)pbi.PebBaseAddress;
                }
                // Read the PEB
                PEB peb;
                SIZE_T bytes_read;
                if (ReadProcessMemory(process, (LPVOID)peb_address, &peb, sizeof(PEB), &bytes_read) && bytes_read == sizeof(PEB)) {
                    // Check if the process is being debugged
                    if (peb.BeingDebugged){
cout << "Found suspicious process being debugged: " << entry.szExeFile << endl;
// If dump_if_debug_registers_set is set to true, dump the process if it has debug registers set
if (dump_if_debug_registers_set) {
CONTEXT context;
context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
if (GetThreadContext(process, &context)) {
if (context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0) {
dump_process(entry.th32ProcessID, dumped_processes);
}
}
}
}
CloseHandle(process);
}
}
} while (Process32Next(snapshot, &entry) == TRUE);
}
CloseHandle(snapshot);
}

void dump_process(DWORD process_id, set<DWORD>& dumped_processes) {
    // Open the process
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
    if (process != NULL) {
        // Create a file to dump the memory to
        stringstream ss;
        ss << "process_" << process_id << "_dump.bin";
        ofstream file(ss.str().c_str(), ios::out | ios::binary);
        if (!file.is_open()) {
            cout << "Failed to open file for dumping process " << process_id << endl;
            CloseHandle(process);
            return;
        }
        cout << "Dumping process " << process_id << " to " << ss.str() << endl;
        // Get the minimum and maximum address to dump
        SYSTEM_INFO system_info;
        GetSystemInfo(&system_info);
        void* min_address = system_info.lpMinimumApplicationAddress;
        void* max_address = system_info.lpMaximumApplicationAddress;
        // Dump each suspicious memory region
        MEMORY_BASIC_INFORMATION memory_info;
        for (void* address = min_address; address < max_address; address = (char*)memory_info.BaseAddress + memory_info.RegionSize) {
            if (VirtualQueryEx(process, address, &memory_info, sizeof(memory_info)) == sizeof(memory_info)) {
                MemoryRegion region = to_memory_region(memory_info);
                if (is_memory_suspicious(region, process_id)) {
                    // Dump the memory region to file
                    char* buffer = new char[region.RegionSize];
                    SIZE_T bytes_read;
                    if (ReadProcessMemory(process, region.BaseAddress, buffer, region.RegionSize, &bytes_read)) {
                        file.write(buffer, region.RegionSize);
                    }
                    delete[] buffer;
                }
            }
        }
        file.close();
        dumped_processes.insert(process_id);
        CloseHandle(process);
    }
}

bool is_memory_suspicious(const MemoryRegion& region, DWORD process_id) {
    // Check if the region is writable or executable
    if (region.protect & PAGE_EXECUTE || region.protect & PAGE_EXECUTE_READ || region.protect & PAGE_EXECUTE_READWRITE || region.protect & PAGE_EXECUTE_WRITECOPY || region.protect & PAGE_WRITECOPY || region.protect & PAGE_READWRITE) {
        // Check if the memory region contains a suspicious API function
        char buffer[MAX_PATH];
        GetMappedFileName(GetCurrentProcess(), region.BaseAddress, buffer, MAX_PATH);
        string filename = buffer;
if (filename.length() > 4 && filename.substr(0, 4) == "\\\\?\\") {
    filename = filename.substr(4);
}

        if (filename.find(".dll") != string::npos || filename.find(".exe") != string::npos) {
            HMODULE module = LoadLibraryExA(buffer, NULL, DONT_RESOLVE_DLL_REFERENCES);
            if (module != NULL) {
                for (int i = 0; i < num_suspicious_api_functions; i++) {
                    FARPROC function_address = GetProcAddress(module, suspicious_api_functions[i]);
                    if (function_address != NULL && ((char*)function_address == (char*)region.BaseAddress || ((char*)function_address > (char*)region.BaseAddress && (char*)function_address < (char*)region.BaseAddress + region.RegionSize))) {


                        // Suspicious memory found, dump to file
                        stringstream ss;
                        ss << "process_" << process_id << "_suspicious_memory_" << function_address << ".bin";
                        ofstream file(ss.str().c_str(), ios::out | ios::binary);
                        if (!file.is_open()) {
                            cout << "Failed to open file for dumping suspicious memory for process " << process_id << endl;
                            FreeLibrary(module);
                            return true;
                        }
                        char* buffer = new char[region.RegionSize];
                        SIZE_T bytes_read;
                        HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
                        if (ReadProcessMemory(process, region.BaseAddress, buffer, region.RegionSize, &bytes_read)) {

                            file.write(buffer, region.RegionSize);
                        }
                        file.close();
                        delete[] buffer;
                        FreeLibrary(module);
                        return true;
                    }
                }
                FreeLibrary(module);
            }
        }
    }
    return false;
}



MemoryRegion to_memory_region(const MEMORY_BASIC_INFORMATION& memory_info) {
MemoryRegion region;
region.BaseAddress = memory_info.BaseAddress;
region.RegionSize = memory_info.RegionSize;
region.allocation_type = memory_info.AllocationProtect;
region.state = memory_info.State;
region.protect = memory_info.Protect;
region.allocation_protect = memory_info.AllocationProtect;
return region;
}

int main() {
scan_processes(true);
return 0;
}
