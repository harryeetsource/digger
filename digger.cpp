#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>

using namespace std;
struct MemoryRegion {
    void* BaseAddress;
    size_t RegionSize;
    DWORD allocation_type;
    DWORD state;
    DWORD protect;
    DWORD allocation_protect;
};

// Define the list of suspicious API functions
const char* suspicious_api_functions[] = { "HideThreadFromDebugger", "DllRegisterServer", "SuspendThread", "ShellExecute", "ShellExecuteW", "ShellExecuteEx", "ZwLoadDriver", "MapViewOfFile", "GetAsyncKeyState", "SetWindowsHookEx", "GetForegroundWindow", "WSASocket", "bind", "URLDownloadToFile", "InternetOpen", "InternetConnect", "WriteProcessMemory", "GetTickCount", "GetEIP", "free", "WinExec", "UnhookWindowsHookEx", "WinHttpOpen" };
const int num_suspicious_api_functions = sizeof(suspicious_api_functions) / sizeof(char*);

// Convert a MEMORY_BASIC_INFORMATION structure to a MemoryRegion structure
MemoryRegion to_memory_region(const MEMORY_BASIC_INFORMATION& memory_info) {
    MemoryRegion region;
    region.BaseAddress = memory_info.BaseAddress;
    region.RegionSize = memory_info.RegionSize;
    region.allocation_type = memory_info.Type;
    region.state = memory_info.State;
    region.protect = memory_info.Protect;
    region.allocation_protect = memory_info.AllocationProtect;
    return region;
}

// Define the list of suspicious memory regions
bool is_memory_suspicious(const MemoryRegion& region) {
    if ((region.allocation_type & MEM_COMMIT) && (region.allocation_protect & PAGE_EXECUTE_READWRITE)) {
        // Executable memory region with RWX protection
        return true;
    } else if ((region.allocation_type & MEM_IMAGE) && (region.state & MEM_COMMIT) && !(region.protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY)) && (region.protect & PAGE_EXECUTE_READWRITE)) {
        // Executable memory region that does not map to a file on disk
        return true;
    } else if ((region.allocation_type & MEM_COMMIT) && (region.protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_READWRITE | PAGE_WRITECOPY))) {
        // RWX memory region
        return true;
    } else {
        return false;
    }
}

// Scan for suspicious processes
void scan_processes() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(snapshot, &entry) == TRUE) {
        do {
            // Check if the process has a non-existent parent
            HANDLE parent_process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, entry.th32ParentProcessID);
            if (parent_process == NULL && entry.th32ParentProcessID != 0) {
                cout << "Found suspicious process with non-existent parent: " << entry.szExeFile << endl;
                // Write the process memory to disk
                HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, entry.th32ProcessID);
if (process != NULL) {
    char filename[MAX_PATH];
    sprintf_s(filename, MAX_PATH, "%s.dmp", entry.szExeFile);
    HANDLE file = CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file != INVALID_HANDLE_VALUE) {
        SYSTEM_INFO system_info;
        GetSystemInfo(&system_info);
        DWORD_PTR address = (DWORD_PTR)system_info.lpMinimumApplicationAddress;
        while (address < (DWORD_PTR)system_info.lpMaximumApplicationAddress) {
            MEMORY_BASIC_INFORMATION memory_info;
            if (VirtualQueryEx(process, (LPCVOID)address, &memory_info, sizeof(memory_info)) == sizeof(memory_info)) {
                if (memory_info.State == MEM_COMMIT) {
                    MemoryRegion region = to_memory_region(memory_info);
                    if (!is_memory_suspicious(region)) {
                        char* buffer = new char[memory_info.RegionSize];
                        SIZE_T bytes_read;
                        if (ReadProcessMemory(process, memory_info.BaseAddress, buffer, memory_info.RegionSize, &bytes_read)) {
                            DWORD bytes_written;
                            WriteFile(file, buffer, bytes_read, &bytes_written, NULL);
                        }
                        delete[] buffer;
                    }
                }
                address += memory_info.RegionSize;
            }
            else {
                address += system_info.dwPageSize;
            }
        }
        CloseHandle(file);
    }
    CloseHandle(process);
}
}
            CloseHandle(parent_process);
        } while (Process32Next(snapshot, &entry) == TRUE);
    }
    CloseHandle(snapshot);
}

// Scan for suspicious API calls
void scan_api_calls() {
    HMODULE module = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)module + dos_header->e_lfanew);
    PIMAGE_IMPORT_DESCRIPTOR import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)module + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    while ((uintptr_t)import_descriptor->Name != 0) {
        const char* module_name = (const char*)((BYTE*)module + import_descriptor->Name);
        for (int i = 0; i < num_suspicious_api_functions; i++) {
            if (_stricmp(module_name, suspicious_api_functions[i]) == 0) {
                PIMAGE_THUNK_DATA thunk_data = (PIMAGE_THUNK_DATA)((BYTE*)module + import_descriptor->FirstThunk);
                while ((uintptr_t)thunk_data->u1.Function != 0) {
                    FARPROC function = (FARPROC)thunk_data->u1.Function;
                    if (function != NULL) {
                        const char* function_name = (const char*)((BYTE*)module + *(DWORD*)((BYTE*)function + 2));
                        if (_stricmp(function_name, suspicious_api_functions[i]) == 0) {
                            cout << "Found suspicious API function: " << function_name << endl;
                        }
                    }
                    thunk_data++;
                }
            }
        }
        import_descriptor++;
    }
}

int main() {
    scan_processes();
    scan_api_calls();
    return 0;
}
