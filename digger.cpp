#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>

using namespace std;

// Define the list of suspicious API functions
const char* suspicious_api_functions[] = { "HideThreadFromDebugger", "DllRegisterServer", "SuspendThread", "ShellExecute", "ShellExecuteW", "ShellExecuteEx", "ZwLoadDriver", "MapViewOfFile", "GetAsyncKeyState", "SetWindowsHookEx", "GetForegroundWindow", "WSASocket", "bind", "URLDownloadToFile", "InternetOpen", "InternetConnect", "WriteProcessMemory", "GetTickCount", "GetEIP", "free", "WinExec", "UnhookWindowsHookEx", "WinHttpOpen", "LoadLibrary", "VirtualAlloc", "VirtualProtect", "CreateRemoteThread", "CreateProcess", "NtCreateThreadEx", "SetWindowsHookEx" };
const int num_suspicious_api_functions = sizeof(suspicious_api_functions) / sizeof(char*);

struct MemoryRegion {
    void* base_address;
    size_t region_size;
    DWORD protection;
};
// Check if a memory region is suspicious
bool is_memory_suspicious(const MemoryRegion* region) {
    // Retrieve memory protection information
    MEMORY_BASIC_INFORMATION info;
    if (!VirtualQuery(region->base_address, &info, sizeof(info))) {
        return false;
    }

    // Check for injected memory region
    if ((info.State & MEM_COMMIT) && (info.Protect & PAGE_EXECUTE_READWRITE)) {
        return true;
    }

    // Check for executable memory region that does not map to a file on disk
    if ((info.State & MEM_COMMIT) && (info.Protect & PAGE_EXECUTE) && (info.Type & MEM_IMAGE)) {
        char module_name[MAX_PATH];
        GetModuleFileNameA((HMODULE)info.AllocationBase, module_name, MAX_PATH);
        if (strlen(module_name) == 0) {
            return true;
        }
    }

    // Check for any RWX region
    if ((info.State & MEM_COMMIT) && (info.Protect & PAGE_EXECUTE_READWRITE)) {
        return true;
    }

    return false;
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
                HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, entry.th32ProcessID);
                if (process != NULL) {
                    char filename[MAX_PATH];
                    sprintf_s(filename, MAX_PATH, "%s.dmp", entry.szExeFile);
                    HANDLE file = CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                    if (file != INVALID_HANDLE_VALUE) {
                        SIZE_T bytes_written;
                        const size_t buffer_size = 1024;
                        char buffer[buffer_size];
                        DWORD_PTR address = 0;
                        while (address < 0x7FFFFFFF && ReadProcessMemory(process, (LPCVOID)address, buffer, buffer_size, &bytes_written)) {
                            MemoryRegion region = { (void*)address, bytes_written };
                            if (is_memory_suspicious(&region)) {
                                cout << "Found suspicious memory in process: " << entry.szExeFile << endl;
                                DWORD bytes_written;
                                WriteFile(file, buffer, bytes_written, &bytes_written, NULL);
                            }
                            address += bytes_written;
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


                       
