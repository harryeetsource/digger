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
#pragma comment(lib, "Dbghelp.lib")

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
void scan_processes(bool dump_if_debug_registers_set);
bool is_suspicious_api_call(const CONTEXT& context);

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

            // Check if the process is suspended
            HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, entry.th32ProcessID);
            if (process != NULL) {
                THREADENTRY32 thread_entry;
                thread_entry.dwSize = sizeof(THREADENTRY32);
                HANDLE thread_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, entry.th32ProcessID);
                if (Thread32First(thread_snapshot, &thread_entry) == TRUE) {
                    bool is_suspended = true;
                    do {
                        if (thread_entry.th32OwnerProcessID == entry.th32ProcessID) {
                            HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, thread_entry.th32ThreadID);
                            if (thread != NULL) {
                                // Suspend the thread to avoid interference with the memory dump
                                SuspendThread(thread);

                                // Get the context of the thread to check for suspicious API calls
                                CONTEXT context;
                                memset(&context, 0, sizeof(context));
                                context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;
                                if (GetThreadContext(thread, &context) == TRUE) {
                                    if (is_suspicious_api_call(context)) {
                                        // Dump the process memory if a suspicious API call is detected
dump_process(entry.th32ProcessID, dumped_processes);
break;
}
}
                            // Resume the thread and close the handle
                            ResumeThread(thread);
                            CloseHandle(thread);
                        }
                    }
                } while (Thread32Next(thread_snapshot, &thread_entry) == TRUE && !dumped_processes.count(entry.th32ProcessID));
            }

            // If dump_if_debug_registers_set is set, check for the presence of debug registers
            if (dump_if_debug_registers_set) {
                DWORD debug_register_value;
                if (GetThreadContext(GetCurrentThread(), &context)) {
                    if (context.Dr0 || context.Dr1 || context.Dr2 || context.Dr3) {
                        // Dump the process memory if any debug registers are set
                        dump_process(entry.th32ProcessID, dumped_processes);
                    }
                }
            }

            CloseHandle(process);
        }
    } while (Process32Next(snapshot, &entry) == TRUE && !dumped_processes.count(entry.th32ProcessID));
}
CloseHandle(snapshot);
}
// Check if the given context has made any suspicious API calls
bool is_suspicious_api_call(const CONTEXT& context) {
PEB* peb = (PEB*)__readgsqword(0x60);
PEB_LDR_DATA* ldr_data = peb->Ldr;
LIST_ENTRY* module_list = &ldr_data->InMemoryOrderModuleList;
for (LIST_ENTRY* module_entry = module_list->Flink; module_entry != module_list; module_entry = module_entry->Flink) {
LDR_DATA_TABLE_ENTRY* ldr_data_table_entry = CONTAINING_RECORD(module_entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
HMODULE module_handle = (HMODULE)ldr_data_table_entry->Reserved3[1];
const char* module_name = (const char*)ldr_data_table_entry->FullDllName.Buffer;
if (module_name == NULL) {
continue;
}
if (strstr(module_name, "kernel32.dll") == NULL && strstr(module_name, "ntdll.dll") == NULL) {
continue;
}
IMAGE_DOS_HEADER dos_header;
IMAGE_NT_HEADERS nt_headers;
if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)module_handle, &dos_header, sizeof(dos_header), NULL)) {
continue;
}
if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)((DWORD)module_handle + dos_header.e_lfanew), &nt_headers, sizeof(nt_headers), NULL)) {
continue;
}
IMAGE_EXPORT_DIRECTORY export_directory;
if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)((DWORD)module_handle + nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress), &export_directory, sizeof(export_directory), NULL)) {
continue;
}
DWORD* address_of_functions = new DWORD[export_directory.NumberOfFunctions];
if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)((DWORD)module_handle + export_directory.AddressOfFunctions), address_of_functions, export_directory.NumberOfFunctions * sizeof(DWORD), NULL)) {
delete[] address_of_functions;
continue;
}
for (int i = 0; i < export_directory.NumberOfFunctions; i++) {
if (address_of_functions[i] == NULL) {
continue;
}
char function_name[512];
DWORD function_ordinal = export_directory.Base + i;
if (HIWORD(function_ordinal) == 0) {
continue;
}
if (!ReadProcessMemory(GetCurrentProcess(), (LPCONT)((DWORD)module_handle + export_directory.AddressOfNames + (i * sizeof(DWORD))), &function_name, sizeof(function_name), NULL)) {
continue;
}
if (function_name == NULL) {
continue;
}
for (int j = 0; j < num_suspicious_api_functions; j++) {
if (strstr(function_name, suspicious_api_functions[j]) != NULL) {
return true;
}
}
}
delete[] address_of_functions;
}
return false;
}

// Dump the memory of a process and add it to the set of dumped processes
void dump_process(DWORD process_id, set<DWORD>& dumped_processes) {
// Get the handle of the process
HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
if (process == NULL) {
return;
}
// Suspend all threads in the process to avoid interference with the memory dump
THREADENTRY32 thread_entry;
thread_entry.dwSize = sizeof(THREADENTRY32);
HANDLE thread_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, process_id);
if (Thread32First(thread_snapshot, &thread_entry) == TRUE) {
    do {
        if (thread_entry.th32OwnerProcessID == process_id) {
            HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, thread_entry.th32ThreadID);
            if (thread != NULL) {
                SuspendThread(thread);
                CloseHandle(thread);
            }
        }
    } while (Thread32Next(thread_snapshot, &thread_entry) == TRUE);
}

// Dump the memory of the process
char filename[MAX_PATH];
sprintf_s(filename, MAX_PATH, "process_%d.dmp", process_id);
HANDLE file = CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
if (file != INVALID_HANDLE_VALUE) {
    MINIDUMP_EXCEPTION_INFORMATION exception_info;
    exception_info.ThreadId = GetCurrentThreadId();
    exception_info.ExceptionPointers = NULL;
    exception_info.ClientPointers = FALSE;
    MiniDumpWriteDump(process, process_id, file, MiniDumpWithFullMemory, &exception_info, NULL, NULL);
    CloseHandle(file);
    dumped_processes.insert(process_id);
}

// Resume all threads in the process
if (Thread32First(thread_snapshot, &thread_entry) == TRUE) {
    do {
        if (thread_entry.th32OwnerProcessID == process_id) {
            HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, thread_entry.th32ThreadID);
            if (thread != NULL) {
                ResumeThread(thread);
                CloseHandle(thread);
            }
        }
    } while (Thread32Next(thread_snapshot, &thread_entry) == TRUE);
}
CloseHandle(process);
}
// Convert a MEMORY_BASIC_INFORMATION structure to a MemoryRegion
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

// Check if a memory region is suspicious
bool is_memory_suspicious(const MemoryRegion& region, DWORD process_id) {
// Ignore regions that are not committed or that are read-only
if (region.state != MEM_COMMIT || region.protect == PAGE_READONLY || region.protect == PAGE_EXECUTE_READ) {
return false;
}
// Check if any suspicious APIs are present in the region
DWORD start_address = (DWORD)region.BaseAddress;
DWORD end_address = start_address + region.RegionSize;
for (DWORD address = start_address; address < end_address; address++) {
for (int i = 0; i < num_suspicious_api_functions; i++) {
const char* api_name = suspicious_api_functions[i];
const size_t api_name_len = strlen(api_name);
if (memcmp((void*)address, api_name, api_name_len) == 0) {
// Dump the process memory if a suspicious API call is detected
dump_process(process_id, set<DWORD>());
return true;
}
}
}
return false;
}

int main() {
scan_processes(true);
return 0;
}

