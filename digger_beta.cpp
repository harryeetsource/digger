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

const int num_suspicious_api_functions = sizeof(suspicious_api_functions) / sizeof(const char*);

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
                                    if (is_suspicious_api_call(context)){
// Dump the process memory if debug registers are set
if (dump_if_debug_registers_set) {
dump_process(entry.th32ProcessID, dumped_processes);
} else {
// Get the list of memory regions for the process
vector<MemoryRegion> memory_regions;
MEMORY_BASIC_INFORMATION memory_info;
memset(&memory_info, 0, sizeof(memory_info));
void* address = NULL;
while (VirtualQueryEx(process, address, &memory_info, sizeof(memory_info)) == sizeof(memory_info)) {
// Convert the memory information to a MemoryRegion struct
MemoryRegion region = to_memory_region(memory_info);
// Check if the memory region is suspicious
if (is_memory_suspicious(region, entry.th32ProcessID)) {
memory_regions.push_back(region);
}
address = (char*)address + memory_info.RegionSize;
}
                                        // Dump the suspicious memory regions for the process
                                        if (!memory_regions.empty()) {
                                            dump_process(entry.th32ProcessID, dumped_processes, memory_regions);
                                        }
                                    }
                                }

                                // Resume the thread to allow it to continue running
                                ResumeThread(thread);
                                CloseHandle(thread);
                            }
                        }
                    }
                } while (Thread32Next(thread_snapshot, &thread_entry) == TRUE);
                CloseHandle(thread_snapshot);
            }
            CloseHandle(process);
        }
    } while (Process32Next(snapshot, &entry) == TRUE);
}
CloseHandle(snapshot);
}

// Check if a particular API call is suspicious
bool is_suspicious_api_call(const CONTEXT& context) {
// Get the program counter (instruction pointer) from the context
DWORD_PTR program_counter = context.Eip;
// Get the function name at the current program counter using DbgHelp
char function_name[256];
function_name[0] = '\0';
IMAGEHLP_SYMBOL* symbol = (IMAGEHLP_SYMBOL*)malloc(sizeof(IMAGEHLP_SYMBOL) + 256);
memset(symbol, 0, sizeof(IMAGEHLP_SYMBOL) + 256);
symbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL);
symbol->MaxNameLength = 255;
DWORD displacement;
if (SymGetSymFromAddr(GetCurrentProcess(), program_counter, &displacement, symbol) == TRUE) {
    strcpy(function_name, symbol->Name);
}
free(symbol);

// Check if the function name is in the list of suspicious API functions
for (int i = 0; i < num_suspicious_api_functions; i++) {
    if (strcmp(function_name, suspicious_api_functions[i]) == 0) {
        return true;
    }
}
return false;
}

// Convert a MEMORY_BASIC_INFORMATION struct to a MemoryRegion struct
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
    // Check if the memory region is not a PAGE_NOACCESS or PAGE_GUARD region
    if (region.protect == PAGE_NOACCESS || region.protect == PAGE_GUARD) {
        return false;
    }
    // Check if the memory region is executable
    if ((region.protect & PAGE_EXECUTE) != PAGE_EXECUTE &&
        (region.protect & PAGE_EXECUTE_READ) != PAGE_EXECUTE_READ &&
        (region.protect & PAGE_EXECUTE_READWRITE) != PAGE_EXECUTE_READWRITE &&
        (region.protect & PAGE_EXECUTE_WRITECOPY) != PAGE_EXECUTE_WRITECOPY) {
        return false;
    }
    // Check if the memory region is not a system DLL or executable module
    HMODULE module = NULL;
    if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                          (LPCTSTR)region.BaseAddress, &module) == TRUE) {
        // Get the module information
        MODULEINFO module_info;
        if (GetModuleInformation(GetCurrentProcess(), module, &module_info, sizeof(module_info)) == TRUE) {
            wchar_t module_file_name[MAX_PATH];
            if (GetModuleFileNameExW(GetCurrentProcess(), module, module_file_name, MAX_PATH) != 0) {
                wstring file_name = wstring(module_file_name);
                // Check if the file name contains the Windows or System32 directory
                if (file_name.find(L"\\Windows\\") != wstring::npos || file_name.find(L"\\System32\\") != wstring::npos) {
                    return false;
                }
                // Check if the file name matches a known system DLL or executable module
                unordered_set<wstring> system_modules = {
                    L"ntdll.dll",
                    L"kernel32.dll",
                    L"kernelbase.dll",
                    L"user32.dll",
                    L"gdi32.dll",
                    L"lpk.dll",
                    L"usp10.dll",
                    L"advapi32.dll",
                    L"shell32.dll",
                    L"ole32.dll",
                    L"oleaut32.dll",
                    L"comctl32.dll",
                    L"comdlg32.dll",
                    L"wininet.dll",
                    L"wsock32.dll",
                    L"ws2_32.dll",
                    L"netapi32.dll",
                    L"version.dll",
                    L"rpcrt4.dll",
                    L"shlwapi.dll",
                    L"urlmon.dll",
                    L"crypt32.dll",
                    L"msasn1.dll",
                    L"sspicli.dll",
                    L"secur32.dll",
                    L"imm32.dll",
                    L"msctf.dll",
                    L"cryptdll.dll",
                    L"uxtheme.dll",
                    L"mswsock.dll",
                    L"wshtcpip.dll"
                };
                wstring file_name_lower = file_name;
                transform(file_name_lower.begin(), file_name_lower.end(), file_name_lower.begin(), towlower);
                if (system_modules.count(file_name_lower) > 0) {
                    return false;
                }
            }
        }
    }
    return true;
}

// Dump the memory of a process to a file
void dump_process(DWORD process_id, set<DWORD>& dumped_processes, const vector<MemoryRegion>& memory_regions) {
    // Check if the process has already been dumped
    if (dumped_processes.count(process_id) > 0) {
        return;
    }
    dumped_processes.insert

// Open the process and create the output file
HANDLE process = OpenProcess(PROCESS_VM_READ, FALSE, process_id);
wstringstream file_name_stream;
file_name_stream << "memory_dump_" << process_id << ".dmp";
wstring file_name = file_name_stream.str();
ofstream output_file(file_name, ios::binary);

// Write the process ID and timestamp to the output file
DWORD timestamp = GetTickCount();
output_file.write((char*)&process_id, sizeof(process_id));
output_file.write((char*)&timestamp, sizeof(timestamp));

// Write the memory regions to the output file
for (const MemoryRegion& region : memory_regions) {
    // Allocate a buffer to hold the memory region contents
    void* buffer = VirtualAlloc(NULL, region.RegionSize, MEM_COMMIT, PAGE_READWRITE);
    if (buffer != NULL) {
        // Read the memory region contents into the buffer
        SIZE_T bytes_read;
        if (ReadProcessMemory(process, region.BaseAddress, buffer, region.RegionSize, &bytes_read) == TRUE) {
            // Write the memory region header to the output file
            output_file.write((char*)&region, sizeof(region));

            // Write the memory region contents to the output file
            output_file.write((char*)buffer, region.RegionSize);
        }

        // Free the buffer
        VirtualFree(buffer, 0, MEM_RELEASE);
    }
}

// Close the process and output file
CloseHandle(process);
output_file.close();
}

// Dump the memory of a process to a file
void dump_process(DWORD process_id, set<DWORD>& dumped_processes) {
// Check if the process has already been dumped
if (dumped_processes.count(process_id) > 0) {
return;
}
dumped_processes.insert(process_id);
// Open the process and create the output file
HANDLE process = OpenProcess(PROCESS_VM_READ, FALSE, process_id);
wstringstream file_name_stream;
file_name_stream << "memory_dump_" << process_id << ".dmp";
wstring file_name = file_name_stream.str();
ofstream output_file(file_name, ios::binary);

// Write the process ID and timestamp to the output file
DWORD timestamp = GetTickCount();
output_file.write((char*)&process_id, sizeof(process_id));
output_file.write((char*)&timestamp, sizeof(timestamp));

// Get the list of memory regions for the process
vector<MemoryRegion> memory_regions;
MEMORY_BASIC_INFORMATION memory_info;
memset(&memory_info, 0, sizeof(memory_info));
void* address = NULL;
while (VirtualQueryEx(process, address, &memory_info, sizeof(memory_info)) == sizeof(memory_info)) {
    // Convert the memory information to a MemoryRegion struct
    MemoryRegion region = to_memory_region(memory_info);

    // Check if the memory region is suspicious
    if (is_memory_suspicious(region, process_id)) {
        memory_regions.push_back(region);
    }

    address = (char*)address + memory_info.RegionSize;
}

// Write the memory regions to the output file
for (const MemoryRegion& region : memory_regions) {
    // Allocate a buffer to hold the memory region contents
    void* buffer = VirtualAlloc(NULL, region.RegionSize, MEM_COMMIT, PAGE_READWRITE);
    if (buffer != NULL) {
        // Read the memory region contents into the buffer
        SIZE_T bytes_read;
        if (ReadProcessMemory(process, region.BaseAddress, buffer, region.RegionSize, &bytes_read) == TRUE) {
            // Write the memory region header to the output file
                   output_file.write((char*)&region, sizeof(region));

        // Write the memory region contents to the output file
        output_file.write((char*)buffer, region.RegionSize);
    }

    // Free the buffer
    VirtualFree(buffer, 0, MEM_RELEASE);
}
}

// Close the process and output file
CloseHandle(process);
output_file.close();
}

int main() {
// Initialize the symbol handler for DbgHelp
SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
SymInitialize(GetCurrentProcess(), NULL, TRUE);
// Scan for suspicious processes and dump their memory if necessary
scan_processes(true);

// Cleanup the symbol handler
SymCleanup(GetCurrentProcess());

return 0;
}

