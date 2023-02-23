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
#include <ntstatus.h>
#include <vector>
#include <mutex>

#ifdef _WIN64
#include <winnt.h>
#else
#include <wow64cpu.h>
#endif

#ifdef _WIN64
// Define x64 context struct
CONTEXT64 context = { 0 };
context.ContextFlags = CONTEXT_ALL;
if (GetThreadContext(thread_handle, &context)) {
    // Use x64 context
}
#else
// Define x86 context struct
WOW64_CONTEXT context = { 0 };
context.ContextFlags = WOW64_CONTEXT_ALL;
if (Wow64GetThreadContext(thread_handle, &context)) {
    // Use x86 context
}
#endif

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Dbghelp.lib")

using namespace std;

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

const size_t num_suspicious_api_functions = sizeof(suspicious_api_functions) / sizeof(char*);

struct MemoryRegion {
    void* BaseAddress;
    size_t RegionSize;
    DWORD allocation_type;
    DWORD state;
    DWORD protect;
    DWORD allocation_protect;
};

namespace std {
    template<> struct hash<MemoryRegion> {
        size_t operator()(const MemoryRegion& region) const {
            size_t result = hash<void*>()(region.BaseAddress);
            result ^= hash<size_t>()(region.RegionSize) + 0x9e3779b9 + (result << 6) + (result >> 2);
            result ^= hash<DWORD>()(region.allocation_type) + 0x9e3779b9 + (result << 6) + (result >> 2);
            result ^= hash<DWORD>()(region.state) + 0x9e3779b9 + (result << 6) + (result >> 2);
            result ^= hash<DWORD>()(region.protect) + 0x9e3779b9 + (result << 6) + (result >> 2);
            result ^= hash<DWORD>()(region.allocation_protect) + 0x9e3779b9 + (result << 6) + (result >> 2);
            return result;
        }
    };
}

// Convert a MEMORY_BASIC_INFORMATION struct to a MemoryRegion struct
MemoryRegion to_memory_region(const MEMORY_BASIC_INFORMATION& memory_info) {
    MemoryRegion region;
    region.BaseAddress = memory_info.BaseAddress;
    region.RegionSize = memory_info.RegionSize;
    region.allocation_type= memory_info.Type;
    region.state = memory_info.State;
    region.protect = memory_info.Protect;
    region.allocation_protect = memory_info.AllocationProtect;
    return region;
}

// Check if the given API function name is suspicious
bool is_suspicious_api(const char* api_function_name) {
    for (size_t i = 0; i < num_suspicious_api_functions; i++) {
        if (strcmp(api_function_name, suspicious_api_functions[i]) == 0) {
            return true;
        }
    }
    return false;
}

// Check if the given memory region is suspicious
bool is_suspicious_region(const MemoryRegion& memory_region) {
    // Check if the memory region is RWX or RX and doesn't map to a file on disk
if (((memory_region.protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE ||
(memory_region.protect & PAGE_EXECUTE_READ) == PAGE_EXECUTE_READ ||
(memory_region.protect & PAGE_READWRITE) == PAGE_READWRITE ||
(memory_region.protect & PAGE_WRITECOPY) == PAGE_WRITECOPY) &&
(memory_region.allocation_protect & PAGE_NOCACHE) != PAGE_NOCACHE &&
(memory_region.allocation_protect & PAGE_GUARD) != PAGE_GUARD &&
(memory_region.allocation_protect & PAGE_NOACCESS) != PAGE_NOACCESS) {
WCHAR module_file_name[MAX_PATH];
if (GetMappedFileNameW(GetCurrentProcess(), memory_region.BaseAddress, module_file_name, MAX_PATH) == 0) {
DWORD error = GetLastError();
if (error == ERROR_INSUFFICIENT_BUFFER) {
wcout << L"GetMappedFileNameW: Buffer too small" << endl;
} else if (error == ERROR_INVALID_PARAMETER) {
wcout << L"GetMappedFileNameW: Invalid parameter" << endl;
} else {
wcout << L"GetMappedFileNameW: Unknown error: " << error << endl;
}
return true;
}
}
return false;
}

// Get the list of memory regions for the given process
set<MemoryRegion> get_memory_regions(HANDLE process_handle) {
set<MemoryRegion> regions;
MEMORY_BASIC_INFORMATION memory_info;
memset(&memory_info, 0, sizeof(memory_info));
void* current_address = 0;
while (VirtualQueryEx(process_handle, current_address, &memory_info, sizeof(memory_info))) {
regions.insert(to_memory_region(memory_info));
current_address = (char*)memory_info.BaseAddress + memory_info.RegionSize;
}
return regions;
}

// Get the name of the given module
wstring get_module_name(HANDLE process_handle, HMODULE module_handle) {
wstring module_name;
wchar_t module_file_name[MAX_PATH];
if (GetModuleFileNameExW(process_handle, module_handle, module_file_name, MAX_PATH) > 0) {
module_name = module_file_name;
}
return module_name;
}

// Get the list of module names for the given process
unordered_set<wstring> get_module_names(HANDLE process_handle) {
unordered_set<wstring> module_names;
HMODULE module_handles[1024];
DWORD needed;
if (EnumProcessModules(process_handle, module_handles, sizeof(module_handles), &needed)) {
for (size_t i = 0; i < (needed / sizeof(HMODULE)); i++) {
wstring module_name = get_module_name(process_handle, module_handles[i]);
if (!module_name.empty()) {
module_names.insert(module_name);
}
}
}
return module_names;
}

// Check if the given process is suspicious
bool is_suspicious_process(HANDLE process_handle) {
// Check if the process is suspended
if (SuspendThread(process_handle) == (DWORD)-1) {
return false;
}
// Check if the process has any suspicious memory regions
set<MemoryRegion> memory_regions = get_memory_regions(process_handle);
bool has_suspicious_memory_region = false;
for (const MemoryRegion& memory_region : memory_regions) {
if (is_suspicious_region(memory_region)) {
has_suspicious_memory_region = true;
break;
}
}
// Check if the process is calling any suspicious APIs
bool has_suspicious_API_call = false;
HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
if (snapshot != INVALID_HANDLE_VALUE) {
THREADENTRY32 thread_entry;
thread_entry.dwSize = sizeof(thread_entry);
if (Thread32First(snapshot, &thread_entry)) {
do {
if (thread_entry.th32OwnerProcessID == GetProcessId(process_handle)) {
HANDLE thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_entry.th32ThreadID);
if (thread_handle != NULL) {
CONTEXT context = { 0 };
context.ContextFlags = CONTEXT_CONTROL;
if (GetThreadContext(thread_handle, &context)) {
STACKFRAME64 stack_frame = { 0 };
stack_frame.AddrPC.Mode = AddrModeFlat;
stack_frame.AddrPC.Offset = context.Eip;
stack_frame.AddrStack.Mode = AddrModeFlat;
stack_frame.AddrStack.Offset = context.Esp;
stack_frame.AddrFrame.Mode = AddrModeFlat;
stack_frame.AddrFrame.Offset = context.Ebp;
while (StackWalk64(IMAGE_FILE_MACHINE_I386, GetCurrentProcess(), thread_handle, &stack_frame, &context, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
DWORD64 instruction_address = stack_frame.AddrPC.Offset;
char symbol_buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
PSYMBOL_INFO symbol = (PSYMBOL_INFO*)symbol_buffer;
symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
symbol->MaxNameLen = MAX_SYM_NAME;
DWORD64 symbol_offset = 0;
if (SymFromAddr(GetCurrentProcess(), instruction_address, &symbol_offset, symbol)) {
if (is_suspicious_api(symbol->Name)) {
has_suspicious_API_call = true;
break;
}
}
}
}
CloseHandle(thread_handle);
}
}
} while (Thread32Next(snapshot, &thread_entry) && !has_suspicious_API_call);
}
CloseHandle(snapshot);
}
ResumeThread(process_handle);
return has_suspicious_memory_region || has_suspicious_API_call;
}

// Dump the memory of the given process to the specified file
void dump_process_memory(HANDLE process_handle, const wstring& dump_file_path) {
ofstream dump_file(dump_file_path, ios::binary);
if (dump_file.is_open()) {
set<MemoryRegion> memory_regions = get_memory_regions(process_handle);
for (const MemoryRegion& memory_region : memory_regions) {
if ((memory_region.protect & PAGE_GUARD) == PAGE_GUARD ||
(memory_region.protect & PAGE_NOACCESS) == PAGE_NOACCESS) {
continue;
}
char* buffer = new char[memory_region.RegionSize];
SIZE_T bytes_read;
if (ReadProcessMemory(process_handle, memory_region.BaseAddress, buffer, memory_region.RegionSize, &bytes_read)) {
dump_file.write(buffer, bytes_read);
}
delete[] buffer;
}
dump_file.close();
}
}

int main() {
// Get the list of running processes
vector<DWORD> process_ids;
HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
if (snapshot != INVALID_HANDLE_VALUE) {
PROCESSENTRY32 process_entry;
process_entry.dwSize = sizeof(process_entry);
if (Process32First(snapshot, &process_entry)) {
do {
if (process_entry.th32ProcessID != GetCurrentProcessId()) {
process_ids.push_back(process_entry.th32ProcessID);
}
} while (Process32Next(snapshot, &process_entry));
}
CloseHandle(snapshot);
}

// Initialize the symbol handler
SymInitialize(GetCurrentProcess(), NULL, TRUE);

// Dump memory for suspicious processes
mutex file_output_mutex;
for (DWORD process_id : process_ids) {
HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
if (is_suspicious_process(process_handle)) {
wcout << L"Found suspicious process: " << process_id << endl;
wstring dump_file_path = L"process_" + to_wstring(process_id) + L".dmp";
dump_process_memory(process_handle, dump_file_path);
wcout << L"Dumped memory for process " << process_id << L" to file: " << dump_file_path << endl;
    // Check for suspicious API calls in the process
    CONTEXT context = { 0 };
    context.ContextFlags = CONTEXT_CONTROL;
    GetThreadContext(GetCurrentThread(), &context);
    STACKFRAME64 stack_frame = { 0 };
    stack_frame.AddrPC.Mode = AddrModeFlat;
    stack_frame.AddrPC.Offset = context.Eip;
    stack_frame.AddrStack.Mode = AddrModeFlat;
    stack_frame.AddrStack.Offset = context.Esp;
    stack_frame.AddrFrame.Mode = AddrModeFlat;
    stack_frame.AddrFrame.Offset = context.Ebp;
    HANDLE thread_handle = GetCurrentThread();
    bool api_call_detected = false;
    while (StackWalk64(IMAGE_FILE_MACHINE_I386, GetCurrentProcess(), thread_handle, &stack_frame, &context, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
        DWORD64 instruction_address = stack_frame.AddrPC.Offset;
        char symbol_buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
        PSYMBOL_INFO symbol = (PSYMBOL_INFO*)symbol_buffer;
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol->MaxNameLen = MAX_SYM_NAME;
        DWORD64 symbol_offset = 0;
        if (SymFromAddr(GetCurrentProcess(), instruction_address, &symbol_offset, symbol)) {
            if (is_suspicious_api(symbol->Name)) {
                api_call_detected = true;
                wcout << L"Suspicious API call detected in process " << process_id << L": " << symbol->Name << endl;
                wstring api_dump_file_path = L"process_" + to_wstring(process_id) + L"_api_call.dmp";
                dump_process_memory(process_handle, api_dump_file_path);
                wcout << L"Dumped memory for process " << process_id << L" with suspicious API call to file: " << api_dump_file_path << endl;
                break;
            }
        }
    }
    if (!api_call_detected) {
        wcout << L"No suspicious API calls detected in process " << process_id << endl;
    }
}
CloseHandle(process_handle);
}

// Clean up the symbol handler
SymCleanup(GetCurrentProcess());

return 0;
}
