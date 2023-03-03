#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <iostream>
#include <string>
#include <set>
#include <string>
#include <fstream>
#include <cstring>
#include <Dbghelp.h>
#include <tuple>
#include <cstdint>
#include <winternl.h>
#pragma comment(lib, "Dbghelp.lib")
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

int (*hook)();
// Suspended process threshold in milliseconds
const DWORD SUSPENDED_PROCESS_THRESHOLD = 5000;

// RWX memory protection flags
const DWORD RWX_FLAGS = PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_EXECUTE | PAGE_EXECUTE_READ;

// RX memory protection flags
const DWORD RX_FLAGS = PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

// WCX memory protection flags
const DWORD WCX_FLAGS = PAGE_WRITECOPY | PAGE_READWRITE | PAGE_WRITECOMBINE;

// Suspicious API calls to monitor
const char* SUSPICIOUS_APIS[] = {
    "CreateRemoteThread",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    "NtCreateThreadEx",
    "NtQueueApcThread",
    "NtProtectVirtualMemory",
    "NtMapViewOfSection",
    "NtUnmapViewOfSection",
    "NtCreateSection",
    "NtCreateProcess",
    "NtResumeThread",
    "NtSuspendThread"
};
const int NUM_SUSPICIOUS_APIS = sizeof(SUSPICIOUS_APIS) / sizeof(const char*);

// Set to store PIDs with suspicious indicators
std::set<DWORD> suspicious_pids;

// Set to store already dumped PIDs
std::set<DWORD> dumped_pids;

// Helper function to dump process memory
void dump_process_memory(HANDLE process,
    const std::string& dump_file_path) {
    // Open file for writing
    std::ofstream dump_file(dump_file_path, std::ios::binary);
    // Get process memory information
    SYSTEM_INFO system_info;
    GetSystemInfo(&system_info);
    MEMORY_BASIC_INFORMATION memory_info;

    // Dump memory for each region of the process
    for (LPVOID address = system_info.lpMinimumApplicationAddress; address < system_info.lpMaximumApplicationAddress; address = memory_info.BaseAddress + memory_info.RegionSize) {
        // Get memory information for the region
        VirtualQueryEx(process, address, &memory_info, sizeof(memory_info));

        // Skip regions with no access
        if (memory_info.Protect == PAGE_NOACCESS) {
            continue;
        }

        // Skip regions that have already been dumped
        if (dumped_pids.count(reinterpret_cast<uintptr_t>(memory_info.BaseAddress)) > 0) {
            continue;
        }

        // Calculate chunk size for dumping
        SIZE_T chunk_size = memory_info.RegionSize;
        if (memory_info.Protect == PAGE_GUARD) {
            chunk_size = system_info.dwPageSize;
        }

        // Allocate buffer for dumping memory
        LPVOID buffer = VirtualAlloc(nullptr, chunk_size, MEM_COMMIT, PAGE_READWRITE);
        if (!buffer) {
            continue;
        }

        // Dump memory to file
        SIZE_T bytes_written;
        uintptr_t total_bytes_written = reinterpret_cast<uintptr_t>(memory_info.BaseAddress);
        while (total_bytes_written < reinterpret_cast<uintptr_t>(memory_info.BaseAddress) + memory_info.RegionSize) {
            if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(total_bytes_written), reinterpret_cast<LPVOID>(reinterpret_cast<uintptr_t>(buffer)), chunk_size, &bytes_written)) {
break;
}
dump_file.write(reinterpret_cast<char*>(buffer), bytes_written);
total_bytes_written += bytes_written;
}
    // Free memory buffer
    VirtualFree(buffer, 0, MEM_RELEASE);

    // Add dumped region to set of dumped regions
    dumped_pids.insert(reinterpret_cast<uintptr_t>(memory_info.BaseAddress));
}

// Close dump file
dump_file.close();
}

// Helper function to check if a process is suspended
bool is_process_suspended(HANDLE process) {
FILETIME creation_time;
FILETIME exit_time;
FILETIME kernel_time;
FILETIME user_time;
GetProcessTimes(process, &creation_time, &exit_time, &kernel_time, &user_time);
ULARGE_INTEGER last_time, current_time;
last_time.LowPart = user_time.dwLowDateTime;
last_time.HighPart = user_time.dwHighDateTime;
Sleep(SUSPENDED_PROCESS_THRESHOLD);
GetProcessTimes(process, &creation_time, &exit_time, &kernel_time, &user_time);
current_time.LowPart = user_time.dwLowDateTime;
current_time.HighPart = user_time.dwHighDateTime;
return last_time.QuadPart == current_time.QuadPart;
}

// Hook function to detect suspicious API calls
LONG WINAPI hook_function(EXCEPTION_POINTERS* exception_pointers) {
    // Get exception record and context
    EXCEPTION_RECORD* exception_record = exception_pointers->ExceptionRecord;
    CONTEXT* context = exception_pointers->ContextRecord;
    // Get module and function name for the exception address
    HMODULE module;
    DWORD64 offset;
    SymFromAddr(GetCurrentProcess(), reinterpret_cast<DWORD64>(exception_record->ExceptionAddress), &offset, nullptr);
    IMAGEHLP_MODULE64 module_info = { sizeof(IMAGEHLP_MODULE64) };
    if (SymGetModuleInfo64(GetCurrentProcess(), reinterpret_cast<DWORD64>(exception_record->ExceptionAddress), &module_info)) {
        module = reinterpret_cast<HMODULE>(module_info.BaseOfImage);
    }
    else {
        module = nullptr;
    }
    IMAGEHLP_SYMBOL64 symbol = { 0 };
    symbol.SizeOfStruct = sizeof(symbol);
    symbol.MaxNameLength = MAX_PATH;
    // Get function name for the exception address
    DWORD64 displacement;
    SymGetSymFromAddr(GetCurrentProcess(), reinterpret_cast<DWORD64>(exception_record->ExceptionAddress), &displacement, &symbol);
    CHAR* function_name = symbol.Name;

    // Check if the API call is suspicious
    bool is_suspicious = false;
    for (int i = 0; i < NUM_SUSPICIOUS_APIS; i++) {
        if (std::strcmp(SUSPICIOUS_APIS[i], function_name) == 0) {
            is_suspicious = true;
            break;
        }
    }

    // If the API call is suspicious, add the process to the set of suspicious PIDs
    if (is_suspicious) {
        suspicious_pids.insert(GetCurrentProcessId());
        std::cout << "Detected suspicious API call in process " << GetCurrentProcessId() << "\n";
    }

    // Resume the process
    context->EFlags |= 0x100; // Set the single-step flag
    context->EFlags &= ~0x400; // Clear the trap flag
    return EXCEPTION_CONTINUE_EXECUTION;
}

int main() {
// Initialize symbol handler
SymInitialize(GetCurrentProcess(), nullptr, TRUE);
// Get snapshot of running processes
HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

// Iterate through each process in the snapshot
PROCESSENTRY32 process_entry;
process_entry.dwSize = sizeof(PROCESSENTRY32);
if (Process32First(snapshot, &process_entry)) {
  std::cout << "Got snapshot of running processes\n";
  do {
// Open process with PROCESS_ALL_ACCESS
HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_entry.th32ProcessID);
if (process == nullptr) {
std::cout << "Could not open process " << process_entry.th32ProcessID << "\n";
continue;
}
    // Check if the process is suspended
    if (is_process_suspended(process)) {
        // Dump process memory
        std::string dump_file_path = "process_" + std::to_string(process_entry.th32ProcessID) + ".dmp";
        dump_process_memory(process, dump_file_path);
        std::cout << "Dumped memory of process " << process_entry.th32ProcessID << "\n";
        // Resume the process
        ResumeThread(process);

        // Set exception hook
        hook = reinterpret_cast<int (*)()>(SetUnhandledExceptionFilter(hook_function));

        // Wait for the process to terminate
        WaitForSingleObject(process, INFINITE);

        // Remove exception hook
        SetUnhandledExceptionFilter(reinterpret_cast<LPTOP_LEVEL_EXCEPTION_FILTER>(hook));

        // Close process handle
        CloseHandle(process);

        // Add process to set of dumped PIDs
        dumped_pids.insert(process_entry.th32ProcessID);
    }
    else {
        // Close process handle
        CloseHandle(process);
    }
} while (Process32Next(snapshot, &process_entry));
}

// Print suspicious PIDs
if (!suspicious_pids.empty()) {
std::cout << "Suspicious PIDs:\n";
for (auto pid : suspicious_pids) {
std::cout << "Suspicious PIDs:\n";
std::cout << pid << "\n";
}
}
else {
std::cout << "No suspicious activity detected.\n";
}

// Close snapshot handle
CloseHandle(snapshot);

return 0;
}
