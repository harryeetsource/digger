#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <iostream>
#include <string>
#include <set>
#include <fstream>
#include <Dbghelp.h>

#pragma comment(lib, "Dbghelp.lib")

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
// Helper function to dump process memory
void dump_process_memory(HANDLE process, const std::string& dump_file_path) {
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
            if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(total_bytes_written), buffer, chunk_size, &bytes_written)) {
                break;
            }
            dump_file.write(reinterpret_cast<const char*>(buffer), bytes_written);
            total_bytes_written += bytes_written;
        }

        // Free buffer
        VirtualFree(buffer, 0, MEM_RELEASE);

        // Add dumped region to set
        dumped_pids.insert(reinterpret_cast<uintptr_t>(memory_info.BaseAddress));
    }

    // Close file
    dump_file.close();
}


// Suspicious API hook function
DWORD WINAPI suspicious_api_hook(LPVOID lpParam) {
// Get API parameters
const char* api_name = reinterpret_cast<const char*>(lpParam);
const HANDLE process = GetCurrentProcess();
// Dump process memory
char dump_file_name[MAX_PATH];
GetTempPathA(MAX_PATH, dump_file_name);
strcat_s(dump_file_name, MAX_PATH, api_name);
strcat_s(dump_file_name, MAX_PATH, "_dump.bin");
dump_process_memory(process, dump_file_name);

// Add PID to set of suspicious PIDs
DWORD pid = GetProcessId(process);
suspicious_pids.insert(pid);

// Return control to original API function
return 0;
}

// Hook API function with suspicious_api_hook
void hook_api(const char* api_name) {
HMODULE module = GetModuleHandle(nullptr);
FARPROC original_func = GetProcAddress(module, api_name);
// Create trampoline function
BYTE trampoline_bytes[] = {
    0x48, 0xb8 // mov rax, <suspicious_api_hook>
};
*reinterpret_cast<void**>(&trampoline_bytes[2]) = reinterpret_cast<void*>(&suspicious_api_hook);
trampoline_bytes[10] = 0xff; // jmp rax

// Allocate executable memory for trampoline
LPVOID trampoline_memory = VirtualAlloc(nullptr, sizeof(trampoline_bytes), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
memcpy(trampoline_memory, trampoline_bytes, sizeof(trampoline_bytes));

// Patch original function with trampoline
DWORD old_protection;
VirtualProtect(reinterpret_cast<LPVOID>(original_func), sizeof(trampoline_bytes), PAGE_EXECUTE_READWRITE, &old_protection);
memcpy(reinterpret_cast<void*>(original_func), trampoline_bytes, sizeof(trampoline_bytes));
VirtualProtect(reinterpret_cast<LPVOID>(original_func), sizeof(trampoline_bytes), PAGE_EXECUTE_READWRITE, &old_protection);

}

// Monitor process for suspicious activity
void monitor_process(DWORD pid) {
// Open process handle
HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
if (!process) {
return;
}
// Check if process is already in set of suspicious PIDs
if (suspicious_pids.count(pid) > 0) {
    return;
}

// Check if process is already in set of dumped PIDs
if (dumped_pids.count(pid) > 0) {
    return;
}

// Check if process is suspended
DWORD process_suspend_count = SuspendThread(process);
if (process_suspend_count == (DWORD)-1) {
    CloseHandle(process);
    return;
}
if (process_suspend_count > 0) {
    Sleep(SUSPENDED_PROCESS_THRESHOLD);
    DWORD process_resume_count = ResumeThread(process);
    CloseHandle(process);
    return;
}

// Enumerate process modules
HMODULE modules[1024];
DWORD bytes_needed;
if (EnumProcessModules(process, modules, sizeof(modules), &bytes_needed)) {
    // Get number of modules
    DWORD num_modules = bytes_needed / sizeof(HMODULE);

    // Check each module for RWX or RX memory
    for (DWORD i = 0; i < num_modules; i++) {
        MODULEINFO module_info;
        if (GetModuleInformation(process, modules[i], &module_info, sizeof(module_info))) {
// Check if module has RWX or RX memory protection
uintptr_t module_protection = reinterpret_cast<uintptr_t>(module_info.lpBaseOfDll);
if ((module_protection & RWX_FLAGS) || (module_protection & RX_FLAGS)) {
// Dump process memory and add PID to set of suspicious PIDs
char dump_file_name[MAX_PATH];
GetTempPathA(MAX_PATH, dump_file_name);
strcat_s(dump_file_name, MAX_PATH, "module_dump.bin");
dump_process_memory(process, dump_file_name);
DWORD pid = GetProcessId(process);
suspicious_pids.insert(pid);
break;
}
}
}
// Hook suspicious APIs
for (int i = 0; i < NUM_SUSPICIOUS_APIS; i++) {
    hook_api(SUSPICIOUS_APIS[i]);
}

// Resume process
ResumeThread(process);

// Close process handle
CloseHandle(process);
}
}

int main() {
// Get list of running processes
DWORD processes[1024];
DWORD bytes_needed;
if (EnumProcesses(processes, sizeof(processes), &bytes_needed)) {
// Get number of processes
DWORD num_processes = bytes_needed / sizeof(DWORD);
// Monitor each process
for (DWORD i = 0; i < num_processes; i++) {
    monitor_process(processes[i]);
}
}

// Wait for user input before exiting
std::cout << "Press enter to exit..." << std::endl;
std::cin.get();

return 0;
}