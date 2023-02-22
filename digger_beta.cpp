#include <iostream>
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#include <thread>
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
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Dbghelp.lib")
#define _WIN32_WINNT 0x0501

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
void dump_process(DWORD process_id, set < DWORD >& dumped_processes);
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

const size_t num_suspicious_api_functions = sizeof(suspicious_api_functions) / sizeof(char*);


// Scan for suspicious processes
void scan_processes(bool dump_if_debug_registers_set) {
    set < DWORD > dumped_processes;
    CONTEXT context;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(snapshot, &entry) == TRUE) {
        do {
            // Check if the process has already been dumped or is the current process
            if (dumped_processes.count(entry.th32ProcessID) > 0 || entry.th32ProcessID == GetCurrentProcessId()) {

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
                        // Check if the thread is the current thread
                        if (thread_entry.th32ThreadID == GetThreadId(GetCurrentThread())) {
                            continue;
                        }
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
                    if (GetThreadContext(thread, &context)) {
                        if (context.Dr0 || context.Dr1 || context.Dr2 || context.Dr3) {
                            // Dump the process memory if any debug registers are set
                            dump_process(entry.th32ProcessID, dumped_processes);
                            break;
                        }
                    }
                }
                // Close the process handle
                CloseHandle(process);
            }
        } while (Process32Next(snapshot, &entry));
        CloseHandle(snapshot);
    }
}

// Dump the memory of a process to a file
void dump_process(DWORD process_id, set < DWORD >& dumped_processes) {
    char dump_file_name[MAX_PATH];
    snprintf(dump_file_name, MAX_PATH, "process_%u.dmp", process_id);
    ofstream dump_file(dump_file_name, ios::out | ios::binary);
    if (dump_file.is_open()) {
        HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
        if (process != NULL) {
            // Iterate over the process memory regions and write them to the dump file
            MEMORY_BASIC_INFORMATION memory_info;
            void* address = 0;
            HANDLE process = OpenProcess(PROCESS_VM_READ, FALSE, process_id);
            if (process != NULL) {
                while (VirtualQueryEx(process, address, &memory_info, sizeof(memory_info)) == sizeof(memory_info)) {
                    // Check if the memory region is suspicious and write it to the dump file
                    MemoryRegion region = to_memory_region(memory_info);
                    if (is_memory_suspicious(region, process_id)) {
                        BYTE* buffer = new BYTE[region.RegionSize];
                        SIZE_T bytes_read;
                        if (ReadProcessMemory(process, region.BaseAddress, buffer, region.RegionSize, &bytes_read) == TRUE) {
                            dump_file.write(reinterpret_cast <
                                const char*> (buffer), bytes_read);
                        }
                        delete[] buffer;
                    }
                    address = static_cast <char*> (address) + memory_info.RegionSize;
                }
                CloseHandle(process);
            }
            dump_file.close();
            dumped_processes.insert(process_id);
        }
    }

    // Convert a MEMORY_BASIC_INFORMATION struct to a MemoryRegion struct
    MemoryRegion to_memory_region(const MEMORY_BASIC_INFORMATION & memory_info) {
        MemoryRegion region;
        region.BaseAddress = memory_info.BaseAddress;
        region.RegionSize = memory_info.RegionSize;
        region.allocation_type = memory_info.Type;
        region.state = memory_info.State;
        region.protect = memory_info.Protect;
        region.allocation_protect = memory_info.AllocationProtect;
        return region;
    }
    typedef struct _THREAD_BASIC_INFORMATION {
        NTSTATUS                ExitStatus;
        PVOID                   TebBaseAddress;
        CLIENT_ID               ClientId;
        KAFFINITY               AffinityMask;
        KPRIORITY               Priority;
        KPRIORITY               BasePriority;
    } THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

    // Check if a memory region is suspicious
    bool is_memory_suspicious(const MemoryRegion & region, DWORD process_id) {
        // Check if the memory region is writable and not copy-on-write
        if ((region.allocation_protect & PAGE_READWRITE) == PAGE_READWRITE && (region.protect & PAGE_WRITECOPY) != PAGE_WRITECOPY) {
            // Check if the memory region is executable
            if ((region.protect & PAGE_EXECUTE_READ) == PAGE_EXECUTE_READ || (region.protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE || (region.protect & PAGE_EXECUTE) == PAGE_EXECUTE) {
                // Check if the memory region is within the image or stack of the process
                MODULEINFO module_info;
                if (GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), &module_info, sizeof(module_info))) {
                    if (region.BaseAddress >= module_info.lpBaseOfDll && region.BaseAddress < static_cast <char*> (module_info.lpBaseOfDll) + module_info.SizeOfImage) {
                        return false;
                    }
                }
                // Check if the memory region is within the thread stack of the process
                THREAD_BASIC_INFORMATION thread_basic_information;
                HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, GetCurrentThreadId());
                if (thread != NULL) {
                    THREAD_BASIC_INFORMATION thread_basic_information;
                    if (NtQueryInformationThread(thread, ThreadBasicInformation, &thread_basic_information, sizeof(thread_basic_information), NULL) == STATUS_SUCCESS) {

                        if (region.BaseAddress >= thread_basic_information.TebBaseAddress && region.BaseAddress < static_cast <char*> (thread_basic_information.TebBaseAddress) + 0x1000) {
                            return false;
                        }
                    }
                    return true;
                }
            }
            return false;
        }





        // Check if a function is suspicious based on its name
        bool is_suspicious_api_function(const char* function_name) {
            for (int i = 0; i < num_suspicious_api_functions; i++) {
                if (strcmp(function_name, suspicious_api_functions[i]) == 0) {
                    return true;
                }
            }
            return false;
        }

        // Check if the context of a thread contains a suspicious API call
        bool is_suspicious_api_call(const CONTEXT & context) {
            DWORD64 base_address = SymLoadModuleEx(GetCurrentProcess(), NULL, NULL, NULL, 0, 0, NULL, 0);
            if (base_address == 0) {
                return false;
            }
            if (SymLoadModuleEx(GetCurrentProcess(), NULL, NULL, base_address, 0, 0, NULL, 0) == 0) {
                return false;
            }

            DWORD64 displacement;
            CHAR buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
            PSYMBOL_INFO symbol = (PSYMBOL_INFO)buffer;
            symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
            symbol->MaxNameLen = MAX_SYM_NAME;
            // Loop over the function call stack and check for suspicious API calls
            STACKFRAME64 stack_frame;
            memset(&stack_frame, 0, sizeof(stack_frame));
            DWORD machine_type = IMAGE_FILE_MACHINE_I386;
            stack_frame.AddrPC.Mode = AddrModeFlat;
            stack_frame.AddrFrame.Mode = AddrModeFlat;
            stack_frame.AddrStack.Mode = AddrModeFlat;
#ifdef _M_IX86
            stack_frame.AddrPC.Offset = context.Eip;
            stack_frame.AddrFrame.Offset = context.Ebp;
            stack_frame.AddrStack.Offset = context.Esp;
            machine_type = IMAGE_FILE_MACHINE_I386;
#elif _M_X64
            stack_frame.AddrPC.Offset = context.Rip;
            stack_frame.AddrFrame.Offset = context.Rbp;
            stack_frame.AddrStack.Offset = context.Rsp;
            machine_type = IMAGE_FILE_MACHINE_AMD64;
#elif _M_ARM64
            stack_frame.AddrPC.Offset = context.Pc;
            stack_frame.AddrFrame.Offset = context.Fp;
            stack_frame.AddrStack.Offset = context.Sp;
            machine_type = IMAGE_FILE_MACHINE_ARM64;
#else
#error "Unsupported architecture"
#endif

            while (StackWalk64(machine_type, process, thread, &stack_frame, (PCONTEXT)&context, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {

                if (stack_frame.AddrFrame.Offset == 0) {
                    break;
                }
                // Get the name of the function at the current stack frame
                if (SymFromAddr(process, stack_frame.AddrPC.Offset, &displacement, symbol)) {
                    if (is_suspicious_api_function(symbol->Name)) {
                        return true;
                    }
                }
            }
            SymUnloadModule64(GetCurrentProcess(), base_address);
            return false;
        }

        int main() {
            // Initialize the symbol engine
            SymInitialize(GetCurrentProcess(), NULL, TRUE);
            // Scan for suspicious processes and dump their memory if necessary
            scan_processes(true);
            // Clean up the symbol engine
            SymCleanup(GetCurrentProcess());
            return 0;
        }
