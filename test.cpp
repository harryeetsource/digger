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
const char * SUSPICIOUS_APIS[] = {
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
const int NUM_SUSPICIOUS_APIS = sizeof(SUSPICIOUS_APIS) / sizeof(const char * );

// Set to store PIDs with suspicious indicators
std::set < DWORD > suspicious_pids;

// Set to store already dumped PIDs
std::set < DWORD > dumped_pids;

// Helper function to dump process memory
void dump_process_memory(HANDLE process,
  const std::string & dump_file_path) {
  // Open file for writing
  std::ofstream dump_file(dump_file_path, std::ios::binary);
  // Get process memory information
  SYSTEM_INFO system_info;
  GetSystemInfo( & system_info);
  MEMORY_BASIC_INFORMATION memory_info;

  // Dump memory for each region of the process
  for (LPVOID address = system_info.lpMinimumApplicationAddress; address < system_info.lpMaximumApplicationAddress; address = memory_info.BaseAddress + memory_info.RegionSize) {
    // Get memory information for the region
    VirtualQueryEx(process, address, & memory_info, sizeof(memory_info));

    // Skip regions with no access
    if (memory_info.Protect == PAGE_NOACCESS) {
      continue;
    }

    // Skip regions that have already been dumped
    if (dumped_pids.count(reinterpret_cast < uintptr_t > (memory_info.BaseAddress)) > 0) {
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
    uintptr_t total_bytes_written = reinterpret_cast < uintptr_t > (memory_info.BaseAddress);
    while (total_bytes_written < reinterpret_cast < uintptr_t > (memory_info.BaseAddress) + memory_info.RegionSize) {
      if (!ReadProcessMemory(process, reinterpret_cast < LPCVOID > (total_bytes_written), buffer, chunk_size, & bytes_written)) {
        break;
      }
      dump_file.write(reinterpret_cast <
        const char * > (buffer), bytes_written);
      total_bytes_written += bytes_written;
    }
    // Close file
    dump_file.close();
  }
}

// Helper function to check if a process is suspended
bool is_process_suspended(DWORD pid) {
  HANDLE process = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
  if (!process) {
    return false;
  }
  bool result = (WaitForSingleObject(process, SUSPENDED_PROCESS_THRESHOLD) == WAIT_TIMEOUT);
  CloseHandle(process);
  return result;
}

// Helper function to check if a process is running from a temporary directory
bool is_process_running_from_temp_dir(DWORD pid) {
  HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
  if (!process) {
    return false;
  }
  // Get the process image file name
  char image_file_name[MAX_PATH];
  if (GetProcessImageFileNameA(process, image_file_name, MAX_PATH) == 0) {
    CloseHandle(process);
    return false;
  }
  // Get the path of the parent directory
  std::string parent_dir = image_file_name;
  parent_dir = parent_dir.substr(0, parent_dir.find_last_of("\/"));
  // Check if the parent directory is a temp directory
  char temp_dir[MAX_PATH];
  GetTempPathA(MAX_PATH, temp_dir);
  bool result = (parent_dir.find(temp_dir) != std::string::npos);

  CloseHandle(process);
  return result;
}

// Helper function to check if a memory region is suspicious
bool is_memory_region_suspicious(HANDLE process,
  const MEMORY_BASIC_INFORMATION & memory_info) {
  // Check for suspicious memory protection flags
  DWORD protection = memory_info.Protect;
  if ((protection & RWX_FLAGS) || (protection & RX_FLAGS) || (protection & WCX_FLAGS)) {
    // Check if memory region is backed by a file
    MEMORY_BASIC_INFORMATION memory_info_file;
    VirtualQueryEx(process, memory_info.BaseAddress, & memory_info_file, sizeof(memory_info_file));
    if (memory_info_file.Type == MEM_MAPPED) {
      return false;
    }
    // Check if memory region has been dumped before
    if (dumped_pids.count(reinterpret_cast < uintptr_t > (memory_info.BaseAddress)) > 0) {
      return false;
    }
    return true;
  }
  return false;
}
std::tuple<HMODULE, FARPROC> split_dll_name_and_function_name(const char* name) {
    auto colon_pos = std::strchr(name, ':');
    if (colon_pos == nullptr) {
        return { nullptr, nullptr };
    }
    std::string dll_name(name, colon_pos);




    std::string function_name(colon_pos + 1);
    auto module = GetModuleHandleA(dll_name.c_str());
    if (module == nullptr) {
        module = LoadLibraryA(dll_name.c_str());
        if (module == nullptr) {
            return { nullptr, nullptr };
        }
    }
    auto function = GetProcAddress(module, function_name.c_str());
    return { module, function };
}
// Helper function to check if a process is injecting code
bool is_process_injecting_code(HANDLE process) {
    // Array of suspicious API names
    const char* SUSPICIOUS_APIS[] = {
        "kernel32.dll:LoadLibraryA",
        "kernel32.dll:VirtualAllocEx",
        "kernel32.dll:WriteProcessMemory",
        "kernel32.dll:CreateRemoteThread",
        "ntdll.dll:NtCreateThreadEx",
        "kernel32.dll:RtlCreateUserThread",
        "kernel32.dll:CreateThread",
        "ntdll.dll:NtWriteVirtualMemory",
        "ntdll.dll:NtAllocateVirtualMemory",
        "ntdll.dll:NtCreateSection",
        "ntdll.dll:NtMapViewOfSection",
    };
    constexpr size_t SUSPICIOUS_APIS_COUNT = sizeof(SUSPICIOUS_APIS) / sizeof(SUSPICIOUS_APIS[0]);

    // Iterate through each suspicious API
    for (size_t i = 0; i < SUSPICIOUS_APIS_COUNT; i++) {
        HMODULE module;
        FARPROC function;
        std::tie(module, function) = split_dll_name_and_function_name(SUSPICIOUS_APIS[i]);

        if (function == nullptr) {
            continue;
        }

        // Get the address of the function in the process being scanned
        auto functionPtr = reinterpret_cast<long long int(*)()>(GetProcAddress(module, function));

        if (functionPtr == nullptr) {
            continue;
        }

        // Install the hook for each function with this name in the process being scanned
        for (size_t j = 0; functionPtr[j] != nullptr; j++) {
            union FunctionPointer {
                void* ptr;
                void(*fn)();
            };
            FunctionPointer original_function = { .ptr = functionPtr[j] };
            uint8_t trampoline_bytes[sizeof(FunctionPointer) + 5] = { 0 };
            trampoline_bytes[0] = 0xE9; // JMP rel32
            void* &trampoline_ptr = reinterpret_cast<void*&>(trampoline_bytes[1]);
            trampoline_ptr = original_function.ptr;
            void* &trampoline_offset_ptr = reinterpret_cast<void*&>(trampoline_bytes[5]);
            trampoline_offset_ptr = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(&hook) - reinterpret_cast<uintptr_t>(&trampoline_bytes[1]) - 4);

            DWORD old_protect;
            if (!VirtualProtect(original_function.ptr, sizeof(trampoline_bytes), PAGE_EXECUTE_READWRITE, &old_protect)) {
                return true;
            }

            uint8_t original_bytes[sizeof(trampoline_bytes)];
            memcpy(original_bytes, original_function.ptr, sizeof(trampoline_bytes));

            if (memcmp(original_bytes, trampoline_bytes, sizeof(trampoline_bytes)) == 0) {
                continue;
            }

            if (!WriteProcessMemory(process, original_function.ptr, trampoline_bytes, sizeof(trampoline_bytes), nullptr)) {
                return true;
            }

            if (!VirtualProtect(original_function.ptr, sizeof(trampoline_bytes), old_protect, &old_protect)) {
                return true;
            }

            uint8_t jmp_bytes[5] = { 0 };
            jmp_bytes[0] = 0xE9; // JMP rel32
            int32_t& jmp_ptr = *reinterpret_cast<int32_t*>(&jmp_bytes[1]);
            jmp_ptr = static_cast<int32_t>(reinterpret_cast<uintptr_t>(&hook) - reinterpret_cast<uintptr_t>(original_function.ptr) - 5);

                    if (!VirtualProtect(original_function.ptr, sizeof(jmp_bytes), PAGE_EXECUTE_READWRITE, &old_protect)) {
            return true;
        }

        uint8_t original_jmp_bytes[sizeof(jmp_bytes)];
        memcpy(original_jmp_bytes, original_function.ptr, sizeof(jmp_bytes));

        if (memcmp(original_jmp_bytes, jmp_bytes, sizeof(jmp_bytes)) == 0) {
            continue;
        }

        if (!WriteProcessMemory(process, original_function.ptr, jmp_bytes, sizeof(jmp_bytes), nullptr)) {
            return true;
        }

        if (!VirtualProtect(original_function.ptr, sizeof(jmp_bytes), old_protect, &old_protect)) {
            return true;
        }
    }
}

return false;
}



int main(int argc, char * argv[]) {
  // Get list of running processes
  DWORD pids[1024];
  DWORD needed;
  if (!EnumProcesses(pids, sizeof(pids), & needed)) {
    return 1;
  }
  int num_processes = needed / sizeof(DWORD);
  // Iterate over processes and check for suspicious indicators
  for (int i = 0; i < num_processes; i++) {
    DWORD pid = pids[i];
    if (pid != 0 && pid != 4) { // skip System Idle Process and System
      HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
      if (process) {
        // Check for suspicious indicators
        if (is_process_suspended(pid) || is_process_running_from_temp_dir(pid) || is_process_injecting_code(process)) {
          // Dump process memory
          char dump_file_path[MAX_PATH];
          sprintf_s(dump_file_path, MAX_PATH, "process_%u.dmp", pid);
          dump_process_memory(process, dump_file_path);
          dumped_pids.insert(reinterpret_cast < uintptr_t > (process));
        }
        CloseHandle(process);
      }
    }
  }
  return 0;
}
