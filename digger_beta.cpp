#include <iostream>

#include <Windows.h>

#include <Psapi.h>

#include <TlHelp32.h>

#include <cstring>

#include <cstdio>

#include <fstream>

#include <sstream>

using namespace std;

struct MemoryRegion {
  void * BaseAddress;
  size_t RegionSize;
  DWORD allocation_type;
  DWORD state;
  DWORD protect;
  DWORD allocation_protect;
};

MemoryRegion to_memory_region(const MEMORY_BASIC_INFORMATION & memory_info);
bool is_memory_suspicious(const MemoryRegion & region);
// Define the list of suspicious API functions
const char * suspicious_api_functions[] = {
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
const int num_suspicious_api_functions = sizeof(suspicious_api_functions) / sizeof(char * );
// Scan for suspicious processes
void scan_processes(bool dump_if_debug_registers_set) {
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  PROCESSENTRY32 entry;
  entry.dwSize = sizeof(PROCESSENTRY32);
  if (Process32First(snapshot, & entry) == TRUE) {
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

          if (dump_if_debug_registers_set) {
            CONTEXT context;
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(GetCurrentThread(), & context)) {
              if (context.Dr0 || context.Dr1 || context.Dr2 || context.Dr3) {
                HANDLE file = CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (file != INVALID_HANDLE_VALUE) {
                  SYSTEM_INFO system_info;
                  GetSystemInfo( & system_info);
                  DWORD_PTR address = (DWORD_PTR) system_info.lpMinimumApplicationAddress;
                  while (address < (DWORD_PTR) system_info.lpMaximumApplicationAddress) {
                    MEMORY_BASIC_INFORMATION memory_info;
                    if (VirtualQueryEx(process, (LPCVOID) address, & memory_info, sizeof(memory_info)) == sizeof(memory_info)) {
                      if (memory_info.State == MEM_COMMIT) {
                        MemoryRegion region = to_memory_region(memory_info);
                        if (!is_memory_suspicious(region)) {
                          char * buffer = new char[memory_info.RegionSize];
                          SIZE_T bytes_read;
                          if (ReadProcessMemory(process, memory_info.BaseAddress, buffer, memory_info.RegionSize, & bytes_read)) {
                            DWORD bytes_written;
                            WriteFile(file, buffer, bytes_read, & bytes_written, NULL);
                          }
                          delete[] buffer;
                        }
                      }
                      address += memory_info.RegionSize;
                    } else {
                      address += system_info.dwPageSize;
                    }
                  }
                  CloseHandle(file);
                }
              }
            }
          } else {
            HANDLE file = CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (file != INVALID_HANDLE_VALUE) {
              SYSTEM_INFO system_info;
              GetSystemInfo( & system_info);
              DWORD_PTR address = (DWORD_PTR) system_info.lpMinimumApplicationAddress;
              while (address < (DWORD_PTR) system_info.lpMaximumApplicationAddress) {
                MEMORY_BASIC_INFORMATION memory_info;
                if (VirtualQueryEx(process, (LPCVOID) address, & memory_info, sizeof(memory_info)) == sizeof(memory_info)) {
                  if (memory_info.State == MEM_COMMIT) {
                    MemoryRegion region = to_memory_region(memory_info);
                    if (!is_memory_suspicious(region)) {
                      char * buffer = new char[memory_info.RegionSize];
                      SIZE_T bytes_read;
                      if (ReadProcessMemory(process, memory_info.BaseAddress, buffer, memory_info.RegionSize, & bytes_read)) {
                        DWORD bytes_written;
                        WriteFile(file, buffer, bytes_read, & bytes_written, NULL);
                      }
                      delete[] buffer;
                    }
                  }
                  address += memory_info.RegionSize;
                } else {
                  address += system_info.dwPageSize;
                }
              }
              CloseHandle(file);
            }
          }
          CloseHandle(process);
        }
      }
      CloseHandle(parent_process);
    } while (Process32Next(snapshot, & entry) == TRUE);
  }
  CloseHandle(snapshot);
}

// Dump the memory of the given module to a file
void dump_module_memory(HMODULE module) {
  char module_name[MAX_PATH * 2];
  if (GetModuleFileNameExA(GetCurrentProcess(), module, module_name, MAX_PATH)) {
    cout << "Dumping memory for module: " << module_name << endl;
    // Write the module memory to disk
    stringstream filename_ss;
    filename_ss << module_name << ".dmp";
    string filename = filename_ss.str();
    try {
      ofstream file(filename, ios::out | ios::binary | ios::trunc);
      if (file) {
        MEMORY_BASIC_INFORMATION memory_info;
        DWORD_PTR address = (DWORD_PTR) module;
        DWORD_PTR module_size = 0;

        // Find the size of the module in memory
        while (VirtualQueryEx(GetCurrentProcess(), (LPCVOID) address, & memory_info, sizeof(memory_info)) == sizeof(memory_info)) {
          if (memory_info.AllocationBase == module) {
            module_size += memory_info.RegionSize;
          }
          address += memory_info.RegionSize;
          if (address >= (DWORD_PTR) module + module_size) {
            break;
          }
        }

        // Dump the memory of the module to disk
        address = (DWORD_PTR) module;
        while (VirtualQueryEx(GetCurrentProcess(), (LPCVOID) address, & memory_info, sizeof(memory_info)) == sizeof(memory_info)) {
          if (memory_info.State == MEM_COMMIT) {
            MemoryRegion region = to_memory_region(memory_info);
            if (!is_memory_suspicious(region)) {
              char * buffer = new char[memory_info.RegionSize];
              SIZE_T bytes_read;
              if (ReadProcessMemory(GetCurrentProcess(), memory_info.BaseAddress, buffer, memory_info.RegionSize, & bytes_read)) {
                file.write(buffer, bytes_read);
              }
              delete[] buffer;
            }
          }
          address += memory_info.RegionSize;
          if (address >= (DWORD_PTR) module + module_size) {
            break;
          }
        }
      }
    } catch (...) {
      cout << "Error dumping memory for module: " << module_name << endl;
    }
  }
}

// Dump the memory of all modules in the current process
void dump_process_memory() {
  HMODULE modules[1024];
  DWORD cb_needed;
  if (EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), & cb_needed)) {
    int num_modules = cb_needed / sizeof(HMODULE);
    for (int i = 0; i < num_modules; i++) {
      dump_module_memory(modules[i]);
    }
  }
}

int main() {
  cout << "Scanning for suspicious processes..." << endl;
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  PROCESSENTRY32 entry;
  entry.dwSize = sizeof(PROCESSENTRY32);
  if (Process32First(snapshot, & entry) == TRUE) {
    do {
      // Check if the process is the current process
      if (entry.th32ProcessID == GetCurrentProcessId()) {
        continue;
      }

      cout << "Scanning process: " << entry.szExeFile << endl;
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
    } while (Process32Next(snapshot, &entry) == TRUE);
  }
  CloseHandle(snapshot);

  return 0;
}


// Helper function to convert MEMORY_BASIC_INFORMATION struct to MemoryRegion struct
MemoryRegion to_memory_region(const MEMORY_BASIC_INFORMATION & memory_info) {
  MemoryRegion region;
  region.BaseAddress = memory_info.BaseAddress;
  region.RegionSize = memory_info.RegionSize;
  region.allocation_type = memory_info.AllocationProtect;
  region.state = memory_info.State;
  region.protect = memory_info.Protect;
  region.allocation_protect = memory_info.AllocationProtect;
  return region;
}

// Helper function to check if a memory region is suspicious based on its protection and allocation types
bool is_memory_suspicious(const MemoryRegion & region) {
  // Check if the memory is PAGE_EXECUTE or PAGE_EXECUTE_READ
  if (region.protect == PAGE_EXECUTE || region.protect == PAGE_EXECUTE_READ) {
    return true;
  }
  // Check if the memory is PAGE_READWRITE and has MEM_PRIVATE allocation type
  if (region.protect == PAGE_READWRITE && region.allocation_type == MEM_PRIVATE) {
    return true;
  }
  return false;
}
