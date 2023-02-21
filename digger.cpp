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

using namespace std;

struct MemoryRegion {
  void * BaseAddress;
  size_t RegionSize;
  DWORD allocation_type;
  DWORD state;
  DWORD protect;
  DWORD allocation_protect;
};

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

bool is_memory_suspicious(const MemoryRegion & region) {
  // Check if the region is writable or executable
  if (region.protect & PAGE_EXECUTE || region.protect & PAGE_EXECUTE_READ || region.protect & PAGE_EXECUTE_READWRITE || region.protect & PAGE_EXECUTE_WRITECOPY) {
    return true;
  }
  if (region.protect & PAGE_READWRITE || region.protect & PAGE_WRITECOPY) {
    return true;
  }
  // Check if the region is located in the system or Windows directory
  if (wcsstr((const wchar_t*)region.BaseAddress, L"\\Windows") != NULL || wcsstr((const wchar_t*)region.BaseAddress, L"\\system32") != NULL) {

    return true;
  }
  // Check if the region is a stack or heap
  if (region.allocation_type & MEM_COMMIT || region.allocation_type & MEM_PRIVATE) {
    return true;
  }
  return false;
}

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
  set < DWORD > dumped_processes;
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  PROCESSENTRY32 entry;
  entry.dwSize = sizeof(PROCESSENTRY32);
  if (Process32First(snapshot, & entry) == TRUE) {
    do {
      // Check if the process has already been dumped
      if (dumped_processes.count(entry.th32ProcessID) > 0) {
        continue;
      }
      // Check if the process has a non-existent parent
      HANDLE parent_process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, entry.th32ParentProcessID);
      if (parent_process == NULL && entry.th32ParentProcessID != 0) {
        cout << "Found suspicious process with non-existent parent: " << entry.szExeFile << endl;
      }

      // Write the process memory to disk
      HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, entry.th32ProcessID);
      if (process != NULL) {
        char filename[MAX_PATH];
        sprintf_s(filename, MAX_PATH, "%s.dmp", entry.szExeFile);

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
                  char * buffer = new char[region.RegionSize];
                  SIZE_T bytes_read;
                  if (ReadProcessMemory(process, region.BaseAddress, buffer, region.RegionSize, & bytes_read)) {
                    DWORD bytes_written;
                    WriteFile(file, buffer, region.RegionSize, & bytes_written, NULL);
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
        CloseHandle(process);

        // Add the process ID to the dumped set
        dumped_processes.insert(entry.th32ProcessID);
      }

      // Check if the process is running any suspicious APIs
      process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, entry.th32ProcessID);
      if (process != NULL) {
        // Get the list of modules in the process
        HMODULE modules[1024];
        DWORD num_modules;
        if (EnumProcessModules(process, modules, sizeof(modules), & num_modules)) {
          for (int i = 0; i < num_modules / sizeof(HMODULE); i++) {
            // Get the module file name
            char module_name[MAX_PATH];
            if (GetModuleFileNameEx(process, modules[i], module_name, sizeof(module_name)) > 0) {
              // Open the module file and check for the suspicious API functions
              ifstream module_file(module_name, ios::binary);
              if (module_file.is_open()) {
                stringstream buffer;
                buffer << module_file.rdbuf();
                string module_code = buffer.str();
                bool found_suspect_api = false;
                for (int j = 0; j < num_suspicious_api_functions; j++) {
                  if (module_code.find(suspicious_api_functions[j]) != string::npos) {
                    found_suspect_api = true;
                    break;
                  }
                }
                if (found_suspect_api) {
                  cout << "Found suspicious API call in process: " << entry.szExeFile << endl;
                  if (dump_if_debug_registers_set) {
                    CONTEXT context;
                    memset( & context, 0, sizeof(CONTEXT));
                    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                    if (GetThreadContext(process, & context)) {
                      if (context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0) {
                        cout << "Dumping process memory due to set debug registers" << endl;
                        char filename[MAX_PATH];
                        sprintf_s(filename, MAX_PATH, "%s-debug.dmp", entry.szExeFile);
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
                                  char * buffer = new char[region.RegionSize];
                                  SIZE_T bytes_read;
                                  if (ReadProcessMemory(process, region.BaseAddress, buffer, region.RegionSize, & bytes_read)) {
                                    DWORD bytes_written;
                                    WriteFile(file, buffer, region.RegionSize, & bytes_written, NULL);
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
                        dumped_processes.insert(entry.th32ProcessID);
                        break;
                      }
                    }
                  }
                }
              }
            }
          }
        }
        CloseHandle(process);
      }
    } while (Process32Next(snapshot, & entry) == TRUE);
  }
  CloseHandle(snapshot);
}

int main() {
  // Scan all running processes for suspicious behavior
  scan_processes(true);
  return 0;
}
