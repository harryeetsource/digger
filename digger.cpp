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
// Dump the memory of the given module to a file
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
          if (memory_info.State == MEM_COMMIT && memory_info.AllocationBase == module) {
            char * buffer = new char[memory_info.RegionSize];
            SIZE_T bytes_read;
            if (ReadProcessMemory(GetCurrentProcess(), memory_info.BaseAddress, buffer, memory_info.RegionSize, & bytes_read)) {
              file.write(buffer, bytes_read);
            }
            delete[] buffer;
          }
          address += memory_info.RegionSize;
          if (address >= (DWORD_PTR) module + module_size) {
            break;
          }
        }

        file.close();
      } else {
        throw runtime_error("Failed to create dump file for module: " + filename);
      }
    } catch (const exception & ex) {
      cout << "Error dumping memory for module " << module_name << ": " << ex.what() << endl;
    }
  } else {
    cout << "Failed to get module name" << endl;
  }
}

// Dump the memory of the given process to a file
void dump_process_memory(HANDLE process,
  const char * module_name,
    const char * api_name = nullptr) {
  char process_name[MAX_PATH];
  DWORD process_id = GetProcessId(process);
  if (GetModuleFileNameExA(process, NULL, process_name, MAX_PATH)) {
    cout << "Dumping memory for process: " << process_name << " (PID: " << process_id << ")" << endl;

    // Write the process memory to disk
    char filename[MAX_PATH];
    if (api_name != nullptr) {
      sprintf_s(filename, MAX_PATH, "%s_%s_%s.dmp", process_name, module_name, api_name);
    } else {
      sprintf_s(filename, MAX_PATH, "%s.dmp", process_name);
    }
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
    } else {
      cout << "Failed to create dump file for process: " << process_name << " (PID: " << process_id << ")" << endl;
    }
  } else {
    cout << "Failed to get process name for process with PID: " << process_id << endl;
  }
  CloseHandle(process);
}

// Convert a MEMORY_BASIC_INFORMATION structure to a MemoryRegion structure
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

bool is_memory_suspicious(const MemoryRegion & region) {
  if ((region.allocation_type & MEM_COMMIT) && ((region.allocation_protect & PAGE_EXECUTE_READWRITE) || (region.allocation_protect & PAGE_EXECUTE_READ))) {
    // Executable memory region with RWX or RX protection
    return true;
  } else if ((region.allocation_type & MEM_IMAGE) && (region.state & MEM_COMMIT) && !(region.protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY)) && ((region.protect & PAGE_EXECUTE_READWRITE) || (region.protect & PAGE_EXECUTE_READ))) {
    // Executable memory region that does not map to a file on disk with RWX or RX protection
    return true;
  } else if ((region.allocation_type & MEM_COMMIT) && (region.protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ))) {
    // RWX or RX memory region
    return true;
  } else {
    return false;
  }
}

// Scan for suspicious API calls
void scan_api_calls() {
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  PROCESSENTRY32 entry;
  entry.dwSize = sizeof(PROCESSENTRY32);
  if (Process32First(snapshot, & entry) == TRUE) {
    do {
      // Exclude the current process
      if (entry.th32ProcessID != GetCurrentProcessId()) {
        HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, entry.th32ProcessID);
        if (process != NULL) {
          cout << "Scanning process: " << entry.szExeFile << " (PID: " << entry.th32ProcessID << ")" << endl;
          HMODULE module_handles[1024];
          DWORD num_modules;
          if (EnumProcessModules(process, module_handles, sizeof(module_handles), & num_modules)) {
            for (DWORD i = 0; i < (num_modules / sizeof(HMODULE)); i++) {
              TCHAR module_name[MAX_PATH];
              if (GetModuleFileNameEx(process, module_handles[i], module_name, MAX_PATH)) {
                // Check if any suspicious APIs are called in the module
                HMODULE module = LoadLibraryEx(module_name, NULL, DONT_RESOLVE_DLL_REFERENCES);
                if (module != NULL) {
                  bool found_suspicious_api = false; // flag to track whether a suspicious API was found
                  for (int j = 0; j < num_suspicious_api_functions; j++) {
                    FARPROC function_address = GetProcAddress(module, suspicious_api_functions[j]);
                    if (function_address != NULL) {
                      found_suspicious_api = true;
                      cout << "Found suspicious API function: " << suspicious_api_functions[j] << " in " << module_name << endl;
                      // Find the memory region that contains the suspicious API function
                      MEMORY_BASIC_INFORMATION memory_info;
                      if (VirtualQueryEx(process, (LPCVOID) function_address, & memory_info, sizeof(memory_info)) == sizeof(memory_info)) {
                        // Get the process ID associated with the memory region
                        DWORD process_id = 0;
                        GetWindowThreadProcessId
                          (GetForegroundWindow(), & process_id);
                        // Dump the memory of the process associated with the memory region to disk
                        dump_process_memory(OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, process_id), module_name, suspicious_api_functions[j]);

                        // Write the memory of the module that contains the suspicious API function to disk
                        dump_module_memory(module_handles[i]);
                      }
                    }
                  }
                  FreeLibrary(module);
                  if (found_suspicious_api) {
                    // if a suspicious API was found, dump the memory for the process
                    dump_module_memory(module_handles[i]);
                  }
                }
              }
            }
          }
          CloseHandle(process);
        }
      }
    } while (Process32Next(snapshot, & entry) == TRUE);
  }
  CloseHandle(snapshot);
}

// Scan for suspicious processes
void scan_processes() {
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
          CloseHandle(process);
        }
      }
      CloseHandle(parent_process);
    } while (Process32Next(snapshot, & entry) == TRUE);
  }
  CloseHandle(snapshot);
}
int main() {
  cout << "Starting process scanner..." << endl;
  scan_processes();
  scan_api_calls();
  return 0;
}
