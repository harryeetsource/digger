typedef
const wchar_t * LPCWSTR;

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

#include <winver.h>

#include <versionhelpers.h>

#include <urlmon.h>

#pragma comment(lib, "urlmon.lib")

#pragma comment(lib, "Version.lib")#include <winnt.h>

#include <tchar.h>


using namespace std;
vector < MemoryRegion > get_mem_regions() {
  vector < MemoryRegion > result;
  unordered_set < MemoryRegion, MemoryRegionHasher > region_set;

  SYSTEM_INFO system_info;
  GetSystemInfo( & system_info);

  // Iterate over memory regions in the process
  MEMORY_BASIC_INFORMATION mem_info;
  DWORD last_address = 0;
  while (VirtualQuery((LPCVOID) last_address, & mem_info, sizeof(mem_info)) == sizeof(mem_info)) {
    if (mem_info.State == MEM_COMMIT && mem_info.Type == MEM_PRIVATE) {
      MemoryRegion region;
      region.base_address = (DWORD_PTR) mem_info.BaseAddress;
      region.region_size = mem_info.RegionSize;
      region_set.insert(region);
    }
    last_address = (DWORD) mem_info.BaseAddress + mem_info.RegionSize;
    if (last_address > (DWORD) system_info.lpMaximumApplicationAddress) {
      break;
    }
  }

  // Convert unordered_set to vector
  result.reserve(region_set.size());
  for (const auto & region: region_set) {
    result.push_back(region);
  }

  return result;
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

const size_t num_suspicious_api_functions = sizeof(suspicious_api_functions) / sizeof(char * );

struct MemoryRegion {
  DWORD_PTR base_address;
  SIZE_T region_size;

  bool operator == (const MemoryRegion & other) const {
    return base_address == other.base_address && region_size == other.region_size;
  }
};

struct MemoryRegionHasher {
  std::size_t operator()(const MemoryRegion & region) const {
    return std::hash < DWORD_PTR > {}(region.base_address) ^ std::hash < SIZE_T > {}(region.region_size);
  }
};

namespace std {
  template < > struct hash < MemoryRegion > {
    size_t operator()(const MemoryRegion & region) const {
      size_t result = hash < void * > ()(region.BaseAddress);
      result ^= hash < size_t > ()(region.RegionSize) + 0x9e3779b9 + (result << 6) + (result >> 2);
      result ^= hash < DWORD > ()(region.allocation_type) + 0x9e3779b9 + (result << 6) + (result >> 2);
      result ^= hash < DWORD > ()(region.state) + 0x9e3779b9 + (result << 6) + (result >> 2);
      result ^= hash < DWORD > ()(region.protect) + 0x9e3779b9 + (result << 6) + (result >> 2);
      result ^= hash < DWORD > ()(region.allocation_protect) + 0x9e3779b9 + (result << 6) + (result >> 2);
      return result;
    }
  };
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

// Check if a memory region is executable
bool is_executable(const MemoryRegion & region) {
  return (region.protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

// Check if a memory region is writable
bool is_writable(const MemoryRegion & region) {
  return (region.protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

// Check if a memory region is readable
bool is_readable(const MemoryRegion & region) {
  return (region.protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

// Check if a memory region is suspicious
bool is_suspicious(const MemoryRegion & region) {
  // Check if the region is executable and not a file-backed mapping
  if (is_executable(region) && (region.allocation_protect & PAGE_NOCACHE) == 0 && (region.state & MEM_MAPPED) == 0 && (region.allocation_type & MEM_IMAGE) == 0) {
    return true;
  }
  // Check if the region is writable and not a file-backed mapping
  if (is_writable(region) && (region.allocation_protect & PAGE_NOCACHE) == 0 && (region.state & MEM_MAPPED) == 0 && (region.allocation_type & MEM_IMAGE) == 0) {
    return true;
  }
  return false;
}

// Dump the memory of a process to a file
void dump_memory(HANDLE process_handle,
  const wchar_t * file_name) {
  // Open the file for writing
  FILE * file;
  if (_wfopen_s( & file, file_name, L " wb") != 0) {
    wcout << "Could not open file for writing" << endl;
    return;
  }
  // Get the process ID and open the process
  DWORD process_id = GetProcessId(process_handle);

  // Enumerate the memory regions of the process and dump them to file
  SYSTEM_INFO system_info;
  GetSystemInfo( & system_info);
  for (void * address = system_info.lpMinimumApplicationAddress; address < system_info.lpMaximumApplicationAddress;) {
    MEMORY_BASIC_INFORMATION memory_info;
    if (VirtualQueryEx(process_handle, address, & memory_info, sizeof(memory_info)) == sizeof(memory_info)) {
      // Only dump memory that is committed and readable
      if (memory_info.State == MEM_COMMIT && is_readable(to_memory_region(memory_info))) {
        char buffer[4096];
        SIZE_T bytes_read;
        for (char * address2 = reinterpret_cast < char * > (memory_info.BaseAddress); address2 < reinterpret_cast < char * > (memory_info.BaseAddress) + memory_info.RegionSize; address2 += sizeof(buffer)) {
          if (ReadProcessMemory(process_handle, address2, buffer, sizeof(buffer), & bytes_read) && bytes_read > 0) {
            fwrite(buffer, 1, bytes_read, file);
          }
        }
      }
      address = (void * )((DWORD_PTR) memory_info.BaseAddress + memory_info.RegionSize);
    } else {
      address = (void * )((DWORD_PTR) address + system_info.dwPageSize);
    }
  }

  // Close the file
  fclose(file);

  wcout << "Memory dumped for process " << process_id << endl;
}
// Dump the memory of a process if it is suspicious
void dump_suspicious_process(HANDLE process_handle,
  const wchar_t * dump_dir) {
  // Check if any of the memory regions are suspicious
  unordered_set < MemoryRegion > suspicious_regions;
  SYSTEM_INFO system_info;
  GetSystemInfo( & system_info);
  for (void * address = system_info.lpMinimumApplicationAddress; address < system_info.lpMaximumApplicationAddress;) {
    MEMORY_BASIC_INFORMATION memory_info;
    if (VirtualQueryEx(process_handle, address, & memory_info, sizeof(memory_info)) == sizeof(memory_info)) {
      if (is_suspicious(to_memory_region(memory_info))) {
        suspicious_regions.insert(to_memory_region(memory_info));
      }
      address = (void * )((DWORD_PTR) memory_info.BaseAddress + memory_info.RegionSize);
    } else {
      address = (void * )((DWORD_PTR) address + system_info.dwPageSize);
    }
  }

  // Dump the memory of the process if it has suspicious regions
  if (!suspicious_regions.empty()) {
    // Create the dump directory if it does not exist
    if (!CreateDirectoryW(dump_dir, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
      wcout << "Could not create dump directory" << endl;
      return;
    }

    // Generate a file name for the dump file
    wostringstream file_name_stream;
    file_name_stream << dump_dir << L "\\" << GetProcessId(process_handle) << L ".dmp";

    // Dump the memory to file
    dump_memory(process_handle, file_name_stream.str().c_str());

    wcout << "Memory dumped for suspicious process " << GetProcessId(process_handle) << endl;
  }
}

// Download symbol files from the Microsoft symbol server
std::wstring get_file_version(const std::wstring & module_name) {
  DWORD unused;
  DWORD version_size = GetFileVersionInfoSizeW(module_name.c_str(), & unused);
  if (version_size == 0) {
    return L "";
  }

  std::vector < char > version_info(version_size);
  if (!GetFileVersionInfoW(module_name.c_str(), 0, version_size, & version_info[0])) {
    return L "";
  }

  VS_FIXEDFILEINFO * fixed_file_info;
  UINT fixed_file_info_size;
  if (!VerQueryValueW( & version_info[0], L "\\", reinterpret_cast < void ** > ( & fixed_file_info), & fixed_file_info_size)) {
    return L "";
  }

  return std::to_wstring(HIWORD(fixed_file_info -> dwFileVersionMS)) + L "." + std::to_wstring(LOWORD(fixed_file_info -> dwFileVersionMS)) + L "." + std::to_wstring(HIWORD(fixed_file_info -> dwFileVersionLS)) + L "." + std::to_wstring(LOWORD(fixed_file_info -> dwFileVersionLS));
}

void download_symbols() {
  for (size_t i = 0; i < num_suspicious_api_functions; ++i) {
    // Get the address of the function
    FARPROC function_address = GetProcAddress(GetModuleHandle(NULL), suspicious_api_functions[i]);
    if (function_address == NULL) {
      wcout << "Could not get address of " << suspicious_api_functions[i] << endl;
      continue;
    }

    // Get the name of the module containing the function
    HMODULE module_handle;
    if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCTSTR) function_address, & module_handle)) {
      wcout << "Could not get module containing " << suspicious_api_functions[i] << endl;
      continue;
    }
    wstring module_name(MAX_PATH, L '\0');
    GetModuleFileNameW(module_handle, & module_name[0], MAX_PATH);
    module_name.resize(wcslen(module_name.c_str()));

    // Download the symbol file
    std::wstring version = get_file_version(module_name);
    if (version.empty()) {
      wcout << "Could not get version for " << module_name << endl;
      continue;
    }

    wostringstream symbol_url;
    symbol_url << L "http://msdl.microsoft.com/download/symbols/" << module_name << L "/" << version << L "/" << module_name.substr(module_name.find_last_of(L "\\") + 1) << L ".pdb";

    wostringstream symbol_file_name;
    symbol_file_name << L "C:\\symbols\\" << module_name.substr(module_name.find_last_of(L "\\") + 1) << L ".pdb";

    HRESULT hr = URLDownloadToFileW(NULL, symbol_url.str().c_str(), symbol_file_name.str().c_str(), 0, NULL);

    if (hr == S_OK) {
      wcout << "Downloaded symbols for " << module_name << endl;
    } else {
      wcout << "Could not download symbols for " << module_name << endl;
    }
  }
  SymCleanup(GetCurrentProcess());
}

// Check if an API function is suspicious
bool is_suspicious_api(const char * api_name) {
  for (size_t i = 0; i < num_suspicious_api_functions; ++i) {
    if (strcmp(suspicious_api_functions[i], api_name) == 0) {
      return true;
    }
  }
  return false;
}

// Stackwalk a thread to determine if it is calling suspicious APIs
void stackwalk_thread(HANDLE thread_handle, HANDLE process_handle,
  const wchar_t * dump_dir) {
  CONTEXT context;
  context.ContextFlags = CONTEXT_FULL;
  if (GetThreadContext(thread_handle, & context)) {
    STACKFRAME64 stack_frame;
    memset( & stack_frame, 0, sizeof(stack_frame));

    #ifdef _WIN64
    stack_frame.AddrPC.Mode = AddrModeFlat;
    stack_frame.AddrPC.Offset = context.Rip;
    stack_frame.AddrFrame.Mode = AddrModeFlat;
    stack_frame.AddrFrame.Offset = context.Rbp;
    stack_frame.AddrStack.Mode = AddrModeFlat;
    stack_frame.AddrStack.Offset = context.Rsp;
    #endif

    HANDLE process = GetCurrentProcess();
    HANDLE thread = GetCurrentThread();

    // Open the symbol file for the process
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
    if (!SymInitialize(process, NULL, TRUE)) {
      wcout << "Could not initialize symbol engine" << endl;
      return;
    }

    // Walk the stack frames of the thread
    const int max_frames = 1024;
    DWORD64 frames[max_frames];
    USHORT frames_loaded = 0;
    while (StackWalk64(IMAGE_FILE_MACHINE_AMD64, process_handle, thread_handle, & stack_frame, & context, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
      // Check if the frame is valid
      if (stack_frame.AddrPC.Offset == 0) {
        break;
      }
      // Load the symbol for the frame
      const int max_name_len = 256;
      char symbol_name[max_name_len];
      DWORD64 symbol_displacement = 0;
      IMAGEHLP_LINE64 line_info;
      DWORD line_displacement = 0;
      memset( & line_info, 0, sizeof(line_info));
      line_info.SizeOfStruct = sizeof(line_info);
      SYMBOL_INFO symbol_info;
      symbol_info.SizeOfStruct = sizeof(SYMBOL_INFO);
      symbol_info.MaxNameLen = MAX_SYM_NAME;

      if (SymFromAddr(process, stack_frame.AddrPC.Offset, NULL, & symbol_info) && SymGetLineFromAddr64(process, stack_frame.AddrPC.Offset, & line_displacement, & line_info)) {
        // Check if the symbol is suspicious
        if (is_suspicious_api(symbol_name)) {
          // Log the suspicious API call
          wcout << "Suspicious API call detected in thread " << GetThreadId(thread_handle) << " at address " << (void * ) stack_frame.AddrPC.Offset << " (symbol: " << symbol_name << ", source: " << line_info.FileName << " line " << line_info.LineNumber << ")" << endl;
          // Dump the memory of the process
          dump_suspicious_process(process_handle, dump_dir);
        }
      }
      frames[frames_loaded++] = stack_frame.AddrPC.Offset;
      if (frames_loaded >= max_frames) {
        break;
      }
    }
  }
}
// Clean up the symbol engine

// Scan a process for suspicious indicators
void scan_process(HANDLE process_handle,
  const wchar_t * dump_dir) {
  // Check if the process is the current process
  if (process_handle == GetCurrentProcess()) {
    return;
  }

  // Dump the memory of the process if it has suspicious regions
  dump_suspicious_process(process_handle, dump_dir);

  // Suspend the process to ensure a consistent view of memory
  if (SuspendThread(process_handle) == (DWORD) - 1) {
    wcout << "Could not suspend process " << GetProcessId(process_handle) << endl;
    return;
  }

  // Dump the memory of the process
  wostringstream memory_dump_file_name_stream;
  memory_dump_file_name_stream << dump_dir << L " " << GetProcessId(process_handle) << L ".dmp";
  dump_memory(process_handle, memory_dump_file_name_stream.str().c_str());

  // Enumerate the threads of the process and stackwalk them to detect suspicious API calls
  HANDLE thread_snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (thread_snap != INVALID_HANDLE_VALUE) {
    THREADENTRY32 thread_entry;
    thread_entry.dwSize = sizeof(THREADENTRY32);
    if (Thread32First(thread_snap, & thread_entry)) {
      do {
        if (thread_entry.th32OwnerProcessID == GetProcessId(process_handle)) {
          HANDLE thread_handle = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, thread_entry.th32ThreadID);
          if (thread_handle != NULL) {
            stackwalk_thread(thread_handle, process_handle, dump_dir);
            CloseHandle(thread_handle);
          }
        }
      } while (Thread32Next(thread_snap, & thread_entry));
    }
    CloseHandle(thread_snap);
  }

  // Resume the process
  if (ResumeThread(process_handle) == (DWORD) - 1) {
    wcout << "Could not resume process " << GetProcessId(process_handle) << endl;
  }
}

// Main function
int wmain(int argc, wchar_t * argv[]) {
  // Download symbol files from the Microsoft symbol server
  download_symbols();

  // Get the dump directory
  const wchar_t * dump_dir = L "C:\\dumps";
  if (argc >= 2) {
    dump_dir = argv[1];
  }

  // Enumerate the processes on the system and scan them for suspicious indicators
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snapshot != INVALID_HANDLE_VALUE) {
    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof(process_entry);
    if (Process32First(snapshot, & process_entry)) {
      do {
        HANDLE process_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_SUSPEND_RESUME, FALSE, process_entry.th32ProcessID);
        if (process_handle != NULL) {
          scan_process(process_handle, dump_dir);
          CloseHandle(process_handle);
        }
      } while (Process32Next(snapshot, & process_entry));
    }
    CloseHandle(snapshot);
  }

  return 0;
}
