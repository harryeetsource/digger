#ifndef MEMORY_DUMP_H
#define MEMORY_DUMP_H

#include <Windows.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <fstream>

void dump_memory(HANDLE process_handle) {
  // Get the process ID and name
  DWORD process_id = GetProcessId(process_handle);
  WCHAR process_name[MAX_PATH];
  GetModuleFileNameExW(process_handle, nullptr, process_name, MAX_PATH);

  // Generate the output file name
  std::wostringstream output_file_name_stream;
  output_file_name_stream << L"memory_dump_" << std::setw(8) << std::setfill(L'0') << std::hex << process_id << L"_" << process_name << L".bin";
  std::wstring output_file_name = output_file_name_stream.str();

  // Open the output file
  std::ofstream output_file(output_file_name, std::ios::binary);
  if (!output_file) {
    std::wcerr << L"Failed to open output file " << output_file_name << L": " << std::strerror(errno) << std::endl;
    return;
  }

  // Get the system information
  SYSTEM_INFO system_info;
  GetSystemInfo(&system_info);

  // Enumerate the memory regions of the process and dump them to the output file
  for (LPVOID address = system_info.lpMinimumApplicationAddress; address < system_info.lpMaximumApplicationAddress;) {
    MEMORY_BASIC_INFORMATION memory_info;
    if (VirtualQueryEx(process_handle, address, &memory_info, sizeof(memory_info)) == sizeof(memory_info)) {
      if (memory_info.State == MEM_COMMIT && (memory_info.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_READONLY | PAGE_READWRITE))) {
        char buffer[4096];
        SIZE_T bytes_read;
        for (LPVOID address2 = memory_info.BaseAddress; address2 < (LPBYTE)memory_info.BaseAddress + memory_info.RegionSize; address2 = (LPBYTE)address2 + sizeof(buffer)) {
          if (ReadProcessMemory(process_handle, address2, buffer, sizeof(buffer), &bytes_read) && bytes_read > 0) {
            output_file.write(buffer, bytes_read);
          }
        }
      }
      address = (LPBYTE)memory_info.BaseAddress + memory_info.RegionSize;
    }
    else {
      address = (LPBYTE)address + system_info.dwPageSize;
    }
  }

  // Close the output file
  output_file.close();

  std::wcout << L"Memory dumped for process " << process_id << L" to " << output_file_name << std::endl;
}

#endif // MEMORY_DUMP_H
