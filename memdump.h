#ifndef MEMDUMP_H
#define MEMDUMP_H

#include <Windows.h>
#include <Psapi.h>
#include <DbgHelp.h>
#include <string>
#include <fstream>
#include <codecvt>
#include <locale>
#pragma comment(lib, "dbghelp.lib")

void dump_memory(HANDLE process_handle)
{
    WCHAR process_name[MAX_PATH];
    GetModuleFileNameExW(process_handle, nullptr, process_name, MAX_PATH);
    std::wstring dump_file_name = process_name;
    dump_file_name.replace(dump_file_name.length() - 3, 3, L"dmp");
    std::string dump_file_name_str = std::wstring_convert<std::codecvt_utf8_utf16<WCHAR>>().to_bytes(dump_file_name);
    HANDLE dump_file_handle = CreateFileA(dump_file_name_str.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    MINIDUMP_EXCEPTION_INFORMATION exception_info;
    exception_info.ThreadId = GetCurrentThreadId();
    exception_info.ExceptionPointers = nullptr;
    exception_info.ClientPointers = TRUE;
    std::ofstream dump_file(reinterpret_cast<char*>(dump_file_handle));
    MiniDumpWriteDump(process_handle, GetProcessId(process_handle), dump_file_handle, MiniDumpWithFullMemory, &exception_info, nullptr, nullptr);
    CloseHandle(dump_file_handle);
}

#endif // MEMDUMP_H
