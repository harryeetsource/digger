#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>

using namespace std;

// Define the list of suspicious API functions
char* suspicious_api_functions[] = { "HideThreadFromDebugger", "DllRegisterServer", "SuspendThread", "ShellExecute", "ShellExecuteW", "ShellExecuteEx", "ZwLoadDriver", "MapViewOfFile", "GetAsyncKeyState", "SetWindowsHookEx", "GetForegroundWindow", "WSASocket", "bind", "URLDownloadToFile", "InternetOpen", "InternetConnect", "WriteProcessMemory", "GetTickCount", "GetEIP", "free", "WinExec", "UnhookWindowsHookEx", "WinHttpOpen" };
const int num_suspicious_api_functions = sizeof(suspicious_api_functions) / sizeof(char*);

// Check if a memory region contains a suspicious indicator
bool is_memory_suspicious(const char* buffer, const size_t size) {
    for (int i = 0; i < num_suspicious_indicators; i++) {
        if (strstr(buffer, suspicious_indicators[i]) != NULL) {
            return true;
        }
    }
    return false;
}

// Scan for suspicious processes
void scan_processes() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(snapshot, &entry) == TRUE) {
        do {
            // Check if the process has a non-existent parent
            HANDLE parent_process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, entry.th32ParentProcessID);
            if (parent_process == NULL && entry.th32ParentProcessID != 0) {
                cout << "Found suspicious process with non-existent parent: " << entry.szExeFile << endl;
                // Write the process memory to disk
                HANDLE process = OpenProcess(PROCESS_VM_READ, FALSE, entry.th32ProcessID);
                if (process != NULL) {
                    char filename[MAX_PATH];
                    sprintf_s(filename, MAX_PATH, "%s.dmp", entry.szExeFile);
                    HANDLE file = CreateFileA(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                    if (file != INVALID_HANDLE_VALUE) {
                        SIZE_T bytes_written;
                        const size_t buffer_size = 1024;
                        char buffer[buffer_size];
                        DWORD_PTR address = 0;
                        while (address < 0x7FFFFFFF && ReadProcessMemory(process, (LPCVOID)address, buffer, buffer_size, &bytes_written)) {
                            if (is_memory_suspicious(buffer, bytes_written)) {
                                cout << "Found suspicious memory in process: " << entry.szExeFile << endl;
                                WriteFile(file, buffer, bytes_written, &bytes_written, NULL);
                            }
                            address += bytes_written;
                        }
                        CloseHandle(file);
                    }
                    CloseHandle(process);
                }
            }
            CloseHandle(parent_process);
        } while (Process32Next(snapshot, &entry) == TRUE);
    }
    CloseHandle(snapshot);
}

// Scan for suspicious API calls
void scan_api_calls() {
    HMODULE module = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((BYTE*)module + dos_header->e_lfanew);
    PIMAGE_IMPORT_DESCRIPTOR import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE
