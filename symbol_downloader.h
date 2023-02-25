#ifndef SYMBOL_DOWNLOADER_H
#define SYMBOL_DOWNLOADER_H

#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <wininet.h>
#include <urlmon.h>
#include <lmcons.h>
#include <dbghelp.h>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "dbghelp.lib")

class SymbolDownloader {
public:
    static std::wstring get_file_version(const std::wstring& module_name);

    static void download_symbols(const DWORD processId);

    static void download_symbols(const std::vector<std::string>& suspicious_api_functions);
};

#endif // SYMBOL_DOWNLOADER_H
