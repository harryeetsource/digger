#include "symbol_downloader.h"

#include <iostream>

#include <fstream>

#include <sstream>

#include <wininet.h>

#include <windows.h>

#include <versionhelpers.h>

#include <psapi.h>

#pragma comment(lib, "wininet.lib")

std::wstring SymbolDownloader::get_file_version(const std::wstring & filePath) {
  // Get the size of the file's version info
  DWORD verHandle = 0;
  const DWORD verSize = GetFileVersionInfoSizeW(filePath.c_str(), & verHandle);
  if (verSize == 0) {
    return L"";
  }

  // Allocate memory for the file's version info
  std::vector < BYTE > verData(verSize);
  if (GetFileVersionInfoW(filePath.c_str(), verHandle, verSize, verData.data()) == FALSE) {
    return L"";
  }

  // Get the file version string
  LPVOID fileVersionPtr;
  UINT fileVersionLen;
  if (VerQueryValueW(verData.data(), L"\\StringFileInfo\\040904E4\\FileVersion", & fileVersionPtr, & fileVersionLen) == FALSE) {
    return L"";
  }

  // Return the file version string as a wstring
  return std::wstring(static_cast <
    const wchar_t * > (fileVersionPtr), fileVersionLen);
}

void SymbolDownloader::download_symbols(const std::vector < std::string > & moduleNames, DWORD processId) {
  if (moduleNames.empty()) {
    return;
  }

  // Create a directory for the downloaded symbol files
  if (CreateDirectoryW(L"symbols", NULL) == FALSE && GetLastError() != ERROR_ALREADY_EXISTS) {
    return;
  }

  // Open a handle to the internet
  HINTERNET hInternet = InternetOpenW(L"Microsoft-Symbol-Server/6.3.9600.17298", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
  if (hInternet == NULL) {
    return;
  }

  // Iterate over the module names and download the symbol files for each one
  for (const auto & moduleName: moduleNames) {
    // Form the URL for the symbol file
    const std::wstring symbolUrl = L"http://msdl.microsoft.com/download/symbols/" + std::wstring(moduleName.begin(), moduleName.end()) + L"/" + get_file_version(std::wstring(moduleName.begin(), moduleName.end()));

    // Open a connection to the URL
    HINTERNET hConnect = InternetConnectW(hInternet, L"msdl.microsoft.com", INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, NULL);
    if (hConnect == NULL) {
      continue;
    }

    HINTERNET hRequest = HttpOpenRequestW(hConnect, L"GET", symbolUrl.c_str(), NULL, NULL, NULL, 0, NULL);
    if (hRequest == NULL) {
      InternetCloseHandle(hConnect);
      continue;
    }

    if (HttpSendRequestW(hRequest, NULL, 0, NULL, 0) == FALSE) {
      InternetCloseHandle(hRequest);
      InternetCloseHandle(hConnect);
      continue;
    }

    // Get the HTTP status code for the request
    DWORD httpStatusCode = 0;
    DWORD httpStatusCodeSize = sizeof(httpStatusCode);
    HttpQueryInfoW(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, & httpStatusCode, & httpStatusCodeSize, NULL);

    // Download the symbol file if it was found on the server
    if (httpStatusCode == HTTP_STATUS_OK) {
  // Create the file path for the symbol file
  const std::wstring symbolFilePath = L"\\symbols\\" + std::wstring(moduleName.begin(), moduleName.end()) + L".pdb";

  // Open the file for writing
  std::wofstream symbolFile(symbolFilePath.c_str(), std::ios::out | std::ios_base::binary);
  if (symbolFile.is_open()) {
    // Read the response from the server and write it to the file
    std::vector < char > responseBuffer(1024);
    DWORD bytesRead;
    while (InternetReadFile(hRequest, responseBuffer.data(), responseBuffer.size(), & bytesRead) && bytesRead > 0) {
      symbolFile.write(reinterpret_cast <
        const wchar_t * > (responseBuffer.data()), bytesRead);
    }
    symbolFile.close();
  }
}

// Close the handles
InternetCloseHandle(hRequest);
InternetCloseHandle(hConnect);
}

InternetCloseHandle(hInternet);
}
