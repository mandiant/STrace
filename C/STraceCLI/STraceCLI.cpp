// STraceCLI.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "STraceCLI.hpp"
#include "utils.h"
#include <stdint.h>
#include <string>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <memory>

HANDLE g_Driver;

LPCSTR g_envPluginPath = { "%SystemRoot%\\System32\\drivers\\StracePlugin.sys" };
LPCSTR g_PluginServiceName = { "StracePlugin" };
LPCSTR g_PluginServicePath = { "\\SystemRoot\\System32\\drivers\\StracePlugin.sys" };

std::filesystem::path AskForFile() {
    wchar_t szFileName[MAX_PATH] = { 0 };
    
    OPENFILENAMEW ofn;
	ZeroMemory( &ofn , sizeof( ofn));
	ofn.lStructSize = sizeof ( ofn );
	ofn.hwndOwner = NULL  ;
	ofn.lpstrFile = szFileName;
	ofn.lpstrFile[0] = '\0';
	ofn.nMaxFile = sizeof(szFileName);
	ofn.lpstrFilter = L"All\0*.*\0SYS\0*.sys\0";
	ofn.nFilterIndex =1;
	ofn.lpstrFileTitle = NULL ;
	ofn.nMaxFileTitle = 0 ;
	ofn.lpstrInitialDir=NULL ;
	ofn.Flags = OFN_PATHMUSTEXIST|OFN_FILEMUSTEXIST ;

    if (!GetOpenFileNameW(&ofn))
    {
        return "";
    }
    return szFileName;
}

BOOL FileExists(LPCTSTR szPath)
{
    DWORD dwAttrib = GetFileAttributes(szPath);

    return (dwAttrib != INVALID_FILE_ATTRIBUTES && 
        !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

BOOL IsPluginServiceInstalled() {
    
    ServiceHandle hScm;
    hScm.handle = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hScm.isInvalid()) {
        printf("[!] OpenServiceManager failed with: %d\n", GetLastError());
        return FALSE;
    }

    ServiceHandle hService;
    hService.handle = OpenService(hScm.handle, g_PluginServiceName, SC_MANAGER_CREATE_SERVICE | SERVICE_QUERY_STATUS);
    if (hService.isInvalid()) {
        if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) {
            return FALSE;
        }
        printf("[!] OpenService failed (%d)\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL IsPluginServiceStopped() {
    
    ServiceHandle hScm;
    hScm.handle = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hScm.isInvalid()){
        printf("[!] OpenServiceManager failed with: %d\n", GetLastError());
        return FALSE;
    }

    ServiceHandle hService;
    hService.handle = OpenService(hScm.handle, g_PluginServiceName, SERVICE_QUERY_STATUS);
    if (hService.isInvalid()){
        printf("[!] OpenService failed (%d)\n", GetLastError());
        return FALSE;
    }

    SERVICE_STATUS_PROCESS ssp = { 0 };
    DWORD bytesNeeded;
    if (!QueryServiceStatusEx(hService.handle,
        SC_STATUS_PROCESS_INFO,
        (LPBYTE)&ssp,
        sizeof(SERVICE_STATUS_PROCESS),
        &bytesNeeded)){
        printf("[!] QueryServiceStatusEx failed (%d)\n", GetLastError());
        return FALSE;
    }

    if (ssp.dwCurrentState == SERVICE_STOPPED){
        return TRUE;
    }

    return FALSE;
}

BOOL CreatePluginService(){
    
    if (IsPluginServiceInstalled()){
        return TRUE;
    }

    ServiceHandle hScm;
    hScm.handle = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hScm.isInvalid()){
        printf("[!] OpenServiceManager failed with: %d\n", GetLastError());
        return FALSE;
    }

    ServiceHandle hPluginService;
    // Create Service
    hPluginService.handle = CreateServiceA(hScm.handle,
        g_PluginServiceName,
        g_PluginServiceName,
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        g_PluginServicePath,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL);
    if (hPluginService.isInvalid()) {
        printf("[!] CreateService Failed to create Plugin Service %d\n", GetLastError());
        return FALSE;
    }

    printf("[+] Plugin Service Created\n");
    return TRUE;
}

void LoadPlugin() {
    std::ifstream file(AskForFile(), std::ios::binary | std::ios::ate);

    // Check if plugin service is already running
    if (!IsPluginServiceStopped()){
        printf("[!] Plugin Service already running\n");
        return;
    }

    // Check if we can open the file
    if (!file.good()) {
        std::cout << "[!] failed to open file" << std::endl;
        return;
    }

    std::unique_ptr<uint8_t> fileData;
    uintptr_t fileSize = file.tellg();
    fileData.reset(new uint8_t[fileSize]);
    if (!fileData) {
        std::cout << "[!] failed to allocate memory for file" << std::endl;
    }

    file.seekg(0, std::ios::beg);
    file.read((char*)fileData.get(), fileSize);

    // close as soon as possible
    file.close();

    CHAR pluginPath[MAX_PATH] = { 0 };
    if (!ExpandEnvironmentStringsA(g_envPluginPath, pluginPath, _countof(pluginPath))) {
        printf("[!] failed to expand path systemroot path for %s\n", g_envPluginPath);
        return;
    }

    HANDLE hFile = CreateFileA(pluginPath,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_SYSTEM,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Error creating plugin driver: %d\n", GetLastError());
        return;
    }

    DWORD nWritten = 0;
    if (!WriteFile(hFile, fileData.get(), fileSize, &nWritten, NULL)) {
        printf("[!] Error writing plugin driver: %d\n", GetLastError());
        return;
    }

    // Close Immediately so Loading Driver succeeds
    CloseHandle(hFile);
    hFile = INVALID_HANDLE_VALUE;

    if (!DeviceIoControl(g_Driver, IOCTL_LOADPLUGIN, NULL, 0, 0, 0, NULL, NULL)) {
        DeleteFileA(pluginPath);
        printf("[!] DeviceIoControl for LOADPLUGIN failed, error %d\n", GetLastError());
        return;
    }
}

void UnloadPlugin() {

    if (!DeviceIoControl(g_Driver, IOCTL_UNLOADPLUGIN, NULL, 0, 0, 0, NULL, NULL)) {
        printf("[!] DeviceIoControl for LOADPLUGIN failed, error %d\n", GetLastError());
        return;
    }

    CHAR pluginPath[MAX_PATH] = { 0 };
    if (!ExpandEnvironmentStringsA(g_envPluginPath, pluginPath, _countof(pluginPath))) {
        printf("[!] failed to expand path systemroot path for %s\n", g_envPluginPath);
        return;
    }
    
    if (FileExists(pluginPath)) {
        if (!DeleteFileA(pluginPath)) {
            printf("[!] failed to delete %s\n", pluginPath);
        }
    }
}

int main()
{
    g_Driver = CreateFileW(L"\\\\.\\STrace", GENERIC_ALL, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
    if (g_Driver == INVALID_HANDLE_VALUE) {
        printf("[!] Handle open to driver failed: %d\n", GetLastError());
        return 1;
    }
    printf("[+] Strace Driver Opened\n");

    if (!CreatePluginService()){
        return 1;
    }

    while (true) {
        std::cout << "Input command: load, unload, exit" << std::endl;
        std::string input;
        std::cin >> input;
        if (input == "load") {
            printf("[+] Loading Plugin\n");
            LoadPlugin();
        } else if (input == "unload") {
            printf("[+] Unloading plugin\n");
            UnloadPlugin();
        } else if (input == "exit") {
            break;
        }
    }

    printf("[+] Goodbye\n");
}

