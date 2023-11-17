// STraceCLI.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "STraceCLI.hpp"
#include <stdint.h>
#include <string>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <memory>

HANDLE g_Driver;
SC_HANDLE g_Scm;

std::filesystem::path AskForFile() {
    wchar_t szFileName[MAX_PATH] = { 0 };
    
    OPENFILENAME ofn;
	ZeroMemory( &ofn , sizeof( ofn));
	ofn.lStructSize = sizeof ( ofn );
	ofn.hwndOwner = NULL  ;
	ofn.lpstrFile = szFileName;
	ofn.lpstrFile[0] = '\0';
	ofn.nMaxFile = sizeof(szFileName);
	ofn.lpstrFilter = L"All\0*.*\0DLL\0*.dll\0";
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

void LoadDll() {
    std::ifstream file(AskForFile(), std::ios::binary | std::ios::ate);

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

    DWORD BytesReturned = 0;
    BOOL Result;

    Result = DeviceIoControl(g_Driver, 
        IOCTL_LOADDLL, 
        fileData.get(),
        (DWORD)fileSize, 
        0,
        0,
        &BytesReturned, 
        NULL);

    if (Result != TRUE) {
        printf("DeviceIoControl for LOADDLL failed, error %d\n", GetLastError());
        return;
    }
}

void UnloadDll() {
    DWORD BytesReturned = 0;
    BOOL Result;

    Result = DeviceIoControl(g_Driver,
        IOCTL_UNLOADDLL,
        0,
        0,
        0,
        0,
        &BytesReturned,
        NULL);

    if (Result != TRUE) {
        printf("DeviceIoControl for LOADDLL failed, error %d\n", GetLastError());
        return;
    }
}

int main()
{
    printf("[+] Opening driver\n");
    g_Driver = CreateFileW(L"\\\\.\\STrace", GENERIC_ALL, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
    if (g_Driver == INVALID_HANDLE_VALUE) {
        printf("[!] Handle open to driver failed: %d\n", GetLastError());
        return 1;
    }
    printf("[+] Driver Opened Successfully\n");

    printf("[+] Opening Service Manager\n");
    g_Scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (NULL == g_Scm)
    {
        printf("[!] OpenServiceManager failed with: %d\n", GetLastError());
        return 1;
    }
    printf("[+] Service Manager Opened Successfully\n");


    while (true) {
        std::cout << "Input command: load, unload, exit" << std::endl;
        std::string input;
        std::cin >> input;
        if (input == "load") {
            printf("[+] Asking for plugin\n");
            LoadDll();
        } else if (input == "unload") {
            printf("[+] Unloading plugin\n");
            UnloadDll();
        } else if (input == "exit") {
            break;
        }
    }

    printf("[+] Goodbye\n");
}

