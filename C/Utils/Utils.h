#pragma once


extern "C" bool __stdcall backupFile(PWSTR backupDir, UNICODE_STRING backupFileName, HANDLE hFileSource);
extern "C" OBJECT_NAME_INFORMATION * __stdcall getFilePathFromHandle(HANDLE hFile);