#pragma once

#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <devioctl.h>
#include <tchar.h>
#include <strsafe.h>

#define IOCTL_LOADPLUGIN      CTL_CODE (FILE_DEVICE_UNKNOWN, (0x800 + 0), METHOD_NEITHER, FILE_SPECIAL_ACCESS)
#define IOCTL_UNLOADPLUGIN    CTL_CODE (FILE_DEVICE_UNKNOWN, (0x800 + 1), METHOD_NEITHER, FILE_SPECIAL_ACCESS)