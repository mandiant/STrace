#pragma once

#define DRIVER_POOL_TAG         ' xtS'
#define DRIVER_NAME_WITH_EXT    L"strace.sys"
#define NT_DEVICE_NAME          L"\\Device\\STrace"
#define DOS_DEVICES_LINK_NAME   L"\\DosDevices\\STrace"
#define DEVICE_SDDL             L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"

#define IOCTL_LOADDLL           CTL_CODE (FILE_DEVICE_UNKNOWN, (0x800 + 0), METHOD_NEITHER, FILE_SPECIAL_ACCESS)
#define IOCTL_UNLOADDLL         CTL_CODE (FILE_DEVICE_UNKNOWN, (0x800 + 1), METHOD_NEITHER, FILE_SPECIAL_ACCESS)