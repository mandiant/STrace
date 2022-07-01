# Build

The plugins here are free standing DLLs with no dependencies, not even the CRT. To import kernel APIs, define them within `KernelApis.h`. The `ntoskrn.lib` file within this directory is used to link these definitions to `ntoskrnl.exe` and satisfy the linker. You may with to update the lib with one from your system, but the included one should work fine. The STrace driver will walk the IAT at plugin load time and fill in the DLLs imports.
