# STrace
Steve's Tracer. A DTrace on windows syscall hook reimplementation. Think of this like a patchguard compatible SSDT hook, but without hacks. This doesn't support SSSDT (win32k apis), as the DTrace system call APIs themselves do not support this additional table. Zw* kernel apis can be traced in addition to all usermode SSDT syscalls.

# Functionality

Dtrace on windows supports multiple probe types. These include syscall, fbt, etw, profile, and maybe more. This reimplementation **only re-implements the syscall probe types**. All other probe types are considered completely out of scope for this project, and will **never be supported**. Please feel free to fork the project if you wish to add additional probe types. The scope was limited to just syscall probes due to the complexity of the other probe types and the systems they touch.

This reimplementation completely discards the D scripting language (note: NOT DLang the more popular modern language). The complexity of a VM in the kernel like the original DTrace implementation is unsuitable for this project. Instead, this implementation directly exposes the relevant C callbacks required to plug into the DTrace windows kernel interfaces. To enable 'hot-loading' of scripts a DLL based plugin system was used as a replacement for the VM + scripting evironment of the original dtrace. This plugin system accepts a 'normal' usermode DLL without any security checks enabled, or otherwise external dependencies and manually maps it into the kernel adress space. The `plugin dll` has exports which are invoked when kernel syscall callbacks occur. Kernel APIs are resolved via the normal import table (IAT) of the DLL, plugin DLLs link to `ntoskrnl.lib` and then the driver will resolve these APIs at load time, allowing any system apis to be called within plugin DLLs like normal. Performance of this plugin system is excellent as native code, rather than a script interpreter or a JIT, is directly executing between syscall ENTRY and RETURN. This design improves performance compared to the dtrace implementation provided by Microsoft.

Setting hooks is very simple, you get a routine to register/unregister a hook by api name, with a pre and post syscall callback. Callbacks have arguments and return values accessible as read only values. Return values cannot be spoofed, and the original syscall cannot (without hacks) be 'cancelled' - this API acts as an observer. When events occur and your hook callback fires, whatever you like can be done. Callbacks are synchonous, meaning if you delay execution in the entry callback by say sitting in a while loop then the syscall call will be delayed by that amount of time. Execution of the system call occurs just after return from the entry callback, and just before entry of the return callback. This system is fully patchguard compatible, however DSE must be disable as Microsoft unfortunately considers this type of kernel extension part of the NT kernel and so validates that the root signer is windows. This _does not_ work with tricks like enabling custom kernel signers, DSE really must be off during kernel boot. 
```
ValidationFlags=IMGP_LATEST_MS_ROOT_REQUIRED | IMGP_WINDOWS_ROOT_REQUIRED | IMGP_MS_SIGNATURE_REQUIRED 
Scenario=ImgSigningScenarioWindows
```

The Rust driver discards the DLL based plugin system used by the C++ driver and attempts to use a web assembly interpreter to host wasm scripts in the windows kernel instead. This is to be more similar to the original dtrace implementation which uses a VM, but with a better language than DLang. This provides sandboxing and other nice benefits. The POC is complete and works, but unfortunately is not usable due to performance issues with interpretering WASM with WASMI. A NT kernel compatible JIT based wasm engine would be required for this alternative design to be workable. It's included as a fun novelty, and might be usable for something else with some work.

# Project Organization
This project is largely split between it's C++ and Rust components. The C driver is feature complete and should be preferred. At a high level the project has the following components

* C++ Driver w/ DLL based plugins
* Rust Driver w/ wasm script based plugins
* C++ DLL plugin to monitor file deletes
* C++ DLL plugin to log all system calls and arguments
* Rust Wasm script plugin to test POC of wasm in NT Kernel
* Rust Wasm script tester to mock execution of wasm plugins in usermode 
* Rust log symbolicator to symbolicate C++ driver stack traces. Doesn't use DIA SDK.

# Installation & Setup

Build the driver and cli, then run the installer powershell script in install folder:
```
./install_as_admin.ps1
```

Reboot, then select the STrace boot entry, click F8 and boot with DSE disabled. After successful boot, the CLI can be used to load and unload plugin DLLs to begin tracing. Two example plugins are provided. Read the details below in detail if you run into issues.

## Installation Details
The original DTrace installation is here: https://techcommunity.microsoft.com/t5/windows-kernel-internals/dtrace-on-windows-20h1-updates/ba-p/1127929. The original DTrace requires Secure Boot and Virtualized Based Security to be configured, this is not the case with STrace as it doesn't implement the probe types (FBT) that require those features.

This project does the same operations as the installer, but via a simple powershell script instead of an MSI. The process is simple. First copy an apiset dll to system32 so that the kernel extension is activated. Then install a driver entry so that the driver main is executed at system startup for usermode communications. ApiSet dlls are digitally signed, so the original microsoft apiset was used, as required. This file is only provided in binary form and contains no logic other than to point the extension import to the implementing driver: ext-ms-win-ntos-trace-l1-1-0 -> dtrace.sys. See https://www.geoffchappell.com/studies/windows/win32/apisetschema/index.htm (ApiSetSchemaExtensions) for details on this mechanism.

STrace is loaded very early during kernel initialization, enabling Test Signing in the boot configuration database (BCD) is _not_ sufficient. Driver signature enforcement (DSE) must be disabled for STrace to successfully load, and this must be done every boot manually. To facilitate this the install script creates an easy boot menu entry for the user to select. There is no BCD flag to allow DSE to be permanently disabled across reboots, the kernel specifically forbids this.

Forgetting to disable DSE on boot will win you a trip to the  Automatic Repair menu upon restarting. You can try again without harm, if boot continues to fail the STrace driver will need to be manually removed from the drivers folder. Be aware that **boot failures can cause the STrace service's autorun flag to be disabled by windows***, you may need to set this back to autorun if a boot failure occurs at any time.
