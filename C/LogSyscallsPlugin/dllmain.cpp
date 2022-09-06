#include <stdint.h>
#include <intrin.h>


#include "Interface.h"
#include "crt.h"
#include "utils.h"
#include "config.h"
#include "probedefs.h"
#include "string.h"
#include "magic_enum.hpp"

#pragma warning(disable: 6011)
PluginApis g_Apis;

#define LOG_DEBUG(fmt,...)  g_Apis.pLogPrint(LogLevelDebug, __FUNCTION__, fmt,   __VA_ARGS__)
#define LOG_INFO(fmt,...)   g_Apis.pLogPrint(LogLevelInfo,  __FUNCTION__, fmt,   __VA_ARGS__)
#define LOG_WARN(fmt,...)   g_Apis.pLogPrint(LogLevelWarn,  __FUNCTION__, fmt,   __VA_ARGS__)
#define LOG_ERROR(fmt,...)  g_Apis.pLogPrint(LogLevelError, __FUNCTION__, fmt,   __VA_ARGS__)

extern "C" __declspec(dllexport) void StpInitialize(PluginApis& pApis) {
    g_Apis = pApis;
    LOG_INFO("Plugin Initializing...\r\n");

    g_Apis.pSetCallback("LockProductActivationKeys", true, PROBE_IDS::IdLockProductActivationKeys);
    g_Apis.pSetCallback("LockProductActivationKeys", false, PROBE_IDS::IdLockProductActivationKeys);
    g_Apis.pSetCallback("WaitHighEventPair", true, PROBE_IDS::IdWaitHighEventPair);
    g_Apis.pSetCallback("WaitHighEventPair", false, PROBE_IDS::IdWaitHighEventPair);
    g_Apis.pSetCallback("RegisterThreadTerminatePort", true, PROBE_IDS::IdRegisterThreadTerminatePort);
    g_Apis.pSetCallback("RegisterThreadTerminatePort", false, PROBE_IDS::IdRegisterThreadTerminatePort);
    g_Apis.pSetCallback("AssociateWaitCompletionPacket", true, PROBE_IDS::IdAssociateWaitCompletionPacket);
    g_Apis.pSetCallback("AssociateWaitCompletionPacket", false, PROBE_IDS::IdAssociateWaitCompletionPacket);
    g_Apis.pSetCallback("QueryPerformanceCounter", true, PROBE_IDS::IdQueryPerformanceCounter);
    g_Apis.pSetCallback("QueryPerformanceCounter", false, PROBE_IDS::IdQueryPerformanceCounter);
    g_Apis.pSetCallback("CompactKeys", true, PROBE_IDS::IdCompactKeys);
    g_Apis.pSetCallback("CompactKeys", false, PROBE_IDS::IdCompactKeys);
    g_Apis.pSetCallback("QuerySystemInformationEx", true, PROBE_IDS::IdQuerySystemInformationEx);
    g_Apis.pSetCallback("QuerySystemInformationEx", false, PROBE_IDS::IdQuerySystemInformationEx);
    g_Apis.pSetCallback("ResetEvent", true, PROBE_IDS::IdResetEvent);
    g_Apis.pSetCallback("ResetEvent", false, PROBE_IDS::IdResetEvent);
    g_Apis.pSetCallback("GetContextThread", true, PROBE_IDS::IdGetContextThread);
    g_Apis.pSetCallback("GetContextThread", false, PROBE_IDS::IdGetContextThread);
    g_Apis.pSetCallback("QueryInformationThread", true, PROBE_IDS::IdQueryInformationThread);
    g_Apis.pSetCallback("QueryInformationThread", false, PROBE_IDS::IdQueryInformationThread);
    g_Apis.pSetCallback("WaitForSingleObject", true, PROBE_IDS::IdWaitForSingleObject);
    g_Apis.pSetCallback("WaitForSingleObject", false, PROBE_IDS::IdWaitForSingleObject);
    g_Apis.pSetCallback("FlushBuffersFileEx", true, PROBE_IDS::IdFlushBuffersFileEx);
    g_Apis.pSetCallback("FlushBuffersFileEx", false, PROBE_IDS::IdFlushBuffersFileEx);
    g_Apis.pSetCallback("UnloadKey2", true, PROBE_IDS::IdUnloadKey2);
    g_Apis.pSetCallback("UnloadKey2", false, PROBE_IDS::IdUnloadKey2);
    g_Apis.pSetCallback("ReadOnlyEnlistment", true, PROBE_IDS::IdReadOnlyEnlistment);
    g_Apis.pSetCallback("ReadOnlyEnlistment", false, PROBE_IDS::IdReadOnlyEnlistment);
    g_Apis.pSetCallback("DeleteFile", true, PROBE_IDS::IdDeleteFile);
    g_Apis.pSetCallback("DeleteFile", false, PROBE_IDS::IdDeleteFile);
    g_Apis.pSetCallback("DeleteAtom", true, PROBE_IDS::IdDeleteAtom);
    g_Apis.pSetCallback("DeleteAtom", false, PROBE_IDS::IdDeleteAtom);
    g_Apis.pSetCallback("QueryDirectoryFile", true, PROBE_IDS::IdQueryDirectoryFile);
    g_Apis.pSetCallback("QueryDirectoryFile", false, PROBE_IDS::IdQueryDirectoryFile);
    g_Apis.pSetCallback("SetEventBoostPriority", true, PROBE_IDS::IdSetEventBoostPriority);
    g_Apis.pSetCallback("SetEventBoostPriority", false, PROBE_IDS::IdSetEventBoostPriority);
    g_Apis.pSetCallback("AllocateUserPhysicalPagesEx", true, PROBE_IDS::IdAllocateUserPhysicalPagesEx);
    g_Apis.pSetCallback("AllocateUserPhysicalPagesEx", false, PROBE_IDS::IdAllocateUserPhysicalPagesEx);
    g_Apis.pSetCallback("WriteFile", true, PROBE_IDS::IdWriteFile);
    g_Apis.pSetCallback("WriteFile", false, PROBE_IDS::IdWriteFile);
    g_Apis.pSetCallback("QueryInformationFile", true, PROBE_IDS::IdQueryInformationFile);
    g_Apis.pSetCallback("QueryInformationFile", false, PROBE_IDS::IdQueryInformationFile);
    g_Apis.pSetCallback("AlpcCancelMessage", true, PROBE_IDS::IdAlpcCancelMessage);
    g_Apis.pSetCallback("AlpcCancelMessage", false, PROBE_IDS::IdAlpcCancelMessage);
    g_Apis.pSetCallback("OpenMutant", true, PROBE_IDS::IdOpenMutant);
    g_Apis.pSetCallback("OpenMutant", false, PROBE_IDS::IdOpenMutant);
    g_Apis.pSetCallback("CreatePartition", true, PROBE_IDS::IdCreatePartition);
    g_Apis.pSetCallback("CreatePartition", false, PROBE_IDS::IdCreatePartition);
    g_Apis.pSetCallback("QueryTimer", true, PROBE_IDS::IdQueryTimer);
    g_Apis.pSetCallback("QueryTimer", false, PROBE_IDS::IdQueryTimer);
    g_Apis.pSetCallback("OpenEvent", true, PROBE_IDS::IdOpenEvent);
    g_Apis.pSetCallback("OpenEvent", false, PROBE_IDS::IdOpenEvent);
    g_Apis.pSetCallback("OpenObjectAuditAlarm", true, PROBE_IDS::IdOpenObjectAuditAlarm);
    g_Apis.pSetCallback("OpenObjectAuditAlarm", false, PROBE_IDS::IdOpenObjectAuditAlarm);
    g_Apis.pSetCallback("MakePermanentObject", true, PROBE_IDS::IdMakePermanentObject);
    g_Apis.pSetCallback("MakePermanentObject", false, PROBE_IDS::IdMakePermanentObject);
    g_Apis.pSetCallback("CommitTransaction", true, PROBE_IDS::IdCommitTransaction);
    g_Apis.pSetCallback("CommitTransaction", false, PROBE_IDS::IdCommitTransaction);
    g_Apis.pSetCallback("SetSystemTime", true, PROBE_IDS::IdSetSystemTime);
    g_Apis.pSetCallback("SetSystemTime", false, PROBE_IDS::IdSetSystemTime);
    g_Apis.pSetCallback("GetDevicePowerState", true, PROBE_IDS::IdGetDevicePowerState);
    g_Apis.pSetCallback("GetDevicePowerState", false, PROBE_IDS::IdGetDevicePowerState);
    g_Apis.pSetCallback("SetSystemPowerState", true, PROBE_IDS::IdSetSystemPowerState);
    g_Apis.pSetCallback("SetSystemPowerState", false, PROBE_IDS::IdSetSystemPowerState);
    g_Apis.pSetCallback("AlpcCreateResourceReserve", true, PROBE_IDS::IdAlpcCreateResourceReserve);
    g_Apis.pSetCallback("AlpcCreateResourceReserve", false, PROBE_IDS::IdAlpcCreateResourceReserve);
    g_Apis.pSetCallback("UnlockFile", true, PROBE_IDS::IdUnlockFile);
    g_Apis.pSetCallback("UnlockFile", false, PROBE_IDS::IdUnlockFile);
    g_Apis.pSetCallback("AlpcDeletePortSection", true, PROBE_IDS::IdAlpcDeletePortSection);
    g_Apis.pSetCallback("AlpcDeletePortSection", false, PROBE_IDS::IdAlpcDeletePortSection);
    g_Apis.pSetCallback("SetInformationResourceManager", true, PROBE_IDS::IdSetInformationResourceManager);
    g_Apis.pSetCallback("SetInformationResourceManager", false, PROBE_IDS::IdSetInformationResourceManager);
    g_Apis.pSetCallback("FreeUserPhysicalPages", true, PROBE_IDS::IdFreeUserPhysicalPages);
    g_Apis.pSetCallback("FreeUserPhysicalPages", false, PROBE_IDS::IdFreeUserPhysicalPages);
    g_Apis.pSetCallback("LoadKeyEx", true, PROBE_IDS::IdLoadKeyEx);
    g_Apis.pSetCallback("LoadKeyEx", false, PROBE_IDS::IdLoadKeyEx);
    g_Apis.pSetCallback("PropagationComplete", true, PROBE_IDS::IdPropagationComplete);
    g_Apis.pSetCallback("PropagationComplete", false, PROBE_IDS::IdPropagationComplete);
    g_Apis.pSetCallback("AccessCheckByTypeResultListAndAuditAlarm", true, PROBE_IDS::IdAccessCheckByTypeResultListAndAuditAlarm);
    g_Apis.pSetCallback("AccessCheckByTypeResultListAndAuditAlarm", false, PROBE_IDS::IdAccessCheckByTypeResultListAndAuditAlarm);
    g_Apis.pSetCallback("QueryInformationToken", true, PROBE_IDS::IdQueryInformationToken);
    g_Apis.pSetCallback("QueryInformationToken", false, PROBE_IDS::IdQueryInformationToken);
    g_Apis.pSetCallback("RegisterProtocolAddressInformation", true, PROBE_IDS::IdRegisterProtocolAddressInformation);
    g_Apis.pSetCallback("RegisterProtocolAddressInformation", false, PROBE_IDS::IdRegisterProtocolAddressInformation);
    g_Apis.pSetCallback("ProtectVirtualMemory", true, PROBE_IDS::IdProtectVirtualMemory);
    g_Apis.pSetCallback("ProtectVirtualMemory", false, PROBE_IDS::IdProtectVirtualMemory);
    g_Apis.pSetCallback("CreateKey", true, PROBE_IDS::IdCreateKey);
    g_Apis.pSetCallback("CreateKey", false, PROBE_IDS::IdCreateKey);
    g_Apis.pSetCallback("AlpcSendWaitReceivePort", true, PROBE_IDS::IdAlpcSendWaitReceivePort);
    g_Apis.pSetCallback("AlpcSendWaitReceivePort", false, PROBE_IDS::IdAlpcSendWaitReceivePort);
    g_Apis.pSetCallback("OpenRegistryTransaction", true, PROBE_IDS::IdOpenRegistryTransaction);
    g_Apis.pSetCallback("OpenRegistryTransaction", false, PROBE_IDS::IdOpenRegistryTransaction);
    g_Apis.pSetCallback("TerminateProcess", true, PROBE_IDS::IdTerminateProcess);
    g_Apis.pSetCallback("TerminateProcess", false, PROBE_IDS::IdTerminateProcess);
    g_Apis.pSetCallback("PowerInformation", true, PROBE_IDS::IdPowerInformation);
    g_Apis.pSetCallback("PowerInformation", false, PROBE_IDS::IdPowerInformation);
    g_Apis.pSetCallback("otifyChangeDirectoryFile", true, PROBE_IDS::IdotifyChangeDirectoryFile);
    g_Apis.pSetCallback("otifyChangeDirectoryFile", false, PROBE_IDS::IdotifyChangeDirectoryFile);
    g_Apis.pSetCallback("CreateTransaction", true, PROBE_IDS::IdCreateTransaction);
    g_Apis.pSetCallback("CreateTransaction", false, PROBE_IDS::IdCreateTransaction);
    g_Apis.pSetCallback("CreateProfileEx", true, PROBE_IDS::IdCreateProfileEx);
    g_Apis.pSetCallback("CreateProfileEx", false, PROBE_IDS::IdCreateProfileEx);
    g_Apis.pSetCallback("QueryLicenseValue", true, PROBE_IDS::IdQueryLicenseValue);
    g_Apis.pSetCallback("QueryLicenseValue", false, PROBE_IDS::IdQueryLicenseValue);
    g_Apis.pSetCallback("CreateProfile", true, PROBE_IDS::IdCreateProfile);
    g_Apis.pSetCallback("CreateProfile", false, PROBE_IDS::IdCreateProfile);
    g_Apis.pSetCallback("InitializeRegistry", true, PROBE_IDS::IdInitializeRegistry);
    g_Apis.pSetCallback("InitializeRegistry", false, PROBE_IDS::IdInitializeRegistry);
    g_Apis.pSetCallback("FreezeTransactions", true, PROBE_IDS::IdFreezeTransactions);
    g_Apis.pSetCallback("FreezeTransactions", false, PROBE_IDS::IdFreezeTransactions);
    g_Apis.pSetCallback("OpenJobObject", true, PROBE_IDS::IdOpenJobObject);
    g_Apis.pSetCallback("OpenJobObject", false, PROBE_IDS::IdOpenJobObject);
    g_Apis.pSetCallback("SubscribeWnfStateChange", true, PROBE_IDS::IdSubscribeWnfStateChange);
    g_Apis.pSetCallback("SubscribeWnfStateChange", false, PROBE_IDS::IdSubscribeWnfStateChange);
    g_Apis.pSetCallback("GetWriteWatch", true, PROBE_IDS::IdGetWriteWatch);
    g_Apis.pSetCallback("GetWriteWatch", false, PROBE_IDS::IdGetWriteWatch);
    g_Apis.pSetCallback("GetCachedSigningLevel", true, PROBE_IDS::IdGetCachedSigningLevel);
    g_Apis.pSetCallback("GetCachedSigningLevel", false, PROBE_IDS::IdGetCachedSigningLevel);
    g_Apis.pSetCallback("SetSecurityObject", true, PROBE_IDS::IdSetSecurityObject);
    g_Apis.pSetCallback("SetSecurityObject", false, PROBE_IDS::IdSetSecurityObject);
    g_Apis.pSetCallback("QueryIntervalProfile", true, PROBE_IDS::IdQueryIntervalProfile);
    g_Apis.pSetCallback("QueryIntervalProfile", false, PROBE_IDS::IdQueryIntervalProfile);
    g_Apis.pSetCallback("PropagationFailed", true, PROBE_IDS::IdPropagationFailed);
    g_Apis.pSetCallback("PropagationFailed", false, PROBE_IDS::IdPropagationFailed);
    g_Apis.pSetCallback("CreateSectionEx", true, PROBE_IDS::IdCreateSectionEx);
    g_Apis.pSetCallback("CreateSectionEx", false, PROBE_IDS::IdCreateSectionEx);
    g_Apis.pSetCallback("RaiseException", true, PROBE_IDS::IdRaiseException);
    g_Apis.pSetCallback("RaiseException", false, PROBE_IDS::IdRaiseException);
    g_Apis.pSetCallback("SetCachedSigningLevel2", true, PROBE_IDS::IdSetCachedSigningLevel2);
    g_Apis.pSetCallback("SetCachedSigningLevel2", false, PROBE_IDS::IdSetCachedSigningLevel2);
    g_Apis.pSetCallback("CommitEnlistment", true, PROBE_IDS::IdCommitEnlistment);
    g_Apis.pSetCallback("CommitEnlistment", false, PROBE_IDS::IdCommitEnlistment);
    g_Apis.pSetCallback("QueryInformationByName", true, PROBE_IDS::IdQueryInformationByName);
    g_Apis.pSetCallback("QueryInformationByName", false, PROBE_IDS::IdQueryInformationByName);
    g_Apis.pSetCallback("CreateThread", true, PROBE_IDS::IdCreateThread);
    g_Apis.pSetCallback("CreateThread", false, PROBE_IDS::IdCreateThread);
    g_Apis.pSetCallback("OpenResourceManager", true, PROBE_IDS::IdOpenResourceManager);
    g_Apis.pSetCallback("OpenResourceManager", false, PROBE_IDS::IdOpenResourceManager);
    g_Apis.pSetCallback("ReadRequestData", true, PROBE_IDS::IdReadRequestData);
    g_Apis.pSetCallback("ReadRequestData", false, PROBE_IDS::IdReadRequestData);
    g_Apis.pSetCallback("ClearEvent", true, PROBE_IDS::IdClearEvent);
    g_Apis.pSetCallback("ClearEvent", false, PROBE_IDS::IdClearEvent);
    g_Apis.pSetCallback("TestAlert", true, PROBE_IDS::IdTestAlert);
    g_Apis.pSetCallback("TestAlert", false, PROBE_IDS::IdTestAlert);
    g_Apis.pSetCallback("SetInformationThread", true, PROBE_IDS::IdSetInformationThread);
    g_Apis.pSetCallback("SetInformationThread", false, PROBE_IDS::IdSetInformationThread);
    g_Apis.pSetCallback("SetTimer2", true, PROBE_IDS::IdSetTimer2);
    g_Apis.pSetCallback("SetTimer2", false, PROBE_IDS::IdSetTimer2);
    g_Apis.pSetCallback("SetDefaultUILanguage", true, PROBE_IDS::IdSetDefaultUILanguage);
    g_Apis.pSetCallback("SetDefaultUILanguage", false, PROBE_IDS::IdSetDefaultUILanguage);
    g_Apis.pSetCallback("EnumerateValueKey", true, PROBE_IDS::IdEnumerateValueKey);
    g_Apis.pSetCallback("EnumerateValueKey", false, PROBE_IDS::IdEnumerateValueKey);
    g_Apis.pSetCallback("OpenEnlistment", true, PROBE_IDS::IdOpenEnlistment);
    g_Apis.pSetCallback("OpenEnlistment", false, PROBE_IDS::IdOpenEnlistment);
    g_Apis.pSetCallback("SetIntervalProfile", true, PROBE_IDS::IdSetIntervalProfile);
    g_Apis.pSetCallback("SetIntervalProfile", false, PROBE_IDS::IdSetIntervalProfile);
    g_Apis.pSetCallback("QueryPortInformationProcess", true, PROBE_IDS::IdQueryPortInformationProcess);
    g_Apis.pSetCallback("QueryPortInformationProcess", false, PROBE_IDS::IdQueryPortInformationProcess);
    g_Apis.pSetCallback("QueryInformationTransactionManager", true, PROBE_IDS::IdQueryInformationTransactionManager);
    g_Apis.pSetCallback("QueryInformationTransactionManager", false, PROBE_IDS::IdQueryInformationTransactionManager);
    g_Apis.pSetCallback("SetInformationTransactionManager", true, PROBE_IDS::IdSetInformationTransactionManager);
    g_Apis.pSetCallback("SetInformationTransactionManager", false, PROBE_IDS::IdSetInformationTransactionManager);
    g_Apis.pSetCallback("InitializeEnclave", true, PROBE_IDS::IdInitializeEnclave);
    g_Apis.pSetCallback("InitializeEnclave", false, PROBE_IDS::IdInitializeEnclave);
    g_Apis.pSetCallback("PrepareComplete", true, PROBE_IDS::IdPrepareComplete);
    g_Apis.pSetCallback("PrepareComplete", false, PROBE_IDS::IdPrepareComplete);
    g_Apis.pSetCallback("QueueApcThread", true, PROBE_IDS::IdQueueApcThread);
    g_Apis.pSetCallback("QueueApcThread", false, PROBE_IDS::IdQueueApcThread);
    g_Apis.pSetCallback("WorkerFactoryWorkerReady", true, PROBE_IDS::IdWorkerFactoryWorkerReady);
    g_Apis.pSetCallback("WorkerFactoryWorkerReady", false, PROBE_IDS::IdWorkerFactoryWorkerReady);
    g_Apis.pSetCallback("GetCompleteWnfStateSubscription", true, PROBE_IDS::IdGetCompleteWnfStateSubscription);
    g_Apis.pSetCallback("GetCompleteWnfStateSubscription", false, PROBE_IDS::IdGetCompleteWnfStateSubscription);
    g_Apis.pSetCallback("AlertThreadByThreadId", true, PROBE_IDS::IdAlertThreadByThreadId);
    g_Apis.pSetCallback("AlertThreadByThreadId", false, PROBE_IDS::IdAlertThreadByThreadId);
    g_Apis.pSetCallback("LockVirtualMemory", true, PROBE_IDS::IdLockVirtualMemory);
    g_Apis.pSetCallback("LockVirtualMemory", false, PROBE_IDS::IdLockVirtualMemory);
    g_Apis.pSetCallback("DeviceIoControlFile", true, PROBE_IDS::IdDeviceIoControlFile);
    g_Apis.pSetCallback("DeviceIoControlFile", false, PROBE_IDS::IdDeviceIoControlFile);
    g_Apis.pSetCallback("CreateUserProcess", true, PROBE_IDS::IdCreateUserProcess);
    g_Apis.pSetCallback("CreateUserProcess", false, PROBE_IDS::IdCreateUserProcess);
    g_Apis.pSetCallback("QuerySection", true, PROBE_IDS::IdQuerySection);
    g_Apis.pSetCallback("QuerySection", false, PROBE_IDS::IdQuerySection);
    g_Apis.pSetCallback("SaveKeyEx", true, PROBE_IDS::IdSaveKeyEx);
    g_Apis.pSetCallback("SaveKeyEx", false, PROBE_IDS::IdSaveKeyEx);
    g_Apis.pSetCallback("RollbackTransaction", true, PROBE_IDS::IdRollbackTransaction);
    g_Apis.pSetCallback("RollbackTransaction", false, PROBE_IDS::IdRollbackTransaction);
    g_Apis.pSetCallback("TraceEvent", true, PROBE_IDS::IdTraceEvent);
    g_Apis.pSetCallback("TraceEvent", false, PROBE_IDS::IdTraceEvent);
    g_Apis.pSetCallback("OpenSection", true, PROBE_IDS::IdOpenSection);
    g_Apis.pSetCallback("OpenSection", false, PROBE_IDS::IdOpenSection);
    g_Apis.pSetCallback("RequestPort", true, PROBE_IDS::IdRequestPort);
    g_Apis.pSetCallback("RequestPort", false, PROBE_IDS::IdRequestPort);
    g_Apis.pSetCallback("UnsubscribeWnfStateChange", true, PROBE_IDS::IdUnsubscribeWnfStateChange);
    g_Apis.pSetCallback("UnsubscribeWnfStateChange", false, PROBE_IDS::IdUnsubscribeWnfStateChange);
    g_Apis.pSetCallback("ThawRegistry", true, PROBE_IDS::IdThawRegistry);
    g_Apis.pSetCallback("ThawRegistry", false, PROBE_IDS::IdThawRegistry);
    g_Apis.pSetCallback("CreateJobObject", true, PROBE_IDS::IdCreateJobObject);
    g_Apis.pSetCallback("CreateJobObject", false, PROBE_IDS::IdCreateJobObject);
    g_Apis.pSetCallback("OpenKeyTransactedEx", true, PROBE_IDS::IdOpenKeyTransactedEx);
    g_Apis.pSetCallback("OpenKeyTransactedEx", false, PROBE_IDS::IdOpenKeyTransactedEx);
    g_Apis.pSetCallback("WaitForMultipleObjects", true, PROBE_IDS::IdWaitForMultipleObjects);
    g_Apis.pSetCallback("WaitForMultipleObjects", false, PROBE_IDS::IdWaitForMultipleObjects);
    g_Apis.pSetCallback("DuplicateToken", true, PROBE_IDS::IdDuplicateToken);
    g_Apis.pSetCallback("DuplicateToken", false, PROBE_IDS::IdDuplicateToken);
    g_Apis.pSetCallback("AlpcOpenSenderThread", true, PROBE_IDS::IdAlpcOpenSenderThread);
    g_Apis.pSetCallback("AlpcOpenSenderThread", false, PROBE_IDS::IdAlpcOpenSenderThread);
    g_Apis.pSetCallback("AlpcImpersonateClientContainerOfPort", true, PROBE_IDS::IdAlpcImpersonateClientContainerOfPort);
    g_Apis.pSetCallback("AlpcImpersonateClientContainerOfPort", false, PROBE_IDS::IdAlpcImpersonateClientContainerOfPort);
    g_Apis.pSetCallback("DrawText", true, PROBE_IDS::IdDrawText);
    g_Apis.pSetCallback("DrawText", false, PROBE_IDS::IdDrawText);
    g_Apis.pSetCallback("ReleaseSemaphore", true, PROBE_IDS::IdReleaseSemaphore);
    g_Apis.pSetCallback("ReleaseSemaphore", false, PROBE_IDS::IdReleaseSemaphore);
    g_Apis.pSetCallback("SetQuotaInformationFile", true, PROBE_IDS::IdSetQuotaInformationFile);
    g_Apis.pSetCallback("SetQuotaInformationFile", false, PROBE_IDS::IdSetQuotaInformationFile);
    g_Apis.pSetCallback("QueryInformationAtom", true, PROBE_IDS::IdQueryInformationAtom);
    g_Apis.pSetCallback("QueryInformationAtom", false, PROBE_IDS::IdQueryInformationAtom);
    g_Apis.pSetCallback("EnumerateBootEntries", true, PROBE_IDS::IdEnumerateBootEntries);
    g_Apis.pSetCallback("EnumerateBootEntries", false, PROBE_IDS::IdEnumerateBootEntries);
    g_Apis.pSetCallback("ThawTransactions", true, PROBE_IDS::IdThawTransactions);
    g_Apis.pSetCallback("ThawTransactions", false, PROBE_IDS::IdThawTransactions);
    g_Apis.pSetCallback("AccessCheck", true, PROBE_IDS::IdAccessCheck);
    g_Apis.pSetCallback("AccessCheck", false, PROBE_IDS::IdAccessCheck);
    g_Apis.pSetCallback("FlushProcessWriteBuffers", true, PROBE_IDS::IdFlushProcessWriteBuffers);
    g_Apis.pSetCallback("FlushProcessWriteBuffers", false, PROBE_IDS::IdFlushProcessWriteBuffers);
    g_Apis.pSetCallback("QuerySemaphore", true, PROBE_IDS::IdQuerySemaphore);
    g_Apis.pSetCallback("QuerySemaphore", false, PROBE_IDS::IdQuerySemaphore);
    g_Apis.pSetCallback("CreateNamedPipeFile", true, PROBE_IDS::IdCreateNamedPipeFile);
    g_Apis.pSetCallback("CreateNamedPipeFile", false, PROBE_IDS::IdCreateNamedPipeFile);
    g_Apis.pSetCallback("AlpcDeleteResourceReserve", true, PROBE_IDS::IdAlpcDeleteResourceReserve);
    g_Apis.pSetCallback("AlpcDeleteResourceReserve", false, PROBE_IDS::IdAlpcDeleteResourceReserve);
    g_Apis.pSetCallback("QuerySystemEnvironmentValueEx", true, PROBE_IDS::IdQuerySystemEnvironmentValueEx);
    g_Apis.pSetCallback("QuerySystemEnvironmentValueEx", false, PROBE_IDS::IdQuerySystemEnvironmentValueEx);
    g_Apis.pSetCallback("ReadFileScatter", true, PROBE_IDS::IdReadFileScatter);
    g_Apis.pSetCallback("ReadFileScatter", false, PROBE_IDS::IdReadFileScatter);
    g_Apis.pSetCallback("OpenKeyEx", true, PROBE_IDS::IdOpenKeyEx);
    g_Apis.pSetCallback("OpenKeyEx", false, PROBE_IDS::IdOpenKeyEx);
    g_Apis.pSetCallback("SignalAndWaitForSingleObject", true, PROBE_IDS::IdSignalAndWaitForSingleObject);
    g_Apis.pSetCallback("SignalAndWaitForSingleObject", false, PROBE_IDS::IdSignalAndWaitForSingleObject);
    g_Apis.pSetCallback("ReleaseMutant", true, PROBE_IDS::IdReleaseMutant);
    g_Apis.pSetCallback("ReleaseMutant", false, PROBE_IDS::IdReleaseMutant);
    g_Apis.pSetCallback("TerminateJobObject", true, PROBE_IDS::IdTerminateJobObject);
    g_Apis.pSetCallback("TerminateJobObject", false, PROBE_IDS::IdTerminateJobObject);
    g_Apis.pSetCallback("SetSystemEnvironmentValue", true, PROBE_IDS::IdSetSystemEnvironmentValue);
    g_Apis.pSetCallback("SetSystemEnvironmentValue", false, PROBE_IDS::IdSetSystemEnvironmentValue);
    g_Apis.pSetCallback("Close", true, PROBE_IDS::IdClose);
    g_Apis.pSetCallback("Close", false, PROBE_IDS::IdClose);
    g_Apis.pSetCallback("QueueApcThreadEx", true, PROBE_IDS::IdQueueApcThreadEx);
    g_Apis.pSetCallback("QueueApcThreadEx", false, PROBE_IDS::IdQueueApcThreadEx);
    g_Apis.pSetCallback("QueryMultipleValueKey", true, PROBE_IDS::IdQueryMultipleValueKey);
    g_Apis.pSetCallback("QueryMultipleValueKey", false, PROBE_IDS::IdQueryMultipleValueKey);
    g_Apis.pSetCallback("AlpcQueryInformation", true, PROBE_IDS::IdAlpcQueryInformation);
    g_Apis.pSetCallback("AlpcQueryInformation", false, PROBE_IDS::IdAlpcQueryInformation);
    g_Apis.pSetCallback("UpdateWnfStateData", true, PROBE_IDS::IdUpdateWnfStateData);
    g_Apis.pSetCallback("UpdateWnfStateData", false, PROBE_IDS::IdUpdateWnfStateData);
    g_Apis.pSetCallback("ListenPort", true, PROBE_IDS::IdListenPort);
    g_Apis.pSetCallback("ListenPort", false, PROBE_IDS::IdListenPort);
    g_Apis.pSetCallback("FlushInstructionCache", true, PROBE_IDS::IdFlushInstructionCache);
    g_Apis.pSetCallback("FlushInstructionCache", false, PROBE_IDS::IdFlushInstructionCache);
    g_Apis.pSetCallback("GetNotificationResourceManager", true, PROBE_IDS::IdGetNotificationResourceManager);
    g_Apis.pSetCallback("GetNotificationResourceManager", false, PROBE_IDS::IdGetNotificationResourceManager);
    g_Apis.pSetCallback("QueryFullAttributesFile", true, PROBE_IDS::IdQueryFullAttributesFile);
    g_Apis.pSetCallback("QueryFullAttributesFile", false, PROBE_IDS::IdQueryFullAttributesFile);
    g_Apis.pSetCallback("SuspendThread", true, PROBE_IDS::IdSuspendThread);
    g_Apis.pSetCallback("SuspendThread", false, PROBE_IDS::IdSuspendThread);
    g_Apis.pSetCallback("CompareTokens", true, PROBE_IDS::IdCompareTokens);
    g_Apis.pSetCallback("CompareTokens", false, PROBE_IDS::IdCompareTokens);
    g_Apis.pSetCallback("CancelWaitCompletionPacket", true, PROBE_IDS::IdCancelWaitCompletionPacket);
    g_Apis.pSetCallback("CancelWaitCompletionPacket", false, PROBE_IDS::IdCancelWaitCompletionPacket);
    g_Apis.pSetCallback("AlpcAcceptConnectPort", true, PROBE_IDS::IdAlpcAcceptConnectPort);
    g_Apis.pSetCallback("AlpcAcceptConnectPort", false, PROBE_IDS::IdAlpcAcceptConnectPort);
    g_Apis.pSetCallback("OpenTransaction", true, PROBE_IDS::IdOpenTransaction);
    g_Apis.pSetCallback("OpenTransaction", false, PROBE_IDS::IdOpenTransaction);
    g_Apis.pSetCallback("ImpersonateAnonymousToken", true, PROBE_IDS::IdImpersonateAnonymousToken);
    g_Apis.pSetCallback("ImpersonateAnonymousToken", false, PROBE_IDS::IdImpersonateAnonymousToken);
    g_Apis.pSetCallback("QuerySecurityObject", true, PROBE_IDS::IdQuerySecurityObject);
    g_Apis.pSetCallback("QuerySecurityObject", false, PROBE_IDS::IdQuerySecurityObject);
    g_Apis.pSetCallback("RollbackEnlistment", true, PROBE_IDS::IdRollbackEnlistment);
    g_Apis.pSetCallback("RollbackEnlistment", false, PROBE_IDS::IdRollbackEnlistment);
    g_Apis.pSetCallback("ReplacePartitionUnit", true, PROBE_IDS::IdReplacePartitionUnit);
    g_Apis.pSetCallback("ReplacePartitionUnit", false, PROBE_IDS::IdReplacePartitionUnit);
    g_Apis.pSetCallback("CreateKeyTransacted", true, PROBE_IDS::IdCreateKeyTransacted);
    g_Apis.pSetCallback("CreateKeyTransacted", false, PROBE_IDS::IdCreateKeyTransacted);
    g_Apis.pSetCallback("ConvertBetweenAuxiliaryCounterAndPerformanceCounter", true, PROBE_IDS::IdConvertBetweenAuxiliaryCounterAndPerformanceCounter);
    g_Apis.pSetCallback("ConvertBetweenAuxiliaryCounterAndPerformanceCounter", false, PROBE_IDS::IdConvertBetweenAuxiliaryCounterAndPerformanceCounter);
    g_Apis.pSetCallback("CreateKeyedEvent", true, PROBE_IDS::IdCreateKeyedEvent);
    g_Apis.pSetCallback("CreateKeyedEvent", false, PROBE_IDS::IdCreateKeyedEvent);
    g_Apis.pSetCallback("CreateEventPair", true, PROBE_IDS::IdCreateEventPair);
    g_Apis.pSetCallback("CreateEventPair", false, PROBE_IDS::IdCreateEventPair);
    g_Apis.pSetCallback("AddAtom", true, PROBE_IDS::IdAddAtom);
    g_Apis.pSetCallback("AddAtom", false, PROBE_IDS::IdAddAtom);
    g_Apis.pSetCallback("QueryOpenSubKeys", true, PROBE_IDS::IdQueryOpenSubKeys);
    g_Apis.pSetCallback("QueryOpenSubKeys", false, PROBE_IDS::IdQueryOpenSubKeys);
    g_Apis.pSetCallback("QuerySystemTime", true, PROBE_IDS::IdQuerySystemTime);
    g_Apis.pSetCallback("QuerySystemTime", false, PROBE_IDS::IdQuerySystemTime);
    g_Apis.pSetCallback("SetEaFile", true, PROBE_IDS::IdSetEaFile);
    g_Apis.pSetCallback("SetEaFile", false, PROBE_IDS::IdSetEaFile);
    g_Apis.pSetCallback("SetInformationProcess", true, PROBE_IDS::IdSetInformationProcess);
    g_Apis.pSetCallback("SetInformationProcess", false, PROBE_IDS::IdSetInformationProcess);
    g_Apis.pSetCallback("SetValueKey", true, PROBE_IDS::IdSetValueKey);
    g_Apis.pSetCallback("SetValueKey", false, PROBE_IDS::IdSetValueKey);
    g_Apis.pSetCallback("QuerySymbolicLinkObject", true, PROBE_IDS::IdQuerySymbolicLinkObject);
    g_Apis.pSetCallback("QuerySymbolicLinkObject", false, PROBE_IDS::IdQuerySymbolicLinkObject);
    g_Apis.pSetCallback("QueryOpenSubKeysEx", true, PROBE_IDS::IdQueryOpenSubKeysEx);
    g_Apis.pSetCallback("QueryOpenSubKeysEx", false, PROBE_IDS::IdQueryOpenSubKeysEx);
    g_Apis.pSetCallback("otifyChangeKey", true, PROBE_IDS::IdotifyChangeKey);
    g_Apis.pSetCallback("otifyChangeKey", false, PROBE_IDS::IdotifyChangeKey);
    g_Apis.pSetCallback("IsProcessInJob", true, PROBE_IDS::IdIsProcessInJob);
    g_Apis.pSetCallback("IsProcessInJob", false, PROBE_IDS::IdIsProcessInJob);
    g_Apis.pSetCallback("CommitComplete", true, PROBE_IDS::IdCommitComplete);
    g_Apis.pSetCallback("CommitComplete", false, PROBE_IDS::IdCommitComplete);
    g_Apis.pSetCallback("EnumerateDriverEntries", true, PROBE_IDS::IdEnumerateDriverEntries);
    g_Apis.pSetCallback("EnumerateDriverEntries", false, PROBE_IDS::IdEnumerateDriverEntries);
    g_Apis.pSetCallback("AccessCheckByTypeResultList", true, PROBE_IDS::IdAccessCheckByTypeResultList);
    g_Apis.pSetCallback("AccessCheckByTypeResultList", false, PROBE_IDS::IdAccessCheckByTypeResultList);
    g_Apis.pSetCallback("LoadEnclaveData", true, PROBE_IDS::IdLoadEnclaveData);
    g_Apis.pSetCallback("LoadEnclaveData", false, PROBE_IDS::IdLoadEnclaveData);
    g_Apis.pSetCallback("AllocateVirtualMemoryEx", true, PROBE_IDS::IdAllocateVirtualMemoryEx);
    g_Apis.pSetCallback("AllocateVirtualMemoryEx", false, PROBE_IDS::IdAllocateVirtualMemoryEx);
    g_Apis.pSetCallback("WaitForWorkViaWorkerFactory", true, PROBE_IDS::IdWaitForWorkViaWorkerFactory);
    g_Apis.pSetCallback("WaitForWorkViaWorkerFactory", false, PROBE_IDS::IdWaitForWorkViaWorkerFactory);
    g_Apis.pSetCallback("QueryInformationResourceManager", true, PROBE_IDS::IdQueryInformationResourceManager);
    g_Apis.pSetCallback("QueryInformationResourceManager", false, PROBE_IDS::IdQueryInformationResourceManager);
    g_Apis.pSetCallback("EnumerateKey", true, PROBE_IDS::IdEnumerateKey);
    g_Apis.pSetCallback("EnumerateKey", false, PROBE_IDS::IdEnumerateKey);
    g_Apis.pSetCallback("GetMUIRegistryInfo", true, PROBE_IDS::IdGetMUIRegistryInfo);
    g_Apis.pSetCallback("GetMUIRegistryInfo", false, PROBE_IDS::IdGetMUIRegistryInfo);
    g_Apis.pSetCallback("AcceptConnectPort", true, PROBE_IDS::IdAcceptConnectPort);
    g_Apis.pSetCallback("AcceptConnectPort", false, PROBE_IDS::IdAcceptConnectPort);
    g_Apis.pSetCallback("RecoverTransactionManager", true, PROBE_IDS::IdRecoverTransactionManager);
    g_Apis.pSetCallback("RecoverTransactionManager", false, PROBE_IDS::IdRecoverTransactionManager);
    g_Apis.pSetCallback("WriteVirtualMemory", true, PROBE_IDS::IdWriteVirtualMemory);
    g_Apis.pSetCallback("WriteVirtualMemory", false, PROBE_IDS::IdWriteVirtualMemory);
    g_Apis.pSetCallback("QueryBootOptions", true, PROBE_IDS::IdQueryBootOptions);
    g_Apis.pSetCallback("QueryBootOptions", false, PROBE_IDS::IdQueryBootOptions);
    g_Apis.pSetCallback("RollbackComplete", true, PROBE_IDS::IdRollbackComplete);
    g_Apis.pSetCallback("RollbackComplete", false, PROBE_IDS::IdRollbackComplete);
    g_Apis.pSetCallback("QueryAuxiliaryCounterFrequency", true, PROBE_IDS::IdQueryAuxiliaryCounterFrequency);
    g_Apis.pSetCallback("QueryAuxiliaryCounterFrequency", false, PROBE_IDS::IdQueryAuxiliaryCounterFrequency);
    g_Apis.pSetCallback("AlpcCreatePortSection", true, PROBE_IDS::IdAlpcCreatePortSection);
    g_Apis.pSetCallback("AlpcCreatePortSection", false, PROBE_IDS::IdAlpcCreatePortSection);
    g_Apis.pSetCallback("QueryObject", true, PROBE_IDS::IdQueryObject);
    g_Apis.pSetCallback("QueryObject", false, PROBE_IDS::IdQueryObject);
    g_Apis.pSetCallback("QueryWnfStateData", true, PROBE_IDS::IdQueryWnfStateData);
    g_Apis.pSetCallback("QueryWnfStateData", false, PROBE_IDS::IdQueryWnfStateData);
    g_Apis.pSetCallback("InitiatePowerAction", true, PROBE_IDS::IdInitiatePowerAction);
    g_Apis.pSetCallback("InitiatePowerAction", false, PROBE_IDS::IdInitiatePowerAction);
    g_Apis.pSetCallback("DirectGraphicsCall", true, PROBE_IDS::IdDirectGraphicsCall);
    g_Apis.pSetCallback("DirectGraphicsCall", false, PROBE_IDS::IdDirectGraphicsCall);
    g_Apis.pSetCallback("AcquireCrossVmMutant", true, PROBE_IDS::IdAcquireCrossVmMutant);
    g_Apis.pSetCallback("AcquireCrossVmMutant", false, PROBE_IDS::IdAcquireCrossVmMutant);
    g_Apis.pSetCallback("RollbackRegistryTransaction", true, PROBE_IDS::IdRollbackRegistryTransaction);
    g_Apis.pSetCallback("RollbackRegistryTransaction", false, PROBE_IDS::IdRollbackRegistryTransaction);
    g_Apis.pSetCallback("AlertResumeThread", true, PROBE_IDS::IdAlertResumeThread);
    g_Apis.pSetCallback("AlertResumeThread", false, PROBE_IDS::IdAlertResumeThread);
    g_Apis.pSetCallback("PssCaptureVaSpaceBulk", true, PROBE_IDS::IdPssCaptureVaSpaceBulk);
    g_Apis.pSetCallback("PssCaptureVaSpaceBulk", false, PROBE_IDS::IdPssCaptureVaSpaceBulk);
    g_Apis.pSetCallback("CreateToken", true, PROBE_IDS::IdCreateToken);
    g_Apis.pSetCallback("CreateToken", false, PROBE_IDS::IdCreateToken);
    g_Apis.pSetCallback("PrepareEnlistment", true, PROBE_IDS::IdPrepareEnlistment);
    g_Apis.pSetCallback("PrepareEnlistment", false, PROBE_IDS::IdPrepareEnlistment);
    g_Apis.pSetCallback("FlushWriteBuffer", true, PROBE_IDS::IdFlushWriteBuffer);
    g_Apis.pSetCallback("FlushWriteBuffer", false, PROBE_IDS::IdFlushWriteBuffer);
    g_Apis.pSetCallback("CommitRegistryTransaction", true, PROBE_IDS::IdCommitRegistryTransaction);
    g_Apis.pSetCallback("CommitRegistryTransaction", false, PROBE_IDS::IdCommitRegistryTransaction);
    g_Apis.pSetCallback("AccessCheckByType", true, PROBE_IDS::IdAccessCheckByType);
    g_Apis.pSetCallback("AccessCheckByType", false, PROBE_IDS::IdAccessCheckByType);
    g_Apis.pSetCallback("OpenThread", true, PROBE_IDS::IdOpenThread);
    g_Apis.pSetCallback("OpenThread", false, PROBE_IDS::IdOpenThread);
    g_Apis.pSetCallback("AccessCheckAndAuditAlarm", true, PROBE_IDS::IdAccessCheckAndAuditAlarm);
    g_Apis.pSetCallback("AccessCheckAndAuditAlarm", false, PROBE_IDS::IdAccessCheckAndAuditAlarm);
    g_Apis.pSetCallback("OpenThreadTokenEx", true, PROBE_IDS::IdOpenThreadTokenEx);
    g_Apis.pSetCallback("OpenThreadTokenEx", false, PROBE_IDS::IdOpenThreadTokenEx);
    g_Apis.pSetCallback("WriteRequestData", true, PROBE_IDS::IdWriteRequestData);
    g_Apis.pSetCallback("WriteRequestData", false, PROBE_IDS::IdWriteRequestData);
    g_Apis.pSetCallback("CreateWorkerFactory", true, PROBE_IDS::IdCreateWorkerFactory);
    g_Apis.pSetCallback("CreateWorkerFactory", false, PROBE_IDS::IdCreateWorkerFactory);
    g_Apis.pSetCallback("OpenPartition", true, PROBE_IDS::IdOpenPartition);
    g_Apis.pSetCallback("OpenPartition", false, PROBE_IDS::IdOpenPartition);
    g_Apis.pSetCallback("SetSystemInformation", true, PROBE_IDS::IdSetSystemInformation);
    g_Apis.pSetCallback("SetSystemInformation", false, PROBE_IDS::IdSetSystemInformation);
    g_Apis.pSetCallback("EnumerateSystemEnvironmentValuesEx", true, PROBE_IDS::IdEnumerateSystemEnvironmentValuesEx);
    g_Apis.pSetCallback("EnumerateSystemEnvironmentValuesEx", false, PROBE_IDS::IdEnumerateSystemEnvironmentValuesEx);
    g_Apis.pSetCallback("CreateWnfStateName", true, PROBE_IDS::IdCreateWnfStateName);
    g_Apis.pSetCallback("CreateWnfStateName", false, PROBE_IDS::IdCreateWnfStateName);
    g_Apis.pSetCallback("QueryInformationJobObject", true, PROBE_IDS::IdQueryInformationJobObject);
    g_Apis.pSetCallback("QueryInformationJobObject", false, PROBE_IDS::IdQueryInformationJobObject);
    g_Apis.pSetCallback("PrivilegedServiceAuditAlarm", true, PROBE_IDS::IdPrivilegedServiceAuditAlarm);
    g_Apis.pSetCallback("PrivilegedServiceAuditAlarm", false, PROBE_IDS::IdPrivilegedServiceAuditAlarm);
    g_Apis.pSetCallback("EnableLastKnownGood", true, PROBE_IDS::IdEnableLastKnownGood);
    g_Apis.pSetCallback("EnableLastKnownGood", false, PROBE_IDS::IdEnableLastKnownGood);
    g_Apis.pSetCallback("otifyChangeDirectoryFileEx", true, PROBE_IDS::IdotifyChangeDirectoryFileEx);
    g_Apis.pSetCallback("otifyChangeDirectoryFileEx", false, PROBE_IDS::IdotifyChangeDirectoryFileEx);
    g_Apis.pSetCallback("CreateWaitablePort", true, PROBE_IDS::IdCreateWaitablePort);
    g_Apis.pSetCallback("CreateWaitablePort", false, PROBE_IDS::IdCreateWaitablePort);
    g_Apis.pSetCallback("WaitForAlertByThreadId", true, PROBE_IDS::IdWaitForAlertByThreadId);
    g_Apis.pSetCallback("WaitForAlertByThreadId", false, PROBE_IDS::IdWaitForAlertByThreadId);
    g_Apis.pSetCallback("GetNextProcess", true, PROBE_IDS::IdGetNextProcess);
    g_Apis.pSetCallback("GetNextProcess", false, PROBE_IDS::IdGetNextProcess);
    g_Apis.pSetCallback("OpenKeyedEvent", true, PROBE_IDS::IdOpenKeyedEvent);
    g_Apis.pSetCallback("OpenKeyedEvent", false, PROBE_IDS::IdOpenKeyedEvent);
    g_Apis.pSetCallback("DeleteBootEntry", true, PROBE_IDS::IdDeleteBootEntry);
    g_Apis.pSetCallback("DeleteBootEntry", false, PROBE_IDS::IdDeleteBootEntry);
    g_Apis.pSetCallback("FilterToken", true, PROBE_IDS::IdFilterToken);
    g_Apis.pSetCallback("FilterToken", false, PROBE_IDS::IdFilterToken);
    g_Apis.pSetCallback("CompressKey", true, PROBE_IDS::IdCompressKey);
    g_Apis.pSetCallback("CompressKey", false, PROBE_IDS::IdCompressKey);
    g_Apis.pSetCallback("ModifyBootEntry", true, PROBE_IDS::IdModifyBootEntry);
    g_Apis.pSetCallback("ModifyBootEntry", false, PROBE_IDS::IdModifyBootEntry);
    g_Apis.pSetCallback("SetInformationTransaction", true, PROBE_IDS::IdSetInformationTransaction);
    g_Apis.pSetCallback("SetInformationTransaction", false, PROBE_IDS::IdSetInformationTransaction);
    g_Apis.pSetCallback("PlugPlayControl", true, PROBE_IDS::IdPlugPlayControl);
    g_Apis.pSetCallback("PlugPlayControl", false, PROBE_IDS::IdPlugPlayControl);
    g_Apis.pSetCallback("OpenDirectoryObject", true, PROBE_IDS::IdOpenDirectoryObject);
    g_Apis.pSetCallback("OpenDirectoryObject", false, PROBE_IDS::IdOpenDirectoryObject);
    g_Apis.pSetCallback("Continue", true, PROBE_IDS::IdContinue);
    g_Apis.pSetCallback("Continue", false, PROBE_IDS::IdContinue);
    g_Apis.pSetCallback("PrivilegeObjectAuditAlarm", true, PROBE_IDS::IdPrivilegeObjectAuditAlarm);
    g_Apis.pSetCallback("PrivilegeObjectAuditAlarm", false, PROBE_IDS::IdPrivilegeObjectAuditAlarm);
    g_Apis.pSetCallback("QueryKey", true, PROBE_IDS::IdQueryKey);
    g_Apis.pSetCallback("QueryKey", false, PROBE_IDS::IdQueryKey);
    g_Apis.pSetCallback("FilterBootOption", true, PROBE_IDS::IdFilterBootOption);
    g_Apis.pSetCallback("FilterBootOption", false, PROBE_IDS::IdFilterBootOption);
    g_Apis.pSetCallback("YieldExecution", true, PROBE_IDS::IdYieldExecution);
    g_Apis.pSetCallback("YieldExecution", false, PROBE_IDS::IdYieldExecution);
    g_Apis.pSetCallback("ResumeThread", true, PROBE_IDS::IdResumeThread);
    g_Apis.pSetCallback("ResumeThread", false, PROBE_IDS::IdResumeThread);
    g_Apis.pSetCallback("AddBootEntry", true, PROBE_IDS::IdAddBootEntry);
    g_Apis.pSetCallback("AddBootEntry", false, PROBE_IDS::IdAddBootEntry);
    g_Apis.pSetCallback("GetCurrentProcessorNumberEx", true, PROBE_IDS::IdGetCurrentProcessorNumberEx);
    g_Apis.pSetCallback("GetCurrentProcessorNumberEx", false, PROBE_IDS::IdGetCurrentProcessorNumberEx);
    g_Apis.pSetCallback("CreateLowBoxToken", true, PROBE_IDS::IdCreateLowBoxToken);
    g_Apis.pSetCallback("CreateLowBoxToken", false, PROBE_IDS::IdCreateLowBoxToken);
    g_Apis.pSetCallback("FlushBuffersFile", true, PROBE_IDS::IdFlushBuffersFile);
    g_Apis.pSetCallback("FlushBuffersFile", false, PROBE_IDS::IdFlushBuffersFile);
    g_Apis.pSetCallback("DelayExecution", true, PROBE_IDS::IdDelayExecution);
    g_Apis.pSetCallback("DelayExecution", false, PROBE_IDS::IdDelayExecution);
    g_Apis.pSetCallback("OpenKey", true, PROBE_IDS::IdOpenKey);
    g_Apis.pSetCallback("OpenKey", false, PROBE_IDS::IdOpenKey);
    g_Apis.pSetCallback("StopProfile", true, PROBE_IDS::IdStopProfile);
    g_Apis.pSetCallback("StopProfile", false, PROBE_IDS::IdStopProfile);
    g_Apis.pSetCallback("SetEvent", true, PROBE_IDS::IdSetEvent);
    g_Apis.pSetCallback("SetEvent", false, PROBE_IDS::IdSetEvent);
    g_Apis.pSetCallback("RestoreKey", true, PROBE_IDS::IdRestoreKey);
    g_Apis.pSetCallback("RestoreKey", false, PROBE_IDS::IdRestoreKey);
    g_Apis.pSetCallback("ExtendSection", true, PROBE_IDS::IdExtendSection);
    g_Apis.pSetCallback("ExtendSection", false, PROBE_IDS::IdExtendSection);
    g_Apis.pSetCallback("InitializeNlsFiles", true, PROBE_IDS::IdInitializeNlsFiles);
    g_Apis.pSetCallback("InitializeNlsFiles", false, PROBE_IDS::IdInitializeNlsFiles);
    g_Apis.pSetCallback("FindAtom", true, PROBE_IDS::IdFindAtom);
    g_Apis.pSetCallback("FindAtom", false, PROBE_IDS::IdFindAtom);
    g_Apis.pSetCallback("DisplayString", true, PROBE_IDS::IdDisplayString);
    g_Apis.pSetCallback("DisplayString", false, PROBE_IDS::IdDisplayString);
    g_Apis.pSetCallback("LoadDriver", true, PROBE_IDS::IdLoadDriver);
    g_Apis.pSetCallback("LoadDriver", false, PROBE_IDS::IdLoadDriver);
    g_Apis.pSetCallback("QueryWnfStateNameInformation", true, PROBE_IDS::IdQueryWnfStateNameInformation);
    g_Apis.pSetCallback("QueryWnfStateNameInformation", false, PROBE_IDS::IdQueryWnfStateNameInformation);
    g_Apis.pSetCallback("CreateMutant", true, PROBE_IDS::IdCreateMutant);
    g_Apis.pSetCallback("CreateMutant", false, PROBE_IDS::IdCreateMutant);
    g_Apis.pSetCallback("FlushKey", true, PROBE_IDS::IdFlushKey);
    g_Apis.pSetCallback("FlushKey", false, PROBE_IDS::IdFlushKey);
    g_Apis.pSetCallback("DuplicateObject", true, PROBE_IDS::IdDuplicateObject);
    g_Apis.pSetCallback("DuplicateObject", false, PROBE_IDS::IdDuplicateObject);
    g_Apis.pSetCallback("CancelTimer2", true, PROBE_IDS::IdCancelTimer2);
    g_Apis.pSetCallback("CancelTimer2", false, PROBE_IDS::IdCancelTimer2);
    g_Apis.pSetCallback("QueryAttributesFile", true, PROBE_IDS::IdQueryAttributesFile);
    g_Apis.pSetCallback("QueryAttributesFile", false, PROBE_IDS::IdQueryAttributesFile);
    g_Apis.pSetCallback("CompareSigningLevels", true, PROBE_IDS::IdCompareSigningLevels);
    g_Apis.pSetCallback("CompareSigningLevels", false, PROBE_IDS::IdCompareSigningLevels);
    g_Apis.pSetCallback("AccessCheckByTypeResultListAndAuditAlarmByHandle", true, PROBE_IDS::IdAccessCheckByTypeResultListAndAuditAlarmByHandle);
    g_Apis.pSetCallback("AccessCheckByTypeResultListAndAuditAlarmByHandle", false, PROBE_IDS::IdAccessCheckByTypeResultListAndAuditAlarmByHandle);
    g_Apis.pSetCallback("DeleteValueKey", true, PROBE_IDS::IdDeleteValueKey);
    g_Apis.pSetCallback("DeleteValueKey", false, PROBE_IDS::IdDeleteValueKey);
    g_Apis.pSetCallback("SetDebugFilterState", true, PROBE_IDS::IdSetDebugFilterState);
    g_Apis.pSetCallback("SetDebugFilterState", false, PROBE_IDS::IdSetDebugFilterState);
    g_Apis.pSetCallback("PulseEvent", true, PROBE_IDS::IdPulseEvent);
    g_Apis.pSetCallback("PulseEvent", false, PROBE_IDS::IdPulseEvent);
    g_Apis.pSetCallback("AllocateReserveObject", true, PROBE_IDS::IdAllocateReserveObject);
    g_Apis.pSetCallback("AllocateReserveObject", false, PROBE_IDS::IdAllocateReserveObject);
    g_Apis.pSetCallback("AlpcDisconnectPort", true, PROBE_IDS::IdAlpcDisconnectPort);
    g_Apis.pSetCallback("AlpcDisconnectPort", false, PROBE_IDS::IdAlpcDisconnectPort);
    g_Apis.pSetCallback("QueryTimerResolution", true, PROBE_IDS::IdQueryTimerResolution);
    g_Apis.pSetCallback("QueryTimerResolution", false, PROBE_IDS::IdQueryTimerResolution);
    g_Apis.pSetCallback("DeleteKey", true, PROBE_IDS::IdDeleteKey);
    g_Apis.pSetCallback("DeleteKey", false, PROBE_IDS::IdDeleteKey);
    g_Apis.pSetCallback("CreateFile", true, PROBE_IDS::IdCreateFile);
    g_Apis.pSetCallback("CreateFile", false, PROBE_IDS::IdCreateFile);
    g_Apis.pSetCallback("ReplyPort", true, PROBE_IDS::IdReplyPort);
    g_Apis.pSetCallback("ReplyPort", false, PROBE_IDS::IdReplyPort);
    g_Apis.pSetCallback("GetNlsSectionPtr", true, PROBE_IDS::IdGetNlsSectionPtr);
    g_Apis.pSetCallback("GetNlsSectionPtr", false, PROBE_IDS::IdGetNlsSectionPtr);
    g_Apis.pSetCallback("QueryInformationProcess", true, PROBE_IDS::IdQueryInformationProcess);
    g_Apis.pSetCallback("QueryInformationProcess", false, PROBE_IDS::IdQueryInformationProcess);
    g_Apis.pSetCallback("ReplyWaitReceivePortEx", true, PROBE_IDS::IdReplyWaitReceivePortEx);
    g_Apis.pSetCallback("ReplyWaitReceivePortEx", false, PROBE_IDS::IdReplyWaitReceivePortEx);
    g_Apis.pSetCallback("UmsThreadYield", true, PROBE_IDS::IdUmsThreadYield);
    g_Apis.pSetCallback("UmsThreadYield", false, PROBE_IDS::IdUmsThreadYield);
    g_Apis.pSetCallback("ManagePartition", true, PROBE_IDS::IdManagePartition);
    g_Apis.pSetCallback("ManagePartition", false, PROBE_IDS::IdManagePartition);
    g_Apis.pSetCallback("AdjustPrivilegesToken", true, PROBE_IDS::IdAdjustPrivilegesToken);
    g_Apis.pSetCallback("AdjustPrivilegesToken", false, PROBE_IDS::IdAdjustPrivilegesToken);
    g_Apis.pSetCallback("CreateCrossVmMutant", true, PROBE_IDS::IdCreateCrossVmMutant);
    g_Apis.pSetCallback("CreateCrossVmMutant", false, PROBE_IDS::IdCreateCrossVmMutant);
    g_Apis.pSetCallback("CreateDirectoryObject", true, PROBE_IDS::IdCreateDirectoryObject);
    g_Apis.pSetCallback("CreateDirectoryObject", false, PROBE_IDS::IdCreateDirectoryObject);
    g_Apis.pSetCallback("OpenFile", true, PROBE_IDS::IdOpenFile);
    g_Apis.pSetCallback("OpenFile", false, PROBE_IDS::IdOpenFile);
    g_Apis.pSetCallback("SetInformationVirtualMemory", true, PROBE_IDS::IdSetInformationVirtualMemory);
    g_Apis.pSetCallback("SetInformationVirtualMemory", false, PROBE_IDS::IdSetInformationVirtualMemory);
    g_Apis.pSetCallback("TerminateEnclave", true, PROBE_IDS::IdTerminateEnclave);
    g_Apis.pSetCallback("TerminateEnclave", false, PROBE_IDS::IdTerminateEnclave);
    g_Apis.pSetCallback("SuspendProcess", true, PROBE_IDS::IdSuspendProcess);
    g_Apis.pSetCallback("SuspendProcess", false, PROBE_IDS::IdSuspendProcess);
    g_Apis.pSetCallback("ReplyWaitReplyPort", true, PROBE_IDS::IdReplyWaitReplyPort);
    g_Apis.pSetCallback("ReplyWaitReplyPort", false, PROBE_IDS::IdReplyWaitReplyPort);
    g_Apis.pSetCallback("OpenTransactionManager", true, PROBE_IDS::IdOpenTransactionManager);
    g_Apis.pSetCallback("OpenTransactionManager", false, PROBE_IDS::IdOpenTransactionManager);
    g_Apis.pSetCallback("CreateSemaphore", true, PROBE_IDS::IdCreateSemaphore);
    g_Apis.pSetCallback("CreateSemaphore", false, PROBE_IDS::IdCreateSemaphore);
    g_Apis.pSetCallback("UnmapViewOfSectionEx", true, PROBE_IDS::IdUnmapViewOfSectionEx);
    g_Apis.pSetCallback("UnmapViewOfSectionEx", false, PROBE_IDS::IdUnmapViewOfSectionEx);
    g_Apis.pSetCallback("MapViewOfSection", true, PROBE_IDS::IdMapViewOfSection);
    g_Apis.pSetCallback("MapViewOfSection", false, PROBE_IDS::IdMapViewOfSection);
    g_Apis.pSetCallback("DisableLastKnownGood", true, PROBE_IDS::IdDisableLastKnownGood);
    g_Apis.pSetCallback("DisableLastKnownGood", false, PROBE_IDS::IdDisableLastKnownGood);
    g_Apis.pSetCallback("GetNextThread", true, PROBE_IDS::IdGetNextThread);
    g_Apis.pSetCallback("GetNextThread", false, PROBE_IDS::IdGetNextThread);
    g_Apis.pSetCallback("MakeTemporaryObject", true, PROBE_IDS::IdMakeTemporaryObject);
    g_Apis.pSetCallback("MakeTemporaryObject", false, PROBE_IDS::IdMakeTemporaryObject);
    g_Apis.pSetCallback("SetInformationFile", true, PROBE_IDS::IdSetInformationFile);
    g_Apis.pSetCallback("SetInformationFile", false, PROBE_IDS::IdSetInformationFile);
    g_Apis.pSetCallback("CreateTransactionManager", true, PROBE_IDS::IdCreateTransactionManager);
    g_Apis.pSetCallback("CreateTransactionManager", false, PROBE_IDS::IdCreateTransactionManager);
    g_Apis.pSetCallback("WriteFileGather", true, PROBE_IDS::IdWriteFileGather);
    g_Apis.pSetCallback("WriteFileGather", false, PROBE_IDS::IdWriteFileGather);
    g_Apis.pSetCallback("QueryInformationTransaction", true, PROBE_IDS::IdQueryInformationTransaction);
    g_Apis.pSetCallback("QueryInformationTransaction", false, PROBE_IDS::IdQueryInformationTransaction);
    g_Apis.pSetCallback("FlushVirtualMemory", true, PROBE_IDS::IdFlushVirtualMemory);
    g_Apis.pSetCallback("FlushVirtualMemory", false, PROBE_IDS::IdFlushVirtualMemory);
    g_Apis.pSetCallback("QueryQuotaInformationFile", true, PROBE_IDS::IdQueryQuotaInformationFile);
    g_Apis.pSetCallback("QueryQuotaInformationFile", false, PROBE_IDS::IdQueryQuotaInformationFile);
    g_Apis.pSetCallback("SetVolumeInformationFile", true, PROBE_IDS::IdSetVolumeInformationFile);
    g_Apis.pSetCallback("SetVolumeInformationFile", false, PROBE_IDS::IdSetVolumeInformationFile);
    g_Apis.pSetCallback("QueryInformationEnlistment", true, PROBE_IDS::IdQueryInformationEnlistment);
    g_Apis.pSetCallback("QueryInformationEnlistment", false, PROBE_IDS::IdQueryInformationEnlistment);
    g_Apis.pSetCallback("CreateIoCompletion", true, PROBE_IDS::IdCreateIoCompletion);
    g_Apis.pSetCallback("CreateIoCompletion", false, PROBE_IDS::IdCreateIoCompletion);
    g_Apis.pSetCallback("UnloadKeyEx", true, PROBE_IDS::IdUnloadKeyEx);
    g_Apis.pSetCallback("UnloadKeyEx", false, PROBE_IDS::IdUnloadKeyEx);
    g_Apis.pSetCallback("QueryEaFile", true, PROBE_IDS::IdQueryEaFile);
    g_Apis.pSetCallback("QueryEaFile", false, PROBE_IDS::IdQueryEaFile);
    g_Apis.pSetCallback("QueryDirectoryObject", true, PROBE_IDS::IdQueryDirectoryObject);
    g_Apis.pSetCallback("QueryDirectoryObject", false, PROBE_IDS::IdQueryDirectoryObject);
    g_Apis.pSetCallback("AddAtomEx", true, PROBE_IDS::IdAddAtomEx);
    g_Apis.pSetCallback("AddAtomEx", false, PROBE_IDS::IdAddAtomEx);
    g_Apis.pSetCallback("SinglePhaseReject", true, PROBE_IDS::IdSinglePhaseReject);
    g_Apis.pSetCallback("SinglePhaseReject", false, PROBE_IDS::IdSinglePhaseReject);
    g_Apis.pSetCallback("DeleteWnfStateName", true, PROBE_IDS::IdDeleteWnfStateName);
    g_Apis.pSetCallback("DeleteWnfStateName", false, PROBE_IDS::IdDeleteWnfStateName);
    g_Apis.pSetCallback("SetSystemEnvironmentValueEx", true, PROBE_IDS::IdSetSystemEnvironmentValueEx);
    g_Apis.pSetCallback("SetSystemEnvironmentValueEx", false, PROBE_IDS::IdSetSystemEnvironmentValueEx);
    g_Apis.pSetCallback("ContinueEx", true, PROBE_IDS::IdContinueEx);
    g_Apis.pSetCallback("ContinueEx", false, PROBE_IDS::IdContinueEx);
    g_Apis.pSetCallback("UnloadDriver", true, PROBE_IDS::IdUnloadDriver);
    g_Apis.pSetCallback("UnloadDriver", false, PROBE_IDS::IdUnloadDriver);
    g_Apis.pSetCallback("CallEnclave", true, PROBE_IDS::IdCallEnclave);
    g_Apis.pSetCallback("CallEnclave", false, PROBE_IDS::IdCallEnclave);
    g_Apis.pSetCallback("CancelIoFileEx", true, PROBE_IDS::IdCancelIoFileEx);
    g_Apis.pSetCallback("CancelIoFileEx", false, PROBE_IDS::IdCancelIoFileEx);
    g_Apis.pSetCallback("SetTimer", true, PROBE_IDS::IdSetTimer);
    g_Apis.pSetCallback("SetTimer", false, PROBE_IDS::IdSetTimer);
    g_Apis.pSetCallback("QuerySystemEnvironmentValue", true, PROBE_IDS::IdQuerySystemEnvironmentValue);
    g_Apis.pSetCallback("QuerySystemEnvironmentValue", false, PROBE_IDS::IdQuerySystemEnvironmentValue);
    g_Apis.pSetCallback("OpenThreadToken", true, PROBE_IDS::IdOpenThreadToken);
    g_Apis.pSetCallback("OpenThreadToken", false, PROBE_IDS::IdOpenThreadToken);
    g_Apis.pSetCallback("MapUserPhysicalPagesScatter", true, PROBE_IDS::IdMapUserPhysicalPagesScatter);
    g_Apis.pSetCallback("MapUserPhysicalPagesScatter", false, PROBE_IDS::IdMapUserPhysicalPagesScatter);
    g_Apis.pSetCallback("CreateResourceManager", true, PROBE_IDS::IdCreateResourceManager);
    g_Apis.pSetCallback("CreateResourceManager", false, PROBE_IDS::IdCreateResourceManager);
    g_Apis.pSetCallback("UnlockVirtualMemory", true, PROBE_IDS::IdUnlockVirtualMemory);
    g_Apis.pSetCallback("UnlockVirtualMemory", false, PROBE_IDS::IdUnlockVirtualMemory);
    g_Apis.pSetCallback("QueryInformationPort", true, PROBE_IDS::IdQueryInformationPort);
    g_Apis.pSetCallback("QueryInformationPort", false, PROBE_IDS::IdQueryInformationPort);
    g_Apis.pSetCallback("SetLowEventPair", true, PROBE_IDS::IdSetLowEventPair);
    g_Apis.pSetCallback("SetLowEventPair", false, PROBE_IDS::IdSetLowEventPair);
    g_Apis.pSetCallback("SetInformationKey", true, PROBE_IDS::IdSetInformationKey);
    g_Apis.pSetCallback("SetInformationKey", false, PROBE_IDS::IdSetInformationKey);
    g_Apis.pSetCallback("QuerySecurityPolicy", true, PROBE_IDS::IdQuerySecurityPolicy);
    g_Apis.pSetCallback("QuerySecurityPolicy", false, PROBE_IDS::IdQuerySecurityPolicy);
    g_Apis.pSetCallback("OpenProcessToken", true, PROBE_IDS::IdOpenProcessToken);
    g_Apis.pSetCallback("OpenProcessToken", false, PROBE_IDS::IdOpenProcessToken);
    g_Apis.pSetCallback("QueryVolumeInformationFile", true, PROBE_IDS::IdQueryVolumeInformationFile);
    g_Apis.pSetCallback("QueryVolumeInformationFile", false, PROBE_IDS::IdQueryVolumeInformationFile);
    g_Apis.pSetCallback("OpenTimer", true, PROBE_IDS::IdOpenTimer);
    g_Apis.pSetCallback("OpenTimer", false, PROBE_IDS::IdOpenTimer);
    g_Apis.pSetCallback("MapUserPhysicalPages", true, PROBE_IDS::IdMapUserPhysicalPages);
    g_Apis.pSetCallback("MapUserPhysicalPages", false, PROBE_IDS::IdMapUserPhysicalPages);
    g_Apis.pSetCallback("LoadKey", true, PROBE_IDS::IdLoadKey);
    g_Apis.pSetCallback("LoadKey", false, PROBE_IDS::IdLoadKey);
    g_Apis.pSetCallback("CreateWaitCompletionPacket", true, PROBE_IDS::IdCreateWaitCompletionPacket);
    g_Apis.pSetCallback("CreateWaitCompletionPacket", false, PROBE_IDS::IdCreateWaitCompletionPacket);
    g_Apis.pSetCallback("ReleaseWorkerFactoryWorker", true, PROBE_IDS::IdReleaseWorkerFactoryWorker);
    g_Apis.pSetCallback("ReleaseWorkerFactoryWorker", false, PROBE_IDS::IdReleaseWorkerFactoryWorker);
    g_Apis.pSetCallback("PrePrepareComplete", true, PROBE_IDS::IdPrePrepareComplete);
    g_Apis.pSetCallback("PrePrepareComplete", false, PROBE_IDS::IdPrePrepareComplete);
    g_Apis.pSetCallback("ReadVirtualMemory", true, PROBE_IDS::IdReadVirtualMemory);
    g_Apis.pSetCallback("ReadVirtualMemory", false, PROBE_IDS::IdReadVirtualMemory);
    g_Apis.pSetCallback("FreeVirtualMemory", true, PROBE_IDS::IdFreeVirtualMemory);
    g_Apis.pSetCallback("FreeVirtualMemory", false, PROBE_IDS::IdFreeVirtualMemory);
    g_Apis.pSetCallback("SetDriverEntryOrder", true, PROBE_IDS::IdSetDriverEntryOrder);
    g_Apis.pSetCallback("SetDriverEntryOrder", false, PROBE_IDS::IdSetDriverEntryOrder);
    g_Apis.pSetCallback("ReadFile", true, PROBE_IDS::IdReadFile);
    g_Apis.pSetCallback("ReadFile", false, PROBE_IDS::IdReadFile);
    g_Apis.pSetCallback("TraceControl", true, PROBE_IDS::IdTraceControl);
    g_Apis.pSetCallback("TraceControl", false, PROBE_IDS::IdTraceControl);
    g_Apis.pSetCallback("OpenProcessTokenEx", true, PROBE_IDS::IdOpenProcessTokenEx);
    g_Apis.pSetCallback("OpenProcessTokenEx", false, PROBE_IDS::IdOpenProcessTokenEx);
    g_Apis.pSetCallback("SecureConnectPort", true, PROBE_IDS::IdSecureConnectPort);
    g_Apis.pSetCallback("SecureConnectPort", false, PROBE_IDS::IdSecureConnectPort);
    g_Apis.pSetCallback("SaveKey", true, PROBE_IDS::IdSaveKey);
    g_Apis.pSetCallback("SaveKey", false, PROBE_IDS::IdSaveKey);
    g_Apis.pSetCallback("SetDefaultHardErrorPort", true, PROBE_IDS::IdSetDefaultHardErrorPort);
    g_Apis.pSetCallback("SetDefaultHardErrorPort", false, PROBE_IDS::IdSetDefaultHardErrorPort);
    g_Apis.pSetCallback("CreateEnclave", true, PROBE_IDS::IdCreateEnclave);
    g_Apis.pSetCallback("CreateEnclave", false, PROBE_IDS::IdCreateEnclave);
    g_Apis.pSetCallback("OpenPrivateNamespace", true, PROBE_IDS::IdOpenPrivateNamespace);
    g_Apis.pSetCallback("OpenPrivateNamespace", false, PROBE_IDS::IdOpenPrivateNamespace);
    g_Apis.pSetCallback("SetLdtEntries", true, PROBE_IDS::IdSetLdtEntries);
    g_Apis.pSetCallback("SetLdtEntries", false, PROBE_IDS::IdSetLdtEntries);
    g_Apis.pSetCallback("ResetWriteWatch", true, PROBE_IDS::IdResetWriteWatch);
    g_Apis.pSetCallback("ResetWriteWatch", false, PROBE_IDS::IdResetWriteWatch);
    g_Apis.pSetCallback("RenameKey", true, PROBE_IDS::IdRenameKey);
    g_Apis.pSetCallback("RenameKey", false, PROBE_IDS::IdRenameKey);
    g_Apis.pSetCallback("RevertContainerImpersonation", true, PROBE_IDS::IdRevertContainerImpersonation);
    g_Apis.pSetCallback("RevertContainerImpersonation", false, PROBE_IDS::IdRevertContainerImpersonation);
    g_Apis.pSetCallback("AlpcCreateSectionView", true, PROBE_IDS::IdAlpcCreateSectionView);
    g_Apis.pSetCallback("AlpcCreateSectionView", false, PROBE_IDS::IdAlpcCreateSectionView);
    g_Apis.pSetCallback("CreateCrossVmEvent", true, PROBE_IDS::IdCreateCrossVmEvent);
    g_Apis.pSetCallback("CreateCrossVmEvent", false, PROBE_IDS::IdCreateCrossVmEvent);
    g_Apis.pSetCallback("ImpersonateThread", true, PROBE_IDS::IdImpersonateThread);
    g_Apis.pSetCallback("ImpersonateThread", false, PROBE_IDS::IdImpersonateThread);
    g_Apis.pSetCallback("SetIRTimer", true, PROBE_IDS::IdSetIRTimer);
    g_Apis.pSetCallback("SetIRTimer", false, PROBE_IDS::IdSetIRTimer);
    g_Apis.pSetCallback("CreateDirectoryObjectEx", true, PROBE_IDS::IdCreateDirectoryObjectEx);
    g_Apis.pSetCallback("CreateDirectoryObjectEx", false, PROBE_IDS::IdCreateDirectoryObjectEx);
    g_Apis.pSetCallback("AcquireProcessActivityReference", true, PROBE_IDS::IdAcquireProcessActivityReference);
    g_Apis.pSetCallback("AcquireProcessActivityReference", false, PROBE_IDS::IdAcquireProcessActivityReference);
    g_Apis.pSetCallback("ReplaceKey", true, PROBE_IDS::IdReplaceKey);
    g_Apis.pSetCallback("ReplaceKey", false, PROBE_IDS::IdReplaceKey);
    g_Apis.pSetCallback("StartProfile", true, PROBE_IDS::IdStartProfile);
    g_Apis.pSetCallback("StartProfile", false, PROBE_IDS::IdStartProfile);
    g_Apis.pSetCallback("QueryBootEntryOrder", true, PROBE_IDS::IdQueryBootEntryOrder);
    g_Apis.pSetCallback("QueryBootEntryOrder", false, PROBE_IDS::IdQueryBootEntryOrder);
    g_Apis.pSetCallback("LockRegistryKey", true, PROBE_IDS::IdLockRegistryKey);
    g_Apis.pSetCallback("LockRegistryKey", false, PROBE_IDS::IdLockRegistryKey);
    g_Apis.pSetCallback("ImpersonateClientOfPort", true, PROBE_IDS::IdImpersonateClientOfPort);
    g_Apis.pSetCallback("ImpersonateClientOfPort", false, PROBE_IDS::IdImpersonateClientOfPort);
    g_Apis.pSetCallback("QueryEvent", true, PROBE_IDS::IdQueryEvent);
    g_Apis.pSetCallback("QueryEvent", false, PROBE_IDS::IdQueryEvent);
    g_Apis.pSetCallback("FsControlFile", true, PROBE_IDS::IdFsControlFile);
    g_Apis.pSetCallback("FsControlFile", false, PROBE_IDS::IdFsControlFile);
    g_Apis.pSetCallback("OpenProcess", true, PROBE_IDS::IdOpenProcess);
    g_Apis.pSetCallback("OpenProcess", false, PROBE_IDS::IdOpenProcess);
    g_Apis.pSetCallback("SetIoCompletion", true, PROBE_IDS::IdSetIoCompletion);
    g_Apis.pSetCallback("SetIoCompletion", false, PROBE_IDS::IdSetIoCompletion);
    g_Apis.pSetCallback("ConnectPort", true, PROBE_IDS::IdConnectPort);
    g_Apis.pSetCallback("ConnectPort", false, PROBE_IDS::IdConnectPort);
    g_Apis.pSetCallback("CloseObjectAuditAlarm", true, PROBE_IDS::IdCloseObjectAuditAlarm);
    g_Apis.pSetCallback("CloseObjectAuditAlarm", false, PROBE_IDS::IdCloseObjectAuditAlarm);
    g_Apis.pSetCallback("RequestWaitReplyPort", true, PROBE_IDS::IdRequestWaitReplyPort);
    g_Apis.pSetCallback("RequestWaitReplyPort", false, PROBE_IDS::IdRequestWaitReplyPort);
    g_Apis.pSetCallback("SetInformationObject", true, PROBE_IDS::IdSetInformationObject);
    g_Apis.pSetCallback("SetInformationObject", false, PROBE_IDS::IdSetInformationObject);
    g_Apis.pSetCallback("PrivilegeCheck", true, PROBE_IDS::IdPrivilegeCheck);
    g_Apis.pSetCallback("PrivilegeCheck", false, PROBE_IDS::IdPrivilegeCheck);
    g_Apis.pSetCallback("CallbackReturn", true, PROBE_IDS::IdCallbackReturn);
    g_Apis.pSetCallback("CallbackReturn", false, PROBE_IDS::IdCallbackReturn);
    g_Apis.pSetCallback("SetInformationToken", true, PROBE_IDS::IdSetInformationToken);
    g_Apis.pSetCallback("SetInformationToken", false, PROBE_IDS::IdSetInformationToken);
    g_Apis.pSetCallback("SetUuidSeed", true, PROBE_IDS::IdSetUuidSeed);
    g_Apis.pSetCallback("SetUuidSeed", false, PROBE_IDS::IdSetUuidSeed);
    g_Apis.pSetCallback("OpenKeyTransacted", true, PROBE_IDS::IdOpenKeyTransacted);
    g_Apis.pSetCallback("OpenKeyTransacted", false, PROBE_IDS::IdOpenKeyTransacted);
    g_Apis.pSetCallback("AlpcDeleteSecurityContext", true, PROBE_IDS::IdAlpcDeleteSecurityContext);
    g_Apis.pSetCallback("AlpcDeleteSecurityContext", false, PROBE_IDS::IdAlpcDeleteSecurityContext);
    g_Apis.pSetCallback("SetBootOptions", true, PROBE_IDS::IdSetBootOptions);
    g_Apis.pSetCallback("SetBootOptions", false, PROBE_IDS::IdSetBootOptions);
    g_Apis.pSetCallback("ManageHotPatch", true, PROBE_IDS::IdManageHotPatch);
    g_Apis.pSetCallback("ManageHotPatch", false, PROBE_IDS::IdManageHotPatch);
    g_Apis.pSetCallback("EnumerateTransactionObject", true, PROBE_IDS::IdEnumerateTransactionObject);
    g_Apis.pSetCallback("EnumerateTransactionObject", false, PROBE_IDS::IdEnumerateTransactionObject);
    g_Apis.pSetCallback("SetThreadExecutionState", true, PROBE_IDS::IdSetThreadExecutionState);
    g_Apis.pSetCallback("SetThreadExecutionState", false, PROBE_IDS::IdSetThreadExecutionState);
    g_Apis.pSetCallback("WaitLowEventPair", true, PROBE_IDS::IdWaitLowEventPair);
    g_Apis.pSetCallback("WaitLowEventPair", false, PROBE_IDS::IdWaitLowEventPair);
    g_Apis.pSetCallback("SetHighWaitLowEventPair", true, PROBE_IDS::IdSetHighWaitLowEventPair);
    g_Apis.pSetCallback("SetHighWaitLowEventPair", false, PROBE_IDS::IdSetHighWaitLowEventPair);
    g_Apis.pSetCallback("QueryInformationWorkerFactory", true, PROBE_IDS::IdQueryInformationWorkerFactory);
    g_Apis.pSetCallback("QueryInformationWorkerFactory", false, PROBE_IDS::IdQueryInformationWorkerFactory);
    g_Apis.pSetCallback("SetWnfProcessNotificationEvent", true, PROBE_IDS::IdSetWnfProcessNotificationEvent);
    g_Apis.pSetCallback("SetWnfProcessNotificationEvent", false, PROBE_IDS::IdSetWnfProcessNotificationEvent);
    g_Apis.pSetCallback("AlpcDeleteSectionView", true, PROBE_IDS::IdAlpcDeleteSectionView);
    g_Apis.pSetCallback("AlpcDeleteSectionView", false, PROBE_IDS::IdAlpcDeleteSectionView);
    g_Apis.pSetCallback("CreateMailslotFile", true, PROBE_IDS::IdCreateMailslotFile);
    g_Apis.pSetCallback("CreateMailslotFile", false, PROBE_IDS::IdCreateMailslotFile);
    g_Apis.pSetCallback("CreateProcess", true, PROBE_IDS::IdCreateProcess);
    g_Apis.pSetCallback("CreateProcess", false, PROBE_IDS::IdCreateProcess);
    g_Apis.pSetCallback("QueryIoCompletion", true, PROBE_IDS::IdQueryIoCompletion);
    g_Apis.pSetCallback("QueryIoCompletion", false, PROBE_IDS::IdQueryIoCompletion);
    g_Apis.pSetCallback("CreateTimer", true, PROBE_IDS::IdCreateTimer);
    g_Apis.pSetCallback("CreateTimer", false, PROBE_IDS::IdCreateTimer);
    g_Apis.pSetCallback("FlushInstallUILanguage", true, PROBE_IDS::IdFlushInstallUILanguage);
    g_Apis.pSetCallback("FlushInstallUILanguage", false, PROBE_IDS::IdFlushInstallUILanguage);
    g_Apis.pSetCallback("CompleteConnectPort", true, PROBE_IDS::IdCompleteConnectPort);
    g_Apis.pSetCallback("CompleteConnectPort", false, PROBE_IDS::IdCompleteConnectPort);
    g_Apis.pSetCallback("AlpcConnectPort", true, PROBE_IDS::IdAlpcConnectPort);
    g_Apis.pSetCallback("AlpcConnectPort", false, PROBE_IDS::IdAlpcConnectPort);
    g_Apis.pSetCallback("FreezeRegistry", true, PROBE_IDS::IdFreezeRegistry);
    g_Apis.pSetCallback("FreezeRegistry", false, PROBE_IDS::IdFreezeRegistry);
    g_Apis.pSetCallback("MapCMFModule", true, PROBE_IDS::IdMapCMFModule);
    g_Apis.pSetCallback("MapCMFModule", false, PROBE_IDS::IdMapCMFModule);
    g_Apis.pSetCallback("AllocateUserPhysicalPages", true, PROBE_IDS::IdAllocateUserPhysicalPages);
    g_Apis.pSetCallback("AllocateUserPhysicalPages", false, PROBE_IDS::IdAllocateUserPhysicalPages);
    g_Apis.pSetCallback("SetInformationEnlistment", true, PROBE_IDS::IdSetInformationEnlistment);
    g_Apis.pSetCallback("SetInformationEnlistment", false, PROBE_IDS::IdSetInformationEnlistment);
    g_Apis.pSetCallback("RaiseHardError", true, PROBE_IDS::IdRaiseHardError);
    g_Apis.pSetCallback("RaiseHardError", false, PROBE_IDS::IdRaiseHardError);
    g_Apis.pSetCallback("CreateSection", true, PROBE_IDS::IdCreateSection);
    g_Apis.pSetCallback("CreateSection", false, PROBE_IDS::IdCreateSection);
    g_Apis.pSetCallback("OpenIoCompletion", true, PROBE_IDS::IdOpenIoCompletion);
    g_Apis.pSetCallback("OpenIoCompletion", false, PROBE_IDS::IdOpenIoCompletion);
    g_Apis.pSetCallback("SystemDebugControl", true, PROBE_IDS::IdSystemDebugControl);
    g_Apis.pSetCallback("SystemDebugControl", false, PROBE_IDS::IdSystemDebugControl);
    g_Apis.pSetCallback("TranslateFilePath", true, PROBE_IDS::IdTranslateFilePath);
    g_Apis.pSetCallback("TranslateFilePath", false, PROBE_IDS::IdTranslateFilePath);
    g_Apis.pSetCallback("CreateIRTimer", true, PROBE_IDS::IdCreateIRTimer);
    g_Apis.pSetCallback("CreateIRTimer", false, PROBE_IDS::IdCreateIRTimer);
    g_Apis.pSetCallback("CreateRegistryTransaction", true, PROBE_IDS::IdCreateRegistryTransaction);
    g_Apis.pSetCallback("CreateRegistryTransaction", false, PROBE_IDS::IdCreateRegistryTransaction);
    g_Apis.pSetCallback("LoadKey2", true, PROBE_IDS::IdLoadKey2);
    g_Apis.pSetCallback("LoadKey2", false, PROBE_IDS::IdLoadKey2);
    g_Apis.pSetCallback("AlpcCreatePort", true, PROBE_IDS::IdAlpcCreatePort);
    g_Apis.pSetCallback("AlpcCreatePort", false, PROBE_IDS::IdAlpcCreatePort);
    g_Apis.pSetCallback("DeleteWnfStateData", true, PROBE_IDS::IdDeleteWnfStateData);
    g_Apis.pSetCallback("DeleteWnfStateData", false, PROBE_IDS::IdDeleteWnfStateData);
    g_Apis.pSetCallback("SetTimerEx", true, PROBE_IDS::IdSetTimerEx);
    g_Apis.pSetCallback("SetTimerEx", false, PROBE_IDS::IdSetTimerEx);
    g_Apis.pSetCallback("SetLowWaitHighEventPair", true, PROBE_IDS::IdSetLowWaitHighEventPair);
    g_Apis.pSetCallback("SetLowWaitHighEventPair", false, PROBE_IDS::IdSetLowWaitHighEventPair);
    g_Apis.pSetCallback("AlpcCreateSecurityContext", true, PROBE_IDS::IdAlpcCreateSecurityContext);
    g_Apis.pSetCallback("AlpcCreateSecurityContext", false, PROBE_IDS::IdAlpcCreateSecurityContext);
    g_Apis.pSetCallback("SetCachedSigningLevel", true, PROBE_IDS::IdSetCachedSigningLevel);
    g_Apis.pSetCallback("SetCachedSigningLevel", false, PROBE_IDS::IdSetCachedSigningLevel);
    g_Apis.pSetCallback("SetHighEventPair", true, PROBE_IDS::IdSetHighEventPair);
    g_Apis.pSetCallback("SetHighEventPair", false, PROBE_IDS::IdSetHighEventPair);
    g_Apis.pSetCallback("ShutdownWorkerFactory", true, PROBE_IDS::IdShutdownWorkerFactory);
    g_Apis.pSetCallback("ShutdownWorkerFactory", false, PROBE_IDS::IdShutdownWorkerFactory);
    g_Apis.pSetCallback("SetInformationJobObject", true, PROBE_IDS::IdSetInformationJobObject);
    g_Apis.pSetCallback("SetInformationJobObject", false, PROBE_IDS::IdSetInformationJobObject);
    g_Apis.pSetCallback("AdjustGroupsToken", true, PROBE_IDS::IdAdjustGroupsToken);
    g_Apis.pSetCallback("AdjustGroupsToken", false, PROBE_IDS::IdAdjustGroupsToken);
    g_Apis.pSetCallback("AreMappedFilesTheSame", true, PROBE_IDS::IdAreMappedFilesTheSame);
    g_Apis.pSetCallback("AreMappedFilesTheSame", false, PROBE_IDS::IdAreMappedFilesTheSame);
    g_Apis.pSetCallback("SetBootEntryOrder", true, PROBE_IDS::IdSetBootEntryOrder);
    g_Apis.pSetCallback("SetBootEntryOrder", false, PROBE_IDS::IdSetBootEntryOrder);
    g_Apis.pSetCallback("QueryMutant", true, PROBE_IDS::IdQueryMutant);
    g_Apis.pSetCallback("QueryMutant", false, PROBE_IDS::IdQueryMutant);
    g_Apis.pSetCallback("otifyChangeSession", true, PROBE_IDS::IdotifyChangeSession);
    g_Apis.pSetCallback("otifyChangeSession", false, PROBE_IDS::IdotifyChangeSession);
    g_Apis.pSetCallback("QueryDefaultLocale", true, PROBE_IDS::IdQueryDefaultLocale);
    g_Apis.pSetCallback("QueryDefaultLocale", false, PROBE_IDS::IdQueryDefaultLocale);
    g_Apis.pSetCallback("CreateThreadEx", true, PROBE_IDS::IdCreateThreadEx);
    g_Apis.pSetCallback("CreateThreadEx", false, PROBE_IDS::IdCreateThreadEx);
    g_Apis.pSetCallback("QueryDriverEntryOrder", true, PROBE_IDS::IdQueryDriverEntryOrder);
    g_Apis.pSetCallback("QueryDriverEntryOrder", false, PROBE_IDS::IdQueryDriverEntryOrder);
    g_Apis.pSetCallback("SetTimerResolution", true, PROBE_IDS::IdSetTimerResolution);
    g_Apis.pSetCallback("SetTimerResolution", false, PROBE_IDS::IdSetTimerResolution);
    g_Apis.pSetCallback("PrePrepareEnlistment", true, PROBE_IDS::IdPrePrepareEnlistment);
    g_Apis.pSetCallback("PrePrepareEnlistment", false, PROBE_IDS::IdPrePrepareEnlistment);
    g_Apis.pSetCallback("CancelSynchronousIoFile", true, PROBE_IDS::IdCancelSynchronousIoFile);
    g_Apis.pSetCallback("CancelSynchronousIoFile", false, PROBE_IDS::IdCancelSynchronousIoFile);
    g_Apis.pSetCallback("QueryDirectoryFileEx", true, PROBE_IDS::IdQueryDirectoryFileEx);
    g_Apis.pSetCallback("QueryDirectoryFileEx", false, PROBE_IDS::IdQueryDirectoryFileEx);
    g_Apis.pSetCallback("AddDriverEntry", true, PROBE_IDS::IdAddDriverEntry);
    g_Apis.pSetCallback("AddDriverEntry", false, PROBE_IDS::IdAddDriverEntry);
    g_Apis.pSetCallback("UnloadKey", true, PROBE_IDS::IdUnloadKey);
    g_Apis.pSetCallback("UnloadKey", false, PROBE_IDS::IdUnloadKey);
    g_Apis.pSetCallback("CreateEvent", true, PROBE_IDS::IdCreateEvent);
    g_Apis.pSetCallback("CreateEvent", false, PROBE_IDS::IdCreateEvent);
    g_Apis.pSetCallback("OpenSession", true, PROBE_IDS::IdOpenSession);
    g_Apis.pSetCallback("OpenSession", false, PROBE_IDS::IdOpenSession);
    g_Apis.pSetCallback("QueryValueKey", true, PROBE_IDS::IdQueryValueKey);
    g_Apis.pSetCallback("QueryValueKey", false, PROBE_IDS::IdQueryValueKey);
    g_Apis.pSetCallback("CreatePrivateNamespace", true, PROBE_IDS::IdCreatePrivateNamespace);
    g_Apis.pSetCallback("CreatePrivateNamespace", false, PROBE_IDS::IdCreatePrivateNamespace);
    g_Apis.pSetCallback("IsUILanguageComitted", true, PROBE_IDS::IdIsUILanguageComitted);
    g_Apis.pSetCallback("IsUILanguageComitted", false, PROBE_IDS::IdIsUILanguageComitted);
    g_Apis.pSetCallback("AlertThread", true, PROBE_IDS::IdAlertThread);
    g_Apis.pSetCallback("AlertThread", false, PROBE_IDS::IdAlertThread);
    g_Apis.pSetCallback("QueryInstallUILanguage", true, PROBE_IDS::IdQueryInstallUILanguage);
    g_Apis.pSetCallback("QueryInstallUILanguage", false, PROBE_IDS::IdQueryInstallUILanguage);
    g_Apis.pSetCallback("CreateSymbolicLinkObject", true, PROBE_IDS::IdCreateSymbolicLinkObject);
    g_Apis.pSetCallback("CreateSymbolicLinkObject", false, PROBE_IDS::IdCreateSymbolicLinkObject);
    g_Apis.pSetCallback("AllocateUuids", true, PROBE_IDS::IdAllocateUuids);
    g_Apis.pSetCallback("AllocateUuids", false, PROBE_IDS::IdAllocateUuids);
    g_Apis.pSetCallback("ShutdownSystem", true, PROBE_IDS::IdShutdownSystem);
    g_Apis.pSetCallback("ShutdownSystem", false, PROBE_IDS::IdShutdownSystem);
    g_Apis.pSetCallback("CreateTokenEx", true, PROBE_IDS::IdCreateTokenEx);
    g_Apis.pSetCallback("CreateTokenEx", false, PROBE_IDS::IdCreateTokenEx);
    g_Apis.pSetCallback("QueryVirtualMemory", true, PROBE_IDS::IdQueryVirtualMemory);
    g_Apis.pSetCallback("QueryVirtualMemory", false, PROBE_IDS::IdQueryVirtualMemory);
    g_Apis.pSetCallback("AlpcOpenSenderProcess", true, PROBE_IDS::IdAlpcOpenSenderProcess);
    g_Apis.pSetCallback("AlpcOpenSenderProcess", false, PROBE_IDS::IdAlpcOpenSenderProcess);
    g_Apis.pSetCallback("AssignProcessToJobObject", true, PROBE_IDS::IdAssignProcessToJobObject);
    g_Apis.pSetCallback("AssignProcessToJobObject", false, PROBE_IDS::IdAssignProcessToJobObject);
    g_Apis.pSetCallback("RemoveIoCompletion", true, PROBE_IDS::IdRemoveIoCompletion);
    g_Apis.pSetCallback("RemoveIoCompletion", false, PROBE_IDS::IdRemoveIoCompletion);
    g_Apis.pSetCallback("CreateTimer2", true, PROBE_IDS::IdCreateTimer2);
    g_Apis.pSetCallback("CreateTimer2", false, PROBE_IDS::IdCreateTimer2);
    g_Apis.pSetCallback("CreateEnlistment", true, PROBE_IDS::IdCreateEnlistment);
    g_Apis.pSetCallback("CreateEnlistment", false, PROBE_IDS::IdCreateEnlistment);
    g_Apis.pSetCallback("RecoverEnlistment", true, PROBE_IDS::IdRecoverEnlistment);
    g_Apis.pSetCallback("RecoverEnlistment", false, PROBE_IDS::IdRecoverEnlistment);
    g_Apis.pSetCallback("CreateJobSet", true, PROBE_IDS::IdCreateJobSet);
    g_Apis.pSetCallback("CreateJobSet", false, PROBE_IDS::IdCreateJobSet);
    g_Apis.pSetCallback("SetIoCompletionEx", true, PROBE_IDS::IdSetIoCompletionEx);
    g_Apis.pSetCallback("SetIoCompletionEx", false, PROBE_IDS::IdSetIoCompletionEx);
    g_Apis.pSetCallback("CreateProcessEx", true, PROBE_IDS::IdCreateProcessEx);
    g_Apis.pSetCallback("CreateProcessEx", false, PROBE_IDS::IdCreateProcessEx);
    g_Apis.pSetCallback("AlpcConnectPortEx", true, PROBE_IDS::IdAlpcConnectPortEx);
    g_Apis.pSetCallback("AlpcConnectPortEx", false, PROBE_IDS::IdAlpcConnectPortEx);
    g_Apis.pSetCallback("WaitForMultipleObjects32", true, PROBE_IDS::IdWaitForMultipleObjects32);
    g_Apis.pSetCallback("WaitForMultipleObjects32", false, PROBE_IDS::IdWaitForMultipleObjects32);
    g_Apis.pSetCallback("RecoverResourceManager", true, PROBE_IDS::IdRecoverResourceManager);
    g_Apis.pSetCallback("RecoverResourceManager", false, PROBE_IDS::IdRecoverResourceManager);
    g_Apis.pSetCallback("AlpcSetInformation", true, PROBE_IDS::IdAlpcSetInformation);
    g_Apis.pSetCallback("AlpcSetInformation", false, PROBE_IDS::IdAlpcSetInformation);
    g_Apis.pSetCallback("AlpcRevokeSecurityContext", true, PROBE_IDS::IdAlpcRevokeSecurityContext);
    g_Apis.pSetCallback("AlpcRevokeSecurityContext", false, PROBE_IDS::IdAlpcRevokeSecurityContext);
    g_Apis.pSetCallback("AlpcImpersonateClientOfPort", true, PROBE_IDS::IdAlpcImpersonateClientOfPort);
    g_Apis.pSetCallback("AlpcImpersonateClientOfPort", false, PROBE_IDS::IdAlpcImpersonateClientOfPort);
    g_Apis.pSetCallback("ReleaseKeyedEvent", true, PROBE_IDS::IdReleaseKeyedEvent);
    g_Apis.pSetCallback("ReleaseKeyedEvent", false, PROBE_IDS::IdReleaseKeyedEvent);
    g_Apis.pSetCallback("TerminateThread", true, PROBE_IDS::IdTerminateThread);
    g_Apis.pSetCallback("TerminateThread", false, PROBE_IDS::IdTerminateThread);
    g_Apis.pSetCallback("SetInformationSymbolicLink", true, PROBE_IDS::IdSetInformationSymbolicLink);
    g_Apis.pSetCallback("SetInformationSymbolicLink", false, PROBE_IDS::IdSetInformationSymbolicLink);
    g_Apis.pSetCallback("DeleteObjectAuditAlarm", true, PROBE_IDS::IdDeleteObjectAuditAlarm);
    g_Apis.pSetCallback("DeleteObjectAuditAlarm", false, PROBE_IDS::IdDeleteObjectAuditAlarm);
    g_Apis.pSetCallback("WaitForKeyedEvent", true, PROBE_IDS::IdWaitForKeyedEvent);
    g_Apis.pSetCallback("WaitForKeyedEvent", false, PROBE_IDS::IdWaitForKeyedEvent);
    g_Apis.pSetCallback("CreatePort", true, PROBE_IDS::IdCreatePort);
    g_Apis.pSetCallback("CreatePort", false, PROBE_IDS::IdCreatePort);
    g_Apis.pSetCallback("DeletePrivateNamespace", true, PROBE_IDS::IdDeletePrivateNamespace);
    g_Apis.pSetCallback("DeletePrivateNamespace", false, PROBE_IDS::IdDeletePrivateNamespace);
    g_Apis.pSetCallback("otifyChangeMultipleKeys", true, PROBE_IDS::IdotifyChangeMultipleKeys);
    g_Apis.pSetCallback("otifyChangeMultipleKeys", false, PROBE_IDS::IdotifyChangeMultipleKeys);
    g_Apis.pSetCallback("LockFile", true, PROBE_IDS::IdLockFile);
    g_Apis.pSetCallback("LockFile", false, PROBE_IDS::IdLockFile);
    g_Apis.pSetCallback("QueryDefaultUILanguage", true, PROBE_IDS::IdQueryDefaultUILanguage);
    g_Apis.pSetCallback("QueryDefaultUILanguage", false, PROBE_IDS::IdQueryDefaultUILanguage);
    g_Apis.pSetCallback("OpenEventPair", true, PROBE_IDS::IdOpenEventPair);
    g_Apis.pSetCallback("OpenEventPair", false, PROBE_IDS::IdOpenEventPair);
    g_Apis.pSetCallback("RollforwardTransactionManager", true, PROBE_IDS::IdRollforwardTransactionManager);
    g_Apis.pSetCallback("RollforwardTransactionManager", false, PROBE_IDS::IdRollforwardTransactionManager);
    g_Apis.pSetCallback("AlpcQueryInformationMessage", true, PROBE_IDS::IdAlpcQueryInformationMessage);
    g_Apis.pSetCallback("AlpcQueryInformationMessage", false, PROBE_IDS::IdAlpcQueryInformationMessage);
    g_Apis.pSetCallback("UnmapViewOfSection", true, PROBE_IDS::IdUnmapViewOfSection);
    g_Apis.pSetCallback("UnmapViewOfSection", false, PROBE_IDS::IdUnmapViewOfSection);
    g_Apis.pSetCallback("CancelIoFile", true, PROBE_IDS::IdCancelIoFile);
    g_Apis.pSetCallback("CancelIoFile", false, PROBE_IDS::IdCancelIoFile);
    g_Apis.pSetCallback("CreatePagingFile", true, PROBE_IDS::IdCreatePagingFile);
    g_Apis.pSetCallback("CreatePagingFile", false, PROBE_IDS::IdCreatePagingFile);
    g_Apis.pSetCallback("CancelTimer", true, PROBE_IDS::IdCancelTimer);
    g_Apis.pSetCallback("CancelTimer", false, PROBE_IDS::IdCancelTimer);
    g_Apis.pSetCallback("ReplyWaitReceivePort", true, PROBE_IDS::IdReplyWaitReceivePort);
    g_Apis.pSetCallback("ReplyWaitReceivePort", false, PROBE_IDS::IdReplyWaitReceivePort);
    g_Apis.pSetCallback("CompareObjects", true, PROBE_IDS::IdCompareObjects);
    g_Apis.pSetCallback("CompareObjects", false, PROBE_IDS::IdCompareObjects);
    g_Apis.pSetCallback("SetDefaultLocale", true, PROBE_IDS::IdSetDefaultLocale);
    g_Apis.pSetCallback("SetDefaultLocale", false, PROBE_IDS::IdSetDefaultLocale);
    g_Apis.pSetCallback("AllocateLocallyUniqueId", true, PROBE_IDS::IdAllocateLocallyUniqueId);
    g_Apis.pSetCallback("AllocateLocallyUniqueId", false, PROBE_IDS::IdAllocateLocallyUniqueId);
    g_Apis.pSetCallback("AccessCheckByTypeAndAuditAlarm", true, PROBE_IDS::IdAccessCheckByTypeAndAuditAlarm);
    g_Apis.pSetCallback("AccessCheckByTypeAndAuditAlarm", false, PROBE_IDS::IdAccessCheckByTypeAndAuditAlarm);
    g_Apis.pSetCallback("QueryDebugFilterState", true, PROBE_IDS::IdQueryDebugFilterState);
    g_Apis.pSetCallback("QueryDebugFilterState", false, PROBE_IDS::IdQueryDebugFilterState);
    g_Apis.pSetCallback("OpenSemaphore", true, PROBE_IDS::IdOpenSemaphore);
    g_Apis.pSetCallback("OpenSemaphore", false, PROBE_IDS::IdOpenSemaphore);
    g_Apis.pSetCallback("AllocateVirtualMemory", true, PROBE_IDS::IdAllocateVirtualMemory);
    g_Apis.pSetCallback("AllocateVirtualMemory", false, PROBE_IDS::IdAllocateVirtualMemory);
    g_Apis.pSetCallback("ResumeProcess", true, PROBE_IDS::IdResumeProcess);
    g_Apis.pSetCallback("ResumeProcess", false, PROBE_IDS::IdResumeProcess);
    g_Apis.pSetCallback("SetContextThread", true, PROBE_IDS::IdSetContextThread);
    g_Apis.pSetCallback("SetContextThread", false, PROBE_IDS::IdSetContextThread);
    g_Apis.pSetCallback("OpenSymbolicLinkObject", true, PROBE_IDS::IdOpenSymbolicLinkObject);
    g_Apis.pSetCallback("OpenSymbolicLinkObject", false, PROBE_IDS::IdOpenSymbolicLinkObject);
    g_Apis.pSetCallback("ModifyDriverEntry", true, PROBE_IDS::IdModifyDriverEntry);
    g_Apis.pSetCallback("ModifyDriverEntry", false, PROBE_IDS::IdModifyDriverEntry);
    g_Apis.pSetCallback("SerializeBoot", true, PROBE_IDS::IdSerializeBoot);
    g_Apis.pSetCallback("SerializeBoot", false, PROBE_IDS::IdSerializeBoot);
    g_Apis.pSetCallback("RenameTransactionManager", true, PROBE_IDS::IdRenameTransactionManager);
    g_Apis.pSetCallback("RenameTransactionManager", false, PROBE_IDS::IdRenameTransactionManager);
    g_Apis.pSetCallback("RemoveIoCompletionEx", true, PROBE_IDS::IdRemoveIoCompletionEx);
    g_Apis.pSetCallback("RemoveIoCompletionEx", false, PROBE_IDS::IdRemoveIoCompletionEx);
    g_Apis.pSetCallback("MapViewOfSectionEx", true, PROBE_IDS::IdMapViewOfSectionEx);
    g_Apis.pSetCallback("MapViewOfSectionEx", false, PROBE_IDS::IdMapViewOfSectionEx);
    g_Apis.pSetCallback("FilterTokenEx", true, PROBE_IDS::IdFilterTokenEx);
    g_Apis.pSetCallback("FilterTokenEx", false, PROBE_IDS::IdFilterTokenEx);
    g_Apis.pSetCallback("DeleteDriverEntry", true, PROBE_IDS::IdDeleteDriverEntry);
    g_Apis.pSetCallback("DeleteDriverEntry", false, PROBE_IDS::IdDeleteDriverEntry);
    g_Apis.pSetCallback("QuerySystemInformation", true, PROBE_IDS::IdQuerySystemInformation);
    g_Apis.pSetCallback("QuerySystemInformation", false, PROBE_IDS::IdQuerySystemInformation);
    g_Apis.pSetCallback("SetInformationWorkerFactory", true, PROBE_IDS::IdSetInformationWorkerFactory);
    g_Apis.pSetCallback("SetInformationWorkerFactory", false, PROBE_IDS::IdSetInformationWorkerFactory);
    g_Apis.pSetCallback("AdjustTokenClaimsAndDeviceGroups", true, PROBE_IDS::IdAdjustTokenClaimsAndDeviceGroups);
    g_Apis.pSetCallback("AdjustTokenClaimsAndDeviceGroups", false, PROBE_IDS::IdAdjustTokenClaimsAndDeviceGroups);
    g_Apis.pSetCallback("SaveMergedKeys", true, PROBE_IDS::IdSaveMergedKeys);
    g_Apis.pSetCallback("SaveMergedKeys", false, PROBE_IDS::IdSaveMergedKeys);

    LOG_INFO("Plugin Initialized\r\n");
}
ASSERT_INTERFACE_IMPLEMENTED(StpInitialize, tStpInitialize, "StpInitialize does not match the interface type");

extern "C" __declspec(dllexport) void StpDeInitialize() {
    LOG_INFO("Plugin DeInitializing...\r\n");

    g_Apis.pUnsetCallback("LockProductActivationKeys", true);
    g_Apis.pUnsetCallback("LockProductActivationKeys", false);
    g_Apis.pUnsetCallback("WaitHighEventPair", true);
    g_Apis.pUnsetCallback("WaitHighEventPair", false);
    g_Apis.pUnsetCallback("RegisterThreadTerminatePort", true);
    g_Apis.pUnsetCallback("RegisterThreadTerminatePort", false);
    g_Apis.pUnsetCallback("AssociateWaitCompletionPacket", true);
    g_Apis.pUnsetCallback("AssociateWaitCompletionPacket", false);
    g_Apis.pUnsetCallback("QueryPerformanceCounter", true);
    g_Apis.pUnsetCallback("QueryPerformanceCounter", false);
    g_Apis.pUnsetCallback("CompactKeys", true);
    g_Apis.pUnsetCallback("CompactKeys", false);
    g_Apis.pUnsetCallback("QuerySystemInformationEx", true);
    g_Apis.pUnsetCallback("QuerySystemInformationEx", false);
    g_Apis.pUnsetCallback("ResetEvent", true);
    g_Apis.pUnsetCallback("ResetEvent", false);
    g_Apis.pUnsetCallback("GetContextThread", true);
    g_Apis.pUnsetCallback("GetContextThread", false);
    g_Apis.pUnsetCallback("QueryInformationThread", true);
    g_Apis.pUnsetCallback("QueryInformationThread", false);
    g_Apis.pUnsetCallback("WaitForSingleObject", true);
    g_Apis.pUnsetCallback("WaitForSingleObject", false);
    g_Apis.pUnsetCallback("FlushBuffersFileEx", true);
    g_Apis.pUnsetCallback("FlushBuffersFileEx", false);
    g_Apis.pUnsetCallback("UnloadKey2", true);
    g_Apis.pUnsetCallback("UnloadKey2", false);
    g_Apis.pUnsetCallback("ReadOnlyEnlistment", true);
    g_Apis.pUnsetCallback("ReadOnlyEnlistment", false);
    g_Apis.pUnsetCallback("DeleteFile", true);
    g_Apis.pUnsetCallback("DeleteFile", false);
    g_Apis.pUnsetCallback("DeleteAtom", true);
    g_Apis.pUnsetCallback("DeleteAtom", false);
    g_Apis.pUnsetCallback("QueryDirectoryFile", true);
    g_Apis.pUnsetCallback("QueryDirectoryFile", false);
    g_Apis.pUnsetCallback("SetEventBoostPriority", true);
    g_Apis.pUnsetCallback("SetEventBoostPriority", false);
    g_Apis.pUnsetCallback("AllocateUserPhysicalPagesEx", true);
    g_Apis.pUnsetCallback("AllocateUserPhysicalPagesEx", false);
    g_Apis.pUnsetCallback("WriteFile", true);
    g_Apis.pUnsetCallback("WriteFile", false);
    g_Apis.pUnsetCallback("QueryInformationFile", true);
    g_Apis.pUnsetCallback("QueryInformationFile", false);
    g_Apis.pUnsetCallback("AlpcCancelMessage", true);
    g_Apis.pUnsetCallback("AlpcCancelMessage", false);
    g_Apis.pUnsetCallback("OpenMutant", true);
    g_Apis.pUnsetCallback("OpenMutant", false);
    g_Apis.pUnsetCallback("CreatePartition", true);
    g_Apis.pUnsetCallback("CreatePartition", false);
    g_Apis.pUnsetCallback("QueryTimer", true);
    g_Apis.pUnsetCallback("QueryTimer", false);
    g_Apis.pUnsetCallback("OpenEvent", true);
    g_Apis.pUnsetCallback("OpenEvent", false);
    g_Apis.pUnsetCallback("OpenObjectAuditAlarm", true);
    g_Apis.pUnsetCallback("OpenObjectAuditAlarm", false);
    g_Apis.pUnsetCallback("MakePermanentObject", true);
    g_Apis.pUnsetCallback("MakePermanentObject", false);
    g_Apis.pUnsetCallback("CommitTransaction", true);
    g_Apis.pUnsetCallback("CommitTransaction", false);
    g_Apis.pUnsetCallback("SetSystemTime", true);
    g_Apis.pUnsetCallback("SetSystemTime", false);
    g_Apis.pUnsetCallback("GetDevicePowerState", true);
    g_Apis.pUnsetCallback("GetDevicePowerState", false);
    g_Apis.pUnsetCallback("SetSystemPowerState", true);
    g_Apis.pUnsetCallback("SetSystemPowerState", false);
    g_Apis.pUnsetCallback("AlpcCreateResourceReserve", true);
    g_Apis.pUnsetCallback("AlpcCreateResourceReserve", false);
    g_Apis.pUnsetCallback("UnlockFile", true);
    g_Apis.pUnsetCallback("UnlockFile", false);
    g_Apis.pUnsetCallback("AlpcDeletePortSection", true);
    g_Apis.pUnsetCallback("AlpcDeletePortSection", false);
    g_Apis.pUnsetCallback("SetInformationResourceManager", true);
    g_Apis.pUnsetCallback("SetInformationResourceManager", false);
    g_Apis.pUnsetCallback("FreeUserPhysicalPages", true);
    g_Apis.pUnsetCallback("FreeUserPhysicalPages", false);
    g_Apis.pUnsetCallback("LoadKeyEx", true);
    g_Apis.pUnsetCallback("LoadKeyEx", false);
    g_Apis.pUnsetCallback("PropagationComplete", true);
    g_Apis.pUnsetCallback("PropagationComplete", false);
    g_Apis.pUnsetCallback("AccessCheckByTypeResultListAndAuditAlarm", true);
    g_Apis.pUnsetCallback("AccessCheckByTypeResultListAndAuditAlarm", false);
    g_Apis.pUnsetCallback("QueryInformationToken", true);
    g_Apis.pUnsetCallback("QueryInformationToken", false);
    g_Apis.pUnsetCallback("RegisterProtocolAddressInformation", true);
    g_Apis.pUnsetCallback("RegisterProtocolAddressInformation", false);
    g_Apis.pUnsetCallback("ProtectVirtualMemory", true);
    g_Apis.pUnsetCallback("ProtectVirtualMemory", false);
    g_Apis.pUnsetCallback("CreateKey", true);
    g_Apis.pUnsetCallback("CreateKey", false);
    g_Apis.pUnsetCallback("AlpcSendWaitReceivePort", true);
    g_Apis.pUnsetCallback("AlpcSendWaitReceivePort", false);
    g_Apis.pUnsetCallback("OpenRegistryTransaction", true);
    g_Apis.pUnsetCallback("OpenRegistryTransaction", false);
    g_Apis.pUnsetCallback("TerminateProcess", true);
    g_Apis.pUnsetCallback("TerminateProcess", false);
    g_Apis.pUnsetCallback("PowerInformation", true);
    g_Apis.pUnsetCallback("PowerInformation", false);
    g_Apis.pUnsetCallback("otifyChangeDirectoryFile", true);
    g_Apis.pUnsetCallback("otifyChangeDirectoryFile", false);
    g_Apis.pUnsetCallback("CreateTransaction", true);
    g_Apis.pUnsetCallback("CreateTransaction", false);
    g_Apis.pUnsetCallback("CreateProfileEx", true);
    g_Apis.pUnsetCallback("CreateProfileEx", false);
    g_Apis.pUnsetCallback("QueryLicenseValue", true);
    g_Apis.pUnsetCallback("QueryLicenseValue", false);
    g_Apis.pUnsetCallback("CreateProfile", true);
    g_Apis.pUnsetCallback("CreateProfile", false);
    g_Apis.pUnsetCallback("InitializeRegistry", true);
    g_Apis.pUnsetCallback("InitializeRegistry", false);
    g_Apis.pUnsetCallback("FreezeTransactions", true);
    g_Apis.pUnsetCallback("FreezeTransactions", false);
    g_Apis.pUnsetCallback("OpenJobObject", true);
    g_Apis.pUnsetCallback("OpenJobObject", false);
    g_Apis.pUnsetCallback("SubscribeWnfStateChange", true);
    g_Apis.pUnsetCallback("SubscribeWnfStateChange", false);
    g_Apis.pUnsetCallback("GetWriteWatch", true);
    g_Apis.pUnsetCallback("GetWriteWatch", false);
    g_Apis.pUnsetCallback("GetCachedSigningLevel", true);
    g_Apis.pUnsetCallback("GetCachedSigningLevel", false);
    g_Apis.pUnsetCallback("SetSecurityObject", true);
    g_Apis.pUnsetCallback("SetSecurityObject", false);
    g_Apis.pUnsetCallback("QueryIntervalProfile", true);
    g_Apis.pUnsetCallback("QueryIntervalProfile", false);
    g_Apis.pUnsetCallback("PropagationFailed", true);
    g_Apis.pUnsetCallback("PropagationFailed", false);
    g_Apis.pUnsetCallback("CreateSectionEx", true);
    g_Apis.pUnsetCallback("CreateSectionEx", false);
    g_Apis.pUnsetCallback("RaiseException", true);
    g_Apis.pUnsetCallback("RaiseException", false);
    g_Apis.pUnsetCallback("SetCachedSigningLevel2", true);
    g_Apis.pUnsetCallback("SetCachedSigningLevel2", false);
    g_Apis.pUnsetCallback("CommitEnlistment", true);
    g_Apis.pUnsetCallback("CommitEnlistment", false);
    g_Apis.pUnsetCallback("QueryInformationByName", true);
    g_Apis.pUnsetCallback("QueryInformationByName", false);
    g_Apis.pUnsetCallback("CreateThread", true);
    g_Apis.pUnsetCallback("CreateThread", false);
    g_Apis.pUnsetCallback("OpenResourceManager", true);
    g_Apis.pUnsetCallback("OpenResourceManager", false);
    g_Apis.pUnsetCallback("ReadRequestData", true);
    g_Apis.pUnsetCallback("ReadRequestData", false);
    g_Apis.pUnsetCallback("ClearEvent", true);
    g_Apis.pUnsetCallback("ClearEvent", false);
    g_Apis.pUnsetCallback("TestAlert", true);
    g_Apis.pUnsetCallback("TestAlert", false);
    g_Apis.pUnsetCallback("SetInformationThread", true);
    g_Apis.pUnsetCallback("SetInformationThread", false);
    g_Apis.pUnsetCallback("SetTimer2", true);
    g_Apis.pUnsetCallback("SetTimer2", false);
    g_Apis.pUnsetCallback("SetDefaultUILanguage", true);
    g_Apis.pUnsetCallback("SetDefaultUILanguage", false);
    g_Apis.pUnsetCallback("EnumerateValueKey", true);
    g_Apis.pUnsetCallback("EnumerateValueKey", false);
    g_Apis.pUnsetCallback("OpenEnlistment", true);
    g_Apis.pUnsetCallback("OpenEnlistment", false);
    g_Apis.pUnsetCallback("SetIntervalProfile", true);
    g_Apis.pUnsetCallback("SetIntervalProfile", false);
    g_Apis.pUnsetCallback("QueryPortInformationProcess", true);
    g_Apis.pUnsetCallback("QueryPortInformationProcess", false);
    g_Apis.pUnsetCallback("QueryInformationTransactionManager", true);
    g_Apis.pUnsetCallback("QueryInformationTransactionManager", false);
    g_Apis.pUnsetCallback("SetInformationTransactionManager", true);
    g_Apis.pUnsetCallback("SetInformationTransactionManager", false);
    g_Apis.pUnsetCallback("InitializeEnclave", true);
    g_Apis.pUnsetCallback("InitializeEnclave", false);
    g_Apis.pUnsetCallback("PrepareComplete", true);
    g_Apis.pUnsetCallback("PrepareComplete", false);
    g_Apis.pUnsetCallback("QueueApcThread", true);
    g_Apis.pUnsetCallback("QueueApcThread", false);
    g_Apis.pUnsetCallback("WorkerFactoryWorkerReady", true);
    g_Apis.pUnsetCallback("WorkerFactoryWorkerReady", false);
    g_Apis.pUnsetCallback("GetCompleteWnfStateSubscription", true);
    g_Apis.pUnsetCallback("GetCompleteWnfStateSubscription", false);
    g_Apis.pUnsetCallback("AlertThreadByThreadId", true);
    g_Apis.pUnsetCallback("AlertThreadByThreadId", false);
    g_Apis.pUnsetCallback("LockVirtualMemory", true);
    g_Apis.pUnsetCallback("LockVirtualMemory", false);
    g_Apis.pUnsetCallback("DeviceIoControlFile", true);
    g_Apis.pUnsetCallback("DeviceIoControlFile", false);
    g_Apis.pUnsetCallback("CreateUserProcess", true);
    g_Apis.pUnsetCallback("CreateUserProcess", false);
    g_Apis.pUnsetCallback("QuerySection", true);
    g_Apis.pUnsetCallback("QuerySection", false);
    g_Apis.pUnsetCallback("SaveKeyEx", true);
    g_Apis.pUnsetCallback("SaveKeyEx", false);
    g_Apis.pUnsetCallback("RollbackTransaction", true);
    g_Apis.pUnsetCallback("RollbackTransaction", false);
    g_Apis.pUnsetCallback("TraceEvent", true);
    g_Apis.pUnsetCallback("TraceEvent", false);
    g_Apis.pUnsetCallback("OpenSection", true);
    g_Apis.pUnsetCallback("OpenSection", false);
    g_Apis.pUnsetCallback("RequestPort", true);
    g_Apis.pUnsetCallback("RequestPort", false);
    g_Apis.pUnsetCallback("UnsubscribeWnfStateChange", true);
    g_Apis.pUnsetCallback("UnsubscribeWnfStateChange", false);
    g_Apis.pUnsetCallback("ThawRegistry", true);
    g_Apis.pUnsetCallback("ThawRegistry", false);
    g_Apis.pUnsetCallback("CreateJobObject", true);
    g_Apis.pUnsetCallback("CreateJobObject", false);
    g_Apis.pUnsetCallback("OpenKeyTransactedEx", true);
    g_Apis.pUnsetCallback("OpenKeyTransactedEx", false);
    g_Apis.pUnsetCallback("WaitForMultipleObjects", true);
    g_Apis.pUnsetCallback("WaitForMultipleObjects", false);
    g_Apis.pUnsetCallback("DuplicateToken", true);
    g_Apis.pUnsetCallback("DuplicateToken", false);
    g_Apis.pUnsetCallback("AlpcOpenSenderThread", true);
    g_Apis.pUnsetCallback("AlpcOpenSenderThread", false);
    g_Apis.pUnsetCallback("AlpcImpersonateClientContainerOfPort", true);
    g_Apis.pUnsetCallback("AlpcImpersonateClientContainerOfPort", false);
    g_Apis.pUnsetCallback("DrawText", true);
    g_Apis.pUnsetCallback("DrawText", false);
    g_Apis.pUnsetCallback("ReleaseSemaphore", true);
    g_Apis.pUnsetCallback("ReleaseSemaphore", false);
    g_Apis.pUnsetCallback("SetQuotaInformationFile", true);
    g_Apis.pUnsetCallback("SetQuotaInformationFile", false);
    g_Apis.pUnsetCallback("QueryInformationAtom", true);
    g_Apis.pUnsetCallback("QueryInformationAtom", false);
    g_Apis.pUnsetCallback("EnumerateBootEntries", true);
    g_Apis.pUnsetCallback("EnumerateBootEntries", false);
    g_Apis.pUnsetCallback("ThawTransactions", true);
    g_Apis.pUnsetCallback("ThawTransactions", false);
    g_Apis.pUnsetCallback("AccessCheck", true);
    g_Apis.pUnsetCallback("AccessCheck", false);
    g_Apis.pUnsetCallback("FlushProcessWriteBuffers", true);
    g_Apis.pUnsetCallback("FlushProcessWriteBuffers", false);
    g_Apis.pUnsetCallback("QuerySemaphore", true);
    g_Apis.pUnsetCallback("QuerySemaphore", false);
    g_Apis.pUnsetCallback("CreateNamedPipeFile", true);
    g_Apis.pUnsetCallback("CreateNamedPipeFile", false);
    g_Apis.pUnsetCallback("AlpcDeleteResourceReserve", true);
    g_Apis.pUnsetCallback("AlpcDeleteResourceReserve", false);
    g_Apis.pUnsetCallback("QuerySystemEnvironmentValueEx", true);
    g_Apis.pUnsetCallback("QuerySystemEnvironmentValueEx", false);
    g_Apis.pUnsetCallback("ReadFileScatter", true);
    g_Apis.pUnsetCallback("ReadFileScatter", false);
    g_Apis.pUnsetCallback("OpenKeyEx", true);
    g_Apis.pUnsetCallback("OpenKeyEx", false);
    g_Apis.pUnsetCallback("SignalAndWaitForSingleObject", true);
    g_Apis.pUnsetCallback("SignalAndWaitForSingleObject", false);
    g_Apis.pUnsetCallback("ReleaseMutant", true);
    g_Apis.pUnsetCallback("ReleaseMutant", false);
    g_Apis.pUnsetCallback("TerminateJobObject", true);
    g_Apis.pUnsetCallback("TerminateJobObject", false);
    g_Apis.pUnsetCallback("SetSystemEnvironmentValue", true);
    g_Apis.pUnsetCallback("SetSystemEnvironmentValue", false);
    g_Apis.pUnsetCallback("Close", true);
    g_Apis.pUnsetCallback("Close", false);
    g_Apis.pUnsetCallback("QueueApcThreadEx", true);
    g_Apis.pUnsetCallback("QueueApcThreadEx", false);
    g_Apis.pUnsetCallback("QueryMultipleValueKey", true);
    g_Apis.pUnsetCallback("QueryMultipleValueKey", false);
    g_Apis.pUnsetCallback("AlpcQueryInformation", true);
    g_Apis.pUnsetCallback("AlpcQueryInformation", false);
    g_Apis.pUnsetCallback("UpdateWnfStateData", true);
    g_Apis.pUnsetCallback("UpdateWnfStateData", false);
    g_Apis.pUnsetCallback("ListenPort", true);
    g_Apis.pUnsetCallback("ListenPort", false);
    g_Apis.pUnsetCallback("FlushInstructionCache", true);
    g_Apis.pUnsetCallback("FlushInstructionCache", false);
    g_Apis.pUnsetCallback("GetNotificationResourceManager", true);
    g_Apis.pUnsetCallback("GetNotificationResourceManager", false);
    g_Apis.pUnsetCallback("QueryFullAttributesFile", true);
    g_Apis.pUnsetCallback("QueryFullAttributesFile", false);
    g_Apis.pUnsetCallback("SuspendThread", true);
    g_Apis.pUnsetCallback("SuspendThread", false);
    g_Apis.pUnsetCallback("CompareTokens", true);
    g_Apis.pUnsetCallback("CompareTokens", false);
    g_Apis.pUnsetCallback("CancelWaitCompletionPacket", true);
    g_Apis.pUnsetCallback("CancelWaitCompletionPacket", false);
    g_Apis.pUnsetCallback("AlpcAcceptConnectPort", true);
    g_Apis.pUnsetCallback("AlpcAcceptConnectPort", false);
    g_Apis.pUnsetCallback("OpenTransaction", true);
    g_Apis.pUnsetCallback("OpenTransaction", false);
    g_Apis.pUnsetCallback("ImpersonateAnonymousToken", true);
    g_Apis.pUnsetCallback("ImpersonateAnonymousToken", false);
    g_Apis.pUnsetCallback("QuerySecurityObject", true);
    g_Apis.pUnsetCallback("QuerySecurityObject", false);
    g_Apis.pUnsetCallback("RollbackEnlistment", true);
    g_Apis.pUnsetCallback("RollbackEnlistment", false);
    g_Apis.pUnsetCallback("ReplacePartitionUnit", true);
    g_Apis.pUnsetCallback("ReplacePartitionUnit", false);
    g_Apis.pUnsetCallback("CreateKeyTransacted", true);
    g_Apis.pUnsetCallback("CreateKeyTransacted", false);
    g_Apis.pUnsetCallback("ConvertBetweenAuxiliaryCounterAndPerformanceCounter", true);
    g_Apis.pUnsetCallback("ConvertBetweenAuxiliaryCounterAndPerformanceCounter", false);
    g_Apis.pUnsetCallback("CreateKeyedEvent", true);
    g_Apis.pUnsetCallback("CreateKeyedEvent", false);
    g_Apis.pUnsetCallback("CreateEventPair", true);
    g_Apis.pUnsetCallback("CreateEventPair", false);
    g_Apis.pUnsetCallback("AddAtom", true);
    g_Apis.pUnsetCallback("AddAtom", false);
    g_Apis.pUnsetCallback("QueryOpenSubKeys", true);
    g_Apis.pUnsetCallback("QueryOpenSubKeys", false);
    g_Apis.pUnsetCallback("QuerySystemTime", true);
    g_Apis.pUnsetCallback("QuerySystemTime", false);
    g_Apis.pUnsetCallback("SetEaFile", true);
    g_Apis.pUnsetCallback("SetEaFile", false);
    g_Apis.pUnsetCallback("SetInformationProcess", true);
    g_Apis.pUnsetCallback("SetInformationProcess", false);
    g_Apis.pUnsetCallback("SetValueKey", true);
    g_Apis.pUnsetCallback("SetValueKey", false);
    g_Apis.pUnsetCallback("QuerySymbolicLinkObject", true);
    g_Apis.pUnsetCallback("QuerySymbolicLinkObject", false);
    g_Apis.pUnsetCallback("QueryOpenSubKeysEx", true);
    g_Apis.pUnsetCallback("QueryOpenSubKeysEx", false);
    g_Apis.pUnsetCallback("otifyChangeKey", true);
    g_Apis.pUnsetCallback("otifyChangeKey", false);
    g_Apis.pUnsetCallback("IsProcessInJob", true);
    g_Apis.pUnsetCallback("IsProcessInJob", false);
    g_Apis.pUnsetCallback("CommitComplete", true);
    g_Apis.pUnsetCallback("CommitComplete", false);
    g_Apis.pUnsetCallback("EnumerateDriverEntries", true);
    g_Apis.pUnsetCallback("EnumerateDriverEntries", false);
    g_Apis.pUnsetCallback("AccessCheckByTypeResultList", true);
    g_Apis.pUnsetCallback("AccessCheckByTypeResultList", false);
    g_Apis.pUnsetCallback("LoadEnclaveData", true);
    g_Apis.pUnsetCallback("LoadEnclaveData", false);
    g_Apis.pUnsetCallback("AllocateVirtualMemoryEx", true);
    g_Apis.pUnsetCallback("AllocateVirtualMemoryEx", false);
    g_Apis.pUnsetCallback("WaitForWorkViaWorkerFactory", true);
    g_Apis.pUnsetCallback("WaitForWorkViaWorkerFactory", false);
    g_Apis.pUnsetCallback("QueryInformationResourceManager", true);
    g_Apis.pUnsetCallback("QueryInformationResourceManager", false);
    g_Apis.pUnsetCallback("EnumerateKey", true);
    g_Apis.pUnsetCallback("EnumerateKey", false);
    g_Apis.pUnsetCallback("GetMUIRegistryInfo", true);
    g_Apis.pUnsetCallback("GetMUIRegistryInfo", false);
    g_Apis.pUnsetCallback("AcceptConnectPort", true);
    g_Apis.pUnsetCallback("AcceptConnectPort", false);
    g_Apis.pUnsetCallback("RecoverTransactionManager", true);
    g_Apis.pUnsetCallback("RecoverTransactionManager", false);
    g_Apis.pUnsetCallback("WriteVirtualMemory", true);
    g_Apis.pUnsetCallback("WriteVirtualMemory", false);
    g_Apis.pUnsetCallback("QueryBootOptions", true);
    g_Apis.pUnsetCallback("QueryBootOptions", false);
    g_Apis.pUnsetCallback("RollbackComplete", true);
    g_Apis.pUnsetCallback("RollbackComplete", false);
    g_Apis.pUnsetCallback("QueryAuxiliaryCounterFrequency", true);
    g_Apis.pUnsetCallback("QueryAuxiliaryCounterFrequency", false);
    g_Apis.pUnsetCallback("AlpcCreatePortSection", true);
    g_Apis.pUnsetCallback("AlpcCreatePortSection", false);
    g_Apis.pUnsetCallback("QueryObject", true);
    g_Apis.pUnsetCallback("QueryObject", false);
    g_Apis.pUnsetCallback("QueryWnfStateData", true);
    g_Apis.pUnsetCallback("QueryWnfStateData", false);
    g_Apis.pUnsetCallback("InitiatePowerAction", true);
    g_Apis.pUnsetCallback("InitiatePowerAction", false);
    g_Apis.pUnsetCallback("DirectGraphicsCall", true);
    g_Apis.pUnsetCallback("DirectGraphicsCall", false);
    g_Apis.pUnsetCallback("AcquireCrossVmMutant", true);
    g_Apis.pUnsetCallback("AcquireCrossVmMutant", false);
    g_Apis.pUnsetCallback("RollbackRegistryTransaction", true);
    g_Apis.pUnsetCallback("RollbackRegistryTransaction", false);
    g_Apis.pUnsetCallback("AlertResumeThread", true);
    g_Apis.pUnsetCallback("AlertResumeThread", false);
    g_Apis.pUnsetCallback("PssCaptureVaSpaceBulk", true);
    g_Apis.pUnsetCallback("PssCaptureVaSpaceBulk", false);
    g_Apis.pUnsetCallback("CreateToken", true);
    g_Apis.pUnsetCallback("CreateToken", false);
    g_Apis.pUnsetCallback("PrepareEnlistment", true);
    g_Apis.pUnsetCallback("PrepareEnlistment", false);
    g_Apis.pUnsetCallback("FlushWriteBuffer", true);
    g_Apis.pUnsetCallback("FlushWriteBuffer", false);
    g_Apis.pUnsetCallback("CommitRegistryTransaction", true);
    g_Apis.pUnsetCallback("CommitRegistryTransaction", false);
    g_Apis.pUnsetCallback("AccessCheckByType", true);
    g_Apis.pUnsetCallback("AccessCheckByType", false);
    g_Apis.pUnsetCallback("OpenThread", true);
    g_Apis.pUnsetCallback("OpenThread", false);
    g_Apis.pUnsetCallback("AccessCheckAndAuditAlarm", true);
    g_Apis.pUnsetCallback("AccessCheckAndAuditAlarm", false);
    g_Apis.pUnsetCallback("OpenThreadTokenEx", true);
    g_Apis.pUnsetCallback("OpenThreadTokenEx", false);
    g_Apis.pUnsetCallback("WriteRequestData", true);
    g_Apis.pUnsetCallback("WriteRequestData", false);
    g_Apis.pUnsetCallback("CreateWorkerFactory", true);
    g_Apis.pUnsetCallback("CreateWorkerFactory", false);
    g_Apis.pUnsetCallback("OpenPartition", true);
    g_Apis.pUnsetCallback("OpenPartition", false);
    g_Apis.pUnsetCallback("SetSystemInformation", true);
    g_Apis.pUnsetCallback("SetSystemInformation", false);
    g_Apis.pUnsetCallback("EnumerateSystemEnvironmentValuesEx", true);
    g_Apis.pUnsetCallback("EnumerateSystemEnvironmentValuesEx", false);
    g_Apis.pUnsetCallback("CreateWnfStateName", true);
    g_Apis.pUnsetCallback("CreateWnfStateName", false);
    g_Apis.pUnsetCallback("QueryInformationJobObject", true);
    g_Apis.pUnsetCallback("QueryInformationJobObject", false);
    g_Apis.pUnsetCallback("PrivilegedServiceAuditAlarm", true);
    g_Apis.pUnsetCallback("PrivilegedServiceAuditAlarm", false);
    g_Apis.pUnsetCallback("EnableLastKnownGood", true);
    g_Apis.pUnsetCallback("EnableLastKnownGood", false);
    g_Apis.pUnsetCallback("otifyChangeDirectoryFileEx", true);
    g_Apis.pUnsetCallback("otifyChangeDirectoryFileEx", false);
    g_Apis.pUnsetCallback("CreateWaitablePort", true);
    g_Apis.pUnsetCallback("CreateWaitablePort", false);
    g_Apis.pUnsetCallback("WaitForAlertByThreadId", true);
    g_Apis.pUnsetCallback("WaitForAlertByThreadId", false);
    g_Apis.pUnsetCallback("GetNextProcess", true);
    g_Apis.pUnsetCallback("GetNextProcess", false);
    g_Apis.pUnsetCallback("OpenKeyedEvent", true);
    g_Apis.pUnsetCallback("OpenKeyedEvent", false);
    g_Apis.pUnsetCallback("DeleteBootEntry", true);
    g_Apis.pUnsetCallback("DeleteBootEntry", false);
    g_Apis.pUnsetCallback("FilterToken", true);
    g_Apis.pUnsetCallback("FilterToken", false);
    g_Apis.pUnsetCallback("CompressKey", true);
    g_Apis.pUnsetCallback("CompressKey", false);
    g_Apis.pUnsetCallback("ModifyBootEntry", true);
    g_Apis.pUnsetCallback("ModifyBootEntry", false);
    g_Apis.pUnsetCallback("SetInformationTransaction", true);
    g_Apis.pUnsetCallback("SetInformationTransaction", false);
    g_Apis.pUnsetCallback("PlugPlayControl", true);
    g_Apis.pUnsetCallback("PlugPlayControl", false);
    g_Apis.pUnsetCallback("OpenDirectoryObject", true);
    g_Apis.pUnsetCallback("OpenDirectoryObject", false);
    g_Apis.pUnsetCallback("Continue", true);
    g_Apis.pUnsetCallback("Continue", false);
    g_Apis.pUnsetCallback("PrivilegeObjectAuditAlarm", true);
    g_Apis.pUnsetCallback("PrivilegeObjectAuditAlarm", false);
    g_Apis.pUnsetCallback("QueryKey", true);
    g_Apis.pUnsetCallback("QueryKey", false);
    g_Apis.pUnsetCallback("FilterBootOption", true);
    g_Apis.pUnsetCallback("FilterBootOption", false);
    g_Apis.pUnsetCallback("YieldExecution", true);
    g_Apis.pUnsetCallback("YieldExecution", false);
    g_Apis.pUnsetCallback("ResumeThread", true);
    g_Apis.pUnsetCallback("ResumeThread", false);
    g_Apis.pUnsetCallback("AddBootEntry", true);
    g_Apis.pUnsetCallback("AddBootEntry", false);
    g_Apis.pUnsetCallback("GetCurrentProcessorNumberEx", true);
    g_Apis.pUnsetCallback("GetCurrentProcessorNumberEx", false);
    g_Apis.pUnsetCallback("CreateLowBoxToken", true);
    g_Apis.pUnsetCallback("CreateLowBoxToken", false);
    g_Apis.pUnsetCallback("FlushBuffersFile", true);
    g_Apis.pUnsetCallback("FlushBuffersFile", false);
    g_Apis.pUnsetCallback("DelayExecution", true);
    g_Apis.pUnsetCallback("DelayExecution", false);
    g_Apis.pUnsetCallback("OpenKey", true);
    g_Apis.pUnsetCallback("OpenKey", false);
    g_Apis.pUnsetCallback("StopProfile", true);
    g_Apis.pUnsetCallback("StopProfile", false);
    g_Apis.pUnsetCallback("SetEvent", true);
    g_Apis.pUnsetCallback("SetEvent", false);
    g_Apis.pUnsetCallback("RestoreKey", true);
    g_Apis.pUnsetCallback("RestoreKey", false);
    g_Apis.pUnsetCallback("ExtendSection", true);
    g_Apis.pUnsetCallback("ExtendSection", false);
    g_Apis.pUnsetCallback("InitializeNlsFiles", true);
    g_Apis.pUnsetCallback("InitializeNlsFiles", false);
    g_Apis.pUnsetCallback("FindAtom", true);
    g_Apis.pUnsetCallback("FindAtom", false);
    g_Apis.pUnsetCallback("DisplayString", true);
    g_Apis.pUnsetCallback("DisplayString", false);
    g_Apis.pUnsetCallback("LoadDriver", true);
    g_Apis.pUnsetCallback("LoadDriver", false);
    g_Apis.pUnsetCallback("QueryWnfStateNameInformation", true);
    g_Apis.pUnsetCallback("QueryWnfStateNameInformation", false);
    g_Apis.pUnsetCallback("CreateMutant", true);
    g_Apis.pUnsetCallback("CreateMutant", false);
    g_Apis.pUnsetCallback("FlushKey", true);
    g_Apis.pUnsetCallback("FlushKey", false);
    g_Apis.pUnsetCallback("DuplicateObject", true);
    g_Apis.pUnsetCallback("DuplicateObject", false);
    g_Apis.pUnsetCallback("CancelTimer2", true);
    g_Apis.pUnsetCallback("CancelTimer2", false);
    g_Apis.pUnsetCallback("QueryAttributesFile", true);
    g_Apis.pUnsetCallback("QueryAttributesFile", false);
    g_Apis.pUnsetCallback("CompareSigningLevels", true);
    g_Apis.pUnsetCallback("CompareSigningLevels", false);
    g_Apis.pUnsetCallback("AccessCheckByTypeResultListAndAuditAlarmByHandle", true);
    g_Apis.pUnsetCallback("AccessCheckByTypeResultListAndAuditAlarmByHandle", false);
    g_Apis.pUnsetCallback("DeleteValueKey", true);
    g_Apis.pUnsetCallback("DeleteValueKey", false);
    g_Apis.pUnsetCallback("SetDebugFilterState", true);
    g_Apis.pUnsetCallback("SetDebugFilterState", false);
    g_Apis.pUnsetCallback("PulseEvent", true);
    g_Apis.pUnsetCallback("PulseEvent", false);
    g_Apis.pUnsetCallback("AllocateReserveObject", true);
    g_Apis.pUnsetCallback("AllocateReserveObject", false);
    g_Apis.pUnsetCallback("AlpcDisconnectPort", true);
    g_Apis.pUnsetCallback("AlpcDisconnectPort", false);
    g_Apis.pUnsetCallback("QueryTimerResolution", true);
    g_Apis.pUnsetCallback("QueryTimerResolution", false);
    g_Apis.pUnsetCallback("DeleteKey", true);
    g_Apis.pUnsetCallback("DeleteKey", false);
    g_Apis.pUnsetCallback("CreateFile", true);
    g_Apis.pUnsetCallback("CreateFile", false);
    g_Apis.pUnsetCallback("ReplyPort", true);
    g_Apis.pUnsetCallback("ReplyPort", false);
    g_Apis.pUnsetCallback("GetNlsSectionPtr", true);
    g_Apis.pUnsetCallback("GetNlsSectionPtr", false);
    g_Apis.pUnsetCallback("QueryInformationProcess", true);
    g_Apis.pUnsetCallback("QueryInformationProcess", false);
    g_Apis.pUnsetCallback("ReplyWaitReceivePortEx", true);
    g_Apis.pUnsetCallback("ReplyWaitReceivePortEx", false);
    g_Apis.pUnsetCallback("UmsThreadYield", true);
    g_Apis.pUnsetCallback("UmsThreadYield", false);
    g_Apis.pUnsetCallback("ManagePartition", true);
    g_Apis.pUnsetCallback("ManagePartition", false);
    g_Apis.pUnsetCallback("AdjustPrivilegesToken", true);
    g_Apis.pUnsetCallback("AdjustPrivilegesToken", false);
    g_Apis.pUnsetCallback("CreateCrossVmMutant", true);
    g_Apis.pUnsetCallback("CreateCrossVmMutant", false);
    g_Apis.pUnsetCallback("CreateDirectoryObject", true);
    g_Apis.pUnsetCallback("CreateDirectoryObject", false);
    g_Apis.pUnsetCallback("OpenFile", true);
    g_Apis.pUnsetCallback("OpenFile", false);
    g_Apis.pUnsetCallback("SetInformationVirtualMemory", true);
    g_Apis.pUnsetCallback("SetInformationVirtualMemory", false);
    g_Apis.pUnsetCallback("TerminateEnclave", true);
    g_Apis.pUnsetCallback("TerminateEnclave", false);
    g_Apis.pUnsetCallback("SuspendProcess", true);
    g_Apis.pUnsetCallback("SuspendProcess", false);
    g_Apis.pUnsetCallback("ReplyWaitReplyPort", true);
    g_Apis.pUnsetCallback("ReplyWaitReplyPort", false);
    g_Apis.pUnsetCallback("OpenTransactionManager", true);
    g_Apis.pUnsetCallback("OpenTransactionManager", false);
    g_Apis.pUnsetCallback("CreateSemaphore", true);
    g_Apis.pUnsetCallback("CreateSemaphore", false);
    g_Apis.pUnsetCallback("UnmapViewOfSectionEx", true);
    g_Apis.pUnsetCallback("UnmapViewOfSectionEx", false);
    g_Apis.pUnsetCallback("MapViewOfSection", true);
    g_Apis.pUnsetCallback("MapViewOfSection", false);
    g_Apis.pUnsetCallback("DisableLastKnownGood", true);
    g_Apis.pUnsetCallback("DisableLastKnownGood", false);
    g_Apis.pUnsetCallback("GetNextThread", true);
    g_Apis.pUnsetCallback("GetNextThread", false);
    g_Apis.pUnsetCallback("MakeTemporaryObject", true);
    g_Apis.pUnsetCallback("MakeTemporaryObject", false);
    g_Apis.pUnsetCallback("SetInformationFile", true);
    g_Apis.pUnsetCallback("SetInformationFile", false);
    g_Apis.pUnsetCallback("CreateTransactionManager", true);
    g_Apis.pUnsetCallback("CreateTransactionManager", false);
    g_Apis.pUnsetCallback("WriteFileGather", true);
    g_Apis.pUnsetCallback("WriteFileGather", false);
    g_Apis.pUnsetCallback("QueryInformationTransaction", true);
    g_Apis.pUnsetCallback("QueryInformationTransaction", false);
    g_Apis.pUnsetCallback("FlushVirtualMemory", true);
    g_Apis.pUnsetCallback("FlushVirtualMemory", false);
    g_Apis.pUnsetCallback("QueryQuotaInformationFile", true);
    g_Apis.pUnsetCallback("QueryQuotaInformationFile", false);
    g_Apis.pUnsetCallback("SetVolumeInformationFile", true);
    g_Apis.pUnsetCallback("SetVolumeInformationFile", false);
    g_Apis.pUnsetCallback("QueryInformationEnlistment", true);
    g_Apis.pUnsetCallback("QueryInformationEnlistment", false);
    g_Apis.pUnsetCallback("CreateIoCompletion", true);
    g_Apis.pUnsetCallback("CreateIoCompletion", false);
    g_Apis.pUnsetCallback("UnloadKeyEx", true);
    g_Apis.pUnsetCallback("UnloadKeyEx", false);
    g_Apis.pUnsetCallback("QueryEaFile", true);
    g_Apis.pUnsetCallback("QueryEaFile", false);
    g_Apis.pUnsetCallback("QueryDirectoryObject", true);
    g_Apis.pUnsetCallback("QueryDirectoryObject", false);
    g_Apis.pUnsetCallback("AddAtomEx", true);
    g_Apis.pUnsetCallback("AddAtomEx", false);
    g_Apis.pUnsetCallback("SinglePhaseReject", true);
    g_Apis.pUnsetCallback("SinglePhaseReject", false);
    g_Apis.pUnsetCallback("DeleteWnfStateName", true);
    g_Apis.pUnsetCallback("DeleteWnfStateName", false);
    g_Apis.pUnsetCallback("SetSystemEnvironmentValueEx", true);
    g_Apis.pUnsetCallback("SetSystemEnvironmentValueEx", false);
    g_Apis.pUnsetCallback("ContinueEx", true);
    g_Apis.pUnsetCallback("ContinueEx", false);
    g_Apis.pUnsetCallback("UnloadDriver", true);
    g_Apis.pUnsetCallback("UnloadDriver", false);
    g_Apis.pUnsetCallback("CallEnclave", true);
    g_Apis.pUnsetCallback("CallEnclave", false);
    g_Apis.pUnsetCallback("CancelIoFileEx", true);
    g_Apis.pUnsetCallback("CancelIoFileEx", false);
    g_Apis.pUnsetCallback("SetTimer", true);
    g_Apis.pUnsetCallback("SetTimer", false);
    g_Apis.pUnsetCallback("QuerySystemEnvironmentValue", true);
    g_Apis.pUnsetCallback("QuerySystemEnvironmentValue", false);
    g_Apis.pUnsetCallback("OpenThreadToken", true);
    g_Apis.pUnsetCallback("OpenThreadToken", false);
    g_Apis.pUnsetCallback("MapUserPhysicalPagesScatter", true);
    g_Apis.pUnsetCallback("MapUserPhysicalPagesScatter", false);
    g_Apis.pUnsetCallback("CreateResourceManager", true);
    g_Apis.pUnsetCallback("CreateResourceManager", false);
    g_Apis.pUnsetCallback("UnlockVirtualMemory", true);
    g_Apis.pUnsetCallback("UnlockVirtualMemory", false);
    g_Apis.pUnsetCallback("QueryInformationPort", true);
    g_Apis.pUnsetCallback("QueryInformationPort", false);
    g_Apis.pUnsetCallback("SetLowEventPair", true);
    g_Apis.pUnsetCallback("SetLowEventPair", false);
    g_Apis.pUnsetCallback("SetInformationKey", true);
    g_Apis.pUnsetCallback("SetInformationKey", false);
    g_Apis.pUnsetCallback("QuerySecurityPolicy", true);
    g_Apis.pUnsetCallback("QuerySecurityPolicy", false);
    g_Apis.pUnsetCallback("OpenProcessToken", true);
    g_Apis.pUnsetCallback("OpenProcessToken", false);
    g_Apis.pUnsetCallback("QueryVolumeInformationFile", true);
    g_Apis.pUnsetCallback("QueryVolumeInformationFile", false);
    g_Apis.pUnsetCallback("OpenTimer", true);
    g_Apis.pUnsetCallback("OpenTimer", false);
    g_Apis.pUnsetCallback("MapUserPhysicalPages", true);
    g_Apis.pUnsetCallback("MapUserPhysicalPages", false);
    g_Apis.pUnsetCallback("LoadKey", true);
    g_Apis.pUnsetCallback("LoadKey", false);
    g_Apis.pUnsetCallback("CreateWaitCompletionPacket", true);
    g_Apis.pUnsetCallback("CreateWaitCompletionPacket", false);
    g_Apis.pUnsetCallback("ReleaseWorkerFactoryWorker", true);
    g_Apis.pUnsetCallback("ReleaseWorkerFactoryWorker", false);
    g_Apis.pUnsetCallback("PrePrepareComplete", true);
    g_Apis.pUnsetCallback("PrePrepareComplete", false);
    g_Apis.pUnsetCallback("ReadVirtualMemory", true);
    g_Apis.pUnsetCallback("ReadVirtualMemory", false);
    g_Apis.pUnsetCallback("FreeVirtualMemory", true);
    g_Apis.pUnsetCallback("FreeVirtualMemory", false);
    g_Apis.pUnsetCallback("SetDriverEntryOrder", true);
    g_Apis.pUnsetCallback("SetDriverEntryOrder", false);
    g_Apis.pUnsetCallback("ReadFile", true);
    g_Apis.pUnsetCallback("ReadFile", false);
    g_Apis.pUnsetCallback("TraceControl", true);
    g_Apis.pUnsetCallback("TraceControl", false);
    g_Apis.pUnsetCallback("OpenProcessTokenEx", true);
    g_Apis.pUnsetCallback("OpenProcessTokenEx", false);
    g_Apis.pUnsetCallback("SecureConnectPort", true);
    g_Apis.pUnsetCallback("SecureConnectPort", false);
    g_Apis.pUnsetCallback("SaveKey", true);
    g_Apis.pUnsetCallback("SaveKey", false);
    g_Apis.pUnsetCallback("SetDefaultHardErrorPort", true);
    g_Apis.pUnsetCallback("SetDefaultHardErrorPort", false);
    g_Apis.pUnsetCallback("CreateEnclave", true);
    g_Apis.pUnsetCallback("CreateEnclave", false);
    g_Apis.pUnsetCallback("OpenPrivateNamespace", true);
    g_Apis.pUnsetCallback("OpenPrivateNamespace", false);
    g_Apis.pUnsetCallback("SetLdtEntries", true);
    g_Apis.pUnsetCallback("SetLdtEntries", false);
    g_Apis.pUnsetCallback("ResetWriteWatch", true);
    g_Apis.pUnsetCallback("ResetWriteWatch", false);
    g_Apis.pUnsetCallback("RenameKey", true);
    g_Apis.pUnsetCallback("RenameKey", false);
    g_Apis.pUnsetCallback("RevertContainerImpersonation", true);
    g_Apis.pUnsetCallback("RevertContainerImpersonation", false);
    g_Apis.pUnsetCallback("AlpcCreateSectionView", true);
    g_Apis.pUnsetCallback("AlpcCreateSectionView", false);
    g_Apis.pUnsetCallback("CreateCrossVmEvent", true);
    g_Apis.pUnsetCallback("CreateCrossVmEvent", false);
    g_Apis.pUnsetCallback("ImpersonateThread", true);
    g_Apis.pUnsetCallback("ImpersonateThread", false);
    g_Apis.pUnsetCallback("SetIRTimer", true);
    g_Apis.pUnsetCallback("SetIRTimer", false);
    g_Apis.pUnsetCallback("CreateDirectoryObjectEx", true);
    g_Apis.pUnsetCallback("CreateDirectoryObjectEx", false);
    g_Apis.pUnsetCallback("AcquireProcessActivityReference", true);
    g_Apis.pUnsetCallback("AcquireProcessActivityReference", false);
    g_Apis.pUnsetCallback("ReplaceKey", true);
    g_Apis.pUnsetCallback("ReplaceKey", false);
    g_Apis.pUnsetCallback("StartProfile", true);
    g_Apis.pUnsetCallback("StartProfile", false);
    g_Apis.pUnsetCallback("QueryBootEntryOrder", true);
    g_Apis.pUnsetCallback("QueryBootEntryOrder", false);
    g_Apis.pUnsetCallback("LockRegistryKey", true);
    g_Apis.pUnsetCallback("LockRegistryKey", false);
    g_Apis.pUnsetCallback("ImpersonateClientOfPort", true);
    g_Apis.pUnsetCallback("ImpersonateClientOfPort", false);
    g_Apis.pUnsetCallback("QueryEvent", true);
    g_Apis.pUnsetCallback("QueryEvent", false);
    g_Apis.pUnsetCallback("FsControlFile", true);
    g_Apis.pUnsetCallback("FsControlFile", false);
    g_Apis.pUnsetCallback("OpenProcess", true);
    g_Apis.pUnsetCallback("OpenProcess", false);
    g_Apis.pUnsetCallback("SetIoCompletion", true);
    g_Apis.pUnsetCallback("SetIoCompletion", false);
    g_Apis.pUnsetCallback("ConnectPort", true);
    g_Apis.pUnsetCallback("ConnectPort", false);
    g_Apis.pUnsetCallback("CloseObjectAuditAlarm", true);
    g_Apis.pUnsetCallback("CloseObjectAuditAlarm", false);
    g_Apis.pUnsetCallback("RequestWaitReplyPort", true);
    g_Apis.pUnsetCallback("RequestWaitReplyPort", false);
    g_Apis.pUnsetCallback("SetInformationObject", true);
    g_Apis.pUnsetCallback("SetInformationObject", false);
    g_Apis.pUnsetCallback("PrivilegeCheck", true);
    g_Apis.pUnsetCallback("PrivilegeCheck", false);
    g_Apis.pUnsetCallback("CallbackReturn", true);
    g_Apis.pUnsetCallback("CallbackReturn", false);
    g_Apis.pUnsetCallback("SetInformationToken", true);
    g_Apis.pUnsetCallback("SetInformationToken", false);
    g_Apis.pUnsetCallback("SetUuidSeed", true);
    g_Apis.pUnsetCallback("SetUuidSeed", false);
    g_Apis.pUnsetCallback("OpenKeyTransacted", true);
    g_Apis.pUnsetCallback("OpenKeyTransacted", false);
    g_Apis.pUnsetCallback("AlpcDeleteSecurityContext", true);
    g_Apis.pUnsetCallback("AlpcDeleteSecurityContext", false);
    g_Apis.pUnsetCallback("SetBootOptions", true);
    g_Apis.pUnsetCallback("SetBootOptions", false);
    g_Apis.pUnsetCallback("ManageHotPatch", true);
    g_Apis.pUnsetCallback("ManageHotPatch", false);
    g_Apis.pUnsetCallback("EnumerateTransactionObject", true);
    g_Apis.pUnsetCallback("EnumerateTransactionObject", false);
    g_Apis.pUnsetCallback("SetThreadExecutionState", true);
    g_Apis.pUnsetCallback("SetThreadExecutionState", false);
    g_Apis.pUnsetCallback("WaitLowEventPair", true);
    g_Apis.pUnsetCallback("WaitLowEventPair", false);
    g_Apis.pUnsetCallback("SetHighWaitLowEventPair", true);
    g_Apis.pUnsetCallback("SetHighWaitLowEventPair", false);
    g_Apis.pUnsetCallback("QueryInformationWorkerFactory", true);
    g_Apis.pUnsetCallback("QueryInformationWorkerFactory", false);
    g_Apis.pUnsetCallback("SetWnfProcessNotificationEvent", true);
    g_Apis.pUnsetCallback("SetWnfProcessNotificationEvent", false);
    g_Apis.pUnsetCallback("AlpcDeleteSectionView", true);
    g_Apis.pUnsetCallback("AlpcDeleteSectionView", false);
    g_Apis.pUnsetCallback("CreateMailslotFile", true);
    g_Apis.pUnsetCallback("CreateMailslotFile", false);
    g_Apis.pUnsetCallback("CreateProcess", true);
    g_Apis.pUnsetCallback("CreateProcess", false);
    g_Apis.pUnsetCallback("QueryIoCompletion", true);
    g_Apis.pUnsetCallback("QueryIoCompletion", false);
    g_Apis.pUnsetCallback("CreateTimer", true);
    g_Apis.pUnsetCallback("CreateTimer", false);
    g_Apis.pUnsetCallback("FlushInstallUILanguage", true);
    g_Apis.pUnsetCallback("FlushInstallUILanguage", false);
    g_Apis.pUnsetCallback("CompleteConnectPort", true);
    g_Apis.pUnsetCallback("CompleteConnectPort", false);
    g_Apis.pUnsetCallback("AlpcConnectPort", true);
    g_Apis.pUnsetCallback("AlpcConnectPort", false);
    g_Apis.pUnsetCallback("FreezeRegistry", true);
    g_Apis.pUnsetCallback("FreezeRegistry", false);
    g_Apis.pUnsetCallback("MapCMFModule", true);
    g_Apis.pUnsetCallback("MapCMFModule", false);
    g_Apis.pUnsetCallback("AllocateUserPhysicalPages", true);
    g_Apis.pUnsetCallback("AllocateUserPhysicalPages", false);
    g_Apis.pUnsetCallback("SetInformationEnlistment", true);
    g_Apis.pUnsetCallback("SetInformationEnlistment", false);
    g_Apis.pUnsetCallback("RaiseHardError", true);
    g_Apis.pUnsetCallback("RaiseHardError", false);
    g_Apis.pUnsetCallback("CreateSection", true);
    g_Apis.pUnsetCallback("CreateSection", false);
    g_Apis.pUnsetCallback("OpenIoCompletion", true);
    g_Apis.pUnsetCallback("OpenIoCompletion", false);
    g_Apis.pUnsetCallback("SystemDebugControl", true);
    g_Apis.pUnsetCallback("SystemDebugControl", false);
    g_Apis.pUnsetCallback("TranslateFilePath", true);
    g_Apis.pUnsetCallback("TranslateFilePath", false);
    g_Apis.pUnsetCallback("CreateIRTimer", true);
    g_Apis.pUnsetCallback("CreateIRTimer", false);
    g_Apis.pUnsetCallback("CreateRegistryTransaction", true);
    g_Apis.pUnsetCallback("CreateRegistryTransaction", false);
    g_Apis.pUnsetCallback("LoadKey2", true);
    g_Apis.pUnsetCallback("LoadKey2", false);
    g_Apis.pUnsetCallback("AlpcCreatePort", true);
    g_Apis.pUnsetCallback("AlpcCreatePort", false);
    g_Apis.pUnsetCallback("DeleteWnfStateData", true);
    g_Apis.pUnsetCallback("DeleteWnfStateData", false);
    g_Apis.pUnsetCallback("SetTimerEx", true);
    g_Apis.pUnsetCallback("SetTimerEx", false);
    g_Apis.pUnsetCallback("SetLowWaitHighEventPair", true);
    g_Apis.pUnsetCallback("SetLowWaitHighEventPair", false);
    g_Apis.pUnsetCallback("AlpcCreateSecurityContext", true);
    g_Apis.pUnsetCallback("AlpcCreateSecurityContext", false);
    g_Apis.pUnsetCallback("SetCachedSigningLevel", true);
    g_Apis.pUnsetCallback("SetCachedSigningLevel", false);
    g_Apis.pUnsetCallback("SetHighEventPair", true);
    g_Apis.pUnsetCallback("SetHighEventPair", false);
    g_Apis.pUnsetCallback("ShutdownWorkerFactory", true);
    g_Apis.pUnsetCallback("ShutdownWorkerFactory", false);
    g_Apis.pUnsetCallback("SetInformationJobObject", true);
    g_Apis.pUnsetCallback("SetInformationJobObject", false);
    g_Apis.pUnsetCallback("AdjustGroupsToken", true);
    g_Apis.pUnsetCallback("AdjustGroupsToken", false);
    g_Apis.pUnsetCallback("AreMappedFilesTheSame", true);
    g_Apis.pUnsetCallback("AreMappedFilesTheSame", false);
    g_Apis.pUnsetCallback("SetBootEntryOrder", true);
    g_Apis.pUnsetCallback("SetBootEntryOrder", false);
    g_Apis.pUnsetCallback("QueryMutant", true);
    g_Apis.pUnsetCallback("QueryMutant", false);
    g_Apis.pUnsetCallback("otifyChangeSession", true);
    g_Apis.pUnsetCallback("otifyChangeSession", false);
    g_Apis.pUnsetCallback("QueryDefaultLocale", true);
    g_Apis.pUnsetCallback("QueryDefaultLocale", false);
    g_Apis.pUnsetCallback("CreateThreadEx", true);
    g_Apis.pUnsetCallback("CreateThreadEx", false);
    g_Apis.pUnsetCallback("QueryDriverEntryOrder", true);
    g_Apis.pUnsetCallback("QueryDriverEntryOrder", false);
    g_Apis.pUnsetCallback("SetTimerResolution", true);
    g_Apis.pUnsetCallback("SetTimerResolution", false);
    g_Apis.pUnsetCallback("PrePrepareEnlistment", true);
    g_Apis.pUnsetCallback("PrePrepareEnlistment", false);
    g_Apis.pUnsetCallback("CancelSynchronousIoFile", true);
    g_Apis.pUnsetCallback("CancelSynchronousIoFile", false);
    g_Apis.pUnsetCallback("QueryDirectoryFileEx", true);
    g_Apis.pUnsetCallback("QueryDirectoryFileEx", false);
    g_Apis.pUnsetCallback("AddDriverEntry", true);
    g_Apis.pUnsetCallback("AddDriverEntry", false);
    g_Apis.pUnsetCallback("UnloadKey", true);
    g_Apis.pUnsetCallback("UnloadKey", false);
    g_Apis.pUnsetCallback("CreateEvent", true);
    g_Apis.pUnsetCallback("CreateEvent", false);
    g_Apis.pUnsetCallback("OpenSession", true);
    g_Apis.pUnsetCallback("OpenSession", false);
    g_Apis.pUnsetCallback("QueryValueKey", true);
    g_Apis.pUnsetCallback("QueryValueKey", false);
    g_Apis.pUnsetCallback("CreatePrivateNamespace", true);
    g_Apis.pUnsetCallback("CreatePrivateNamespace", false);
    g_Apis.pUnsetCallback("IsUILanguageComitted", true);
    g_Apis.pUnsetCallback("IsUILanguageComitted", false);
    g_Apis.pUnsetCallback("AlertThread", true);
    g_Apis.pUnsetCallback("AlertThread", false);
    g_Apis.pUnsetCallback("QueryInstallUILanguage", true);
    g_Apis.pUnsetCallback("QueryInstallUILanguage", false);
    g_Apis.pUnsetCallback("CreateSymbolicLinkObject", true);
    g_Apis.pUnsetCallback("CreateSymbolicLinkObject", false);
    g_Apis.pUnsetCallback("AllocateUuids", true);
    g_Apis.pUnsetCallback("AllocateUuids", false);
    g_Apis.pUnsetCallback("ShutdownSystem", true);
    g_Apis.pUnsetCallback("ShutdownSystem", false);
    g_Apis.pUnsetCallback("CreateTokenEx", true);
    g_Apis.pUnsetCallback("CreateTokenEx", false);
    g_Apis.pUnsetCallback("QueryVirtualMemory", true);
    g_Apis.pUnsetCallback("QueryVirtualMemory", false);
    g_Apis.pUnsetCallback("AlpcOpenSenderProcess", true);
    g_Apis.pUnsetCallback("AlpcOpenSenderProcess", false);
    g_Apis.pUnsetCallback("AssignProcessToJobObject", true);
    g_Apis.pUnsetCallback("AssignProcessToJobObject", false);
    g_Apis.pUnsetCallback("RemoveIoCompletion", true);
    g_Apis.pUnsetCallback("RemoveIoCompletion", false);
    g_Apis.pUnsetCallback("CreateTimer2", true);
    g_Apis.pUnsetCallback("CreateTimer2", false);
    g_Apis.pUnsetCallback("CreateEnlistment", true);
    g_Apis.pUnsetCallback("CreateEnlistment", false);
    g_Apis.pUnsetCallback("RecoverEnlistment", true);
    g_Apis.pUnsetCallback("RecoverEnlistment", false);
    g_Apis.pUnsetCallback("CreateJobSet", true);
    g_Apis.pUnsetCallback("CreateJobSet", false);
    g_Apis.pUnsetCallback("SetIoCompletionEx", true);
    g_Apis.pUnsetCallback("SetIoCompletionEx", false);
    g_Apis.pUnsetCallback("CreateProcessEx", true);
    g_Apis.pUnsetCallback("CreateProcessEx", false);
    g_Apis.pUnsetCallback("AlpcConnectPortEx", true);
    g_Apis.pUnsetCallback("AlpcConnectPortEx", false);
    g_Apis.pUnsetCallback("WaitForMultipleObjects32", true);
    g_Apis.pUnsetCallback("WaitForMultipleObjects32", false);
    g_Apis.pUnsetCallback("RecoverResourceManager", true);
    g_Apis.pUnsetCallback("RecoverResourceManager", false);
    g_Apis.pUnsetCallback("AlpcSetInformation", true);
    g_Apis.pUnsetCallback("AlpcSetInformation", false);
    g_Apis.pUnsetCallback("AlpcRevokeSecurityContext", true);
    g_Apis.pUnsetCallback("AlpcRevokeSecurityContext", false);
    g_Apis.pUnsetCallback("AlpcImpersonateClientOfPort", true);
    g_Apis.pUnsetCallback("AlpcImpersonateClientOfPort", false);
    g_Apis.pUnsetCallback("ReleaseKeyedEvent", true);
    g_Apis.pUnsetCallback("ReleaseKeyedEvent", false);
    g_Apis.pUnsetCallback("TerminateThread", true);
    g_Apis.pUnsetCallback("TerminateThread", false);
    g_Apis.pUnsetCallback("SetInformationSymbolicLink", true);
    g_Apis.pUnsetCallback("SetInformationSymbolicLink", false);
    g_Apis.pUnsetCallback("DeleteObjectAuditAlarm", true);
    g_Apis.pUnsetCallback("DeleteObjectAuditAlarm", false);
    g_Apis.pUnsetCallback("WaitForKeyedEvent", true);
    g_Apis.pUnsetCallback("WaitForKeyedEvent", false);
    g_Apis.pUnsetCallback("CreatePort", true);
    g_Apis.pUnsetCallback("CreatePort", false);
    g_Apis.pUnsetCallback("DeletePrivateNamespace", true);
    g_Apis.pUnsetCallback("DeletePrivateNamespace", false);
    g_Apis.pUnsetCallback("otifyChangeMultipleKeys", true);
    g_Apis.pUnsetCallback("otifyChangeMultipleKeys", false);
    g_Apis.pUnsetCallback("LockFile", true);
    g_Apis.pUnsetCallback("LockFile", false);
    g_Apis.pUnsetCallback("QueryDefaultUILanguage", true);
    g_Apis.pUnsetCallback("QueryDefaultUILanguage", false);
    g_Apis.pUnsetCallback("OpenEventPair", true);
    g_Apis.pUnsetCallback("OpenEventPair", false);
    g_Apis.pUnsetCallback("RollforwardTransactionManager", true);
    g_Apis.pUnsetCallback("RollforwardTransactionManager", false);
    g_Apis.pUnsetCallback("AlpcQueryInformationMessage", true);
    g_Apis.pUnsetCallback("AlpcQueryInformationMessage", false);
    g_Apis.pUnsetCallback("UnmapViewOfSection", true);
    g_Apis.pUnsetCallback("UnmapViewOfSection", false);
    g_Apis.pUnsetCallback("CancelIoFile", true);
    g_Apis.pUnsetCallback("CancelIoFile", false);
    g_Apis.pUnsetCallback("CreatePagingFile", true);
    g_Apis.pUnsetCallback("CreatePagingFile", false);
    g_Apis.pUnsetCallback("CancelTimer", true);
    g_Apis.pUnsetCallback("CancelTimer", false);
    g_Apis.pUnsetCallback("ReplyWaitReceivePort", true);
    g_Apis.pUnsetCallback("ReplyWaitReceivePort", false);
    g_Apis.pUnsetCallback("CompareObjects", true);
    g_Apis.pUnsetCallback("CompareObjects", false);
    g_Apis.pUnsetCallback("SetDefaultLocale", true);
    g_Apis.pUnsetCallback("SetDefaultLocale", false);
    g_Apis.pUnsetCallback("AllocateLocallyUniqueId", true);
    g_Apis.pUnsetCallback("AllocateLocallyUniqueId", false);
    g_Apis.pUnsetCallback("AccessCheckByTypeAndAuditAlarm", true);
    g_Apis.pUnsetCallback("AccessCheckByTypeAndAuditAlarm", false);
    g_Apis.pUnsetCallback("QueryDebugFilterState", true);
    g_Apis.pUnsetCallback("QueryDebugFilterState", false);
    g_Apis.pUnsetCallback("OpenSemaphore", true);
    g_Apis.pUnsetCallback("OpenSemaphore", false);
    g_Apis.pUnsetCallback("AllocateVirtualMemory", true);
    g_Apis.pUnsetCallback("AllocateVirtualMemory", false);
    g_Apis.pUnsetCallback("ResumeProcess", true);
    g_Apis.pUnsetCallback("ResumeProcess", false);
    g_Apis.pUnsetCallback("SetContextThread", true);
    g_Apis.pUnsetCallback("SetContextThread", false);
    g_Apis.pUnsetCallback("OpenSymbolicLinkObject", true);
    g_Apis.pUnsetCallback("OpenSymbolicLinkObject", false);
    g_Apis.pUnsetCallback("ModifyDriverEntry", true);
    g_Apis.pUnsetCallback("ModifyDriverEntry", false);
    g_Apis.pUnsetCallback("SerializeBoot", true);
    g_Apis.pUnsetCallback("SerializeBoot", false);
    g_Apis.pUnsetCallback("RenameTransactionManager", true);
    g_Apis.pUnsetCallback("RenameTransactionManager", false);
    g_Apis.pUnsetCallback("RemoveIoCompletionEx", true);
    g_Apis.pUnsetCallback("RemoveIoCompletionEx", false);
    g_Apis.pUnsetCallback("MapViewOfSectionEx", true);
    g_Apis.pUnsetCallback("MapViewOfSectionEx", false);
    g_Apis.pUnsetCallback("FilterTokenEx", true);
    g_Apis.pUnsetCallback("FilterTokenEx", false);
    g_Apis.pUnsetCallback("DeleteDriverEntry", true);
    g_Apis.pUnsetCallback("DeleteDriverEntry", false);
    g_Apis.pUnsetCallback("QuerySystemInformation", true);
    g_Apis.pUnsetCallback("QuerySystemInformation", false);
    g_Apis.pUnsetCallback("SetInformationWorkerFactory", true);
    g_Apis.pUnsetCallback("SetInformationWorkerFactory", false);
    g_Apis.pUnsetCallback("AdjustTokenClaimsAndDeviceGroups", true);
    g_Apis.pUnsetCallback("AdjustTokenClaimsAndDeviceGroups", false);
    g_Apis.pUnsetCallback("SaveMergedKeys", true);
    g_Apis.pUnsetCallback("SaveMergedKeys", false);

    LOG_INFO("Plugin DeInitialized\r\n");
}
ASSERT_INTERFACE_IMPLEMENTED(StpDeInitialize, tStpDeInitialize, "StpDeInitialize does not match the interface type");

#include <Windows.h>

const static PCHAR GetConfigFilePath() {
    CHAR buffer[MAX_PATH];
    if (GetFullPathNameA("straceconfig.ini", MAX_PATH, buffer, NULL)) {
        return buffer;
    }

    return nullptr;

}

const static PCHAR GetTarget(PCHAR buffer) {
    auto filename = GetConfigFilePath();
    if (filename) {
        if (GetPrivateProfileStringA("TARGET", "exe", "", buffer, MAX_PATH, filename)) {
            return buffer;
        }
    };

    return nullptr;
}

const static PCHAR DoGetTarget() {
    CHAR buffer[MAX_PATH];
    if (GetConfigFilePath()) {
        if (GetTarget(buffer)) {
            return buffer;
        }
    }
    return nullptr;
}

void PrintStackTrace(CallerInfo& callerinfo) {
    for (int i = 0; i < callerinfo.frameDepth; i++) {
        if ((callerinfo.frames)[i].frameaddress) {
            const auto modulePathLen = (callerinfo.frames)[i].modulePath ? strlen((callerinfo.frames)[i].modulePath) : 0;

            // add brackets around module dynamically
            if (modulePathLen) {
                char moduleName[sizeof(CallerInfo::StackFrame::modulePath) + 2] = { 0 };
                moduleName[0] = '[';
                strcpy(&moduleName[1], (callerinfo.frames)[i].modulePath);
                moduleName[modulePathLen + 1] = ']';

                LOG_INFO("  %-18s +0x%08llx\r\n", moduleName, (callerinfo.frames)[i].frameaddress - (callerinfo.frames)[i].modulebase);
            }
            else {
                LOG_INFO("  %-18s 0x%016llx\r\n", "[UNKNOWN MODULE]", (callerinfo.frames)[i].frameaddress);
            }
        }
        else {
            LOG_INFO("  Frame Missing\r\n");
        }
    }
}

void LiveKernelDump(LiveKernelDumpFlags flags)
{
    const auto MANUALLY_INITIATED_CRASH = 0xE2;
    DbgkWerCaptureLiveKernelDump(L"STRACE", MANUALLY_INITIATED_CRASH, 1, 3, 3, 7, flags);
}

extern "C" __declspec(dllexport) bool StpIsTarget(CallerInfo & callerinfo) {
    auto ConfigFile = DoGetTarget();
    if (ConfigFile) {
        if (strcmp(callerinfo.processName, ConfigFile) == 0) {
                return true;
            }
    }
    return false;
}
ASSERT_INTERFACE_IMPLEMENTED(StpIsTarget, tStpIsTarget, "StpIsTarget does not match the interface type");

/**
pService: Pointer to system service from SSDT
probeId: Identifier given in KeSetSystemServiceCallback for this syscall callback
paramCount: Number of arguments this system service uses
pArgs: Argument array, usually x64 fastcall registers rcx, rdx, r8, r9
pArgSize: Length of argument array, usually hard coded to 4
pStackArgs: Pointer to stack area containing the rest of the arguments, if any
**/
extern "C" __declspec(dllexport) void StpCallbackEntry(ULONG64 pService, ULONG32 probeId, MachineState& ctx, CallerInfo& callerinfo)
{
    // !!BEWARE OF HOW MUCH STACK SPACE IS USED!!
    char sprintf_tmp_buf[256] = { 0 };

    LOG_INFO("[ENTRY] %s %s\r\n", get_probe_name((PROBE_IDS)probeId), callerinfo.processName);
    auto argTypes = get_probe_argtypes((PROBE_IDS)probeId);

    String argsString;
    uint8_t argIdx = 0;
    for (uint64_t type_id : argTypes) {
        uint64_t argValue = ctx.read_argument(argIdx);
        switch (type_id) {
        case get_type_id<MY_BOOLEAN>(): {
            string_printf(argsString, sprintf_tmp_buf, "%d - BOOLEAN: %s", argIdx, argValue ? "TRUE" : "FALSE");
            break;
        }
        case get_type_id<MY_PBOOLEAN>(): {
            BOOLEAN val = readUserArgPtr<PBOOLEAN>(argValue, g_Apis);
            string_printf(argsString, sprintf_tmp_buf, "%d - BOOLEAN*: %X->(%s)", argIdx, argValue, val ? "TRUE" : "FALSE");
            break;
        }
        case get_type_id<UCHAR>():
        case get_type_id<CHAR>(): {
            string_printf(argsString, sprintf_tmp_buf, "%d - CHAR: %02X", argIdx, argValue);
            break;
        }
        case get_type_id<UINT16>():
        case get_type_id<INT16>(): {
            string_printf(argsString, sprintf_tmp_buf, "%d - INT16: %04X", argIdx, argValue);
            break;
        }
        case get_type_id<PUINT16>():
        case get_type_id<PINT16>(): {
            UINT16 val = readUserArgPtr<PUINT16>(argValue, g_Apis);
            string_printf(argsString, sprintf_tmp_buf, "%d - INT16*: %X->(%04X)", argIdx, argValue, val);
            break;
        }
        case get_type_id<UINT32>():
        case get_type_id<INT32>(): {
            string_printf(argsString, sprintf_tmp_buf, "%d - INT32: %X", argIdx, argValue);
            break;
        }
        case get_type_id<PUINT32>():
        case get_type_id<PINT32>(): {
            UINT32 val = readUserArgPtr<PUINT32>(argValue, g_Apis);
            string_printf(argsString, sprintf_tmp_buf, "%d - INT32*: %X->(%X)", argIdx, argValue, val);
            break;
        }
        case get_type_id<ULONG>():
        case get_type_id<LONG>(): {
            string_printf(argsString, sprintf_tmp_buf, "%d - LONG: %X", argIdx, argValue);
            break;
        }
        case get_type_id<PULONG>():
        case get_type_id<PLONG>(): {
            ULONG val = readUserArgPtr<PULONG>(argValue, g_Apis);
            string_printf(argsString, sprintf_tmp_buf, "%d - LONG*: %X->(%X)", argIdx, argValue, val);
            break;
        }
        case get_type_id<ULONGLONG>():
        case get_type_id<LONGLONG>(): {
            string_printf(argsString, sprintf_tmp_buf, "%d - LONGLONG: %X", argIdx, argValue);
            break;
        }
        case get_type_id<PLONGLONG>():
        case get_type_id<PULONGLONG>(): {
            ULONGLONG val = readUserArgPtr<PULONGLONG>(argValue, g_Apis);
            string_printf(argsString, sprintf_tmp_buf, "%d - LONGLONG*: %X->(%X)", argIdx, argValue, val);
            break;
        }
        case get_type_id<PVOID>(): {
            string_printf(argsString, sprintf_tmp_buf, "%d - PVOID: %X", argIdx, argValue);
            break;
        }
        case get_type_id<PVOID*>(): {
            PVOID val = readUserArgPtr<PVOID*>(argValue, g_Apis);
            string_printf(argsString, sprintf_tmp_buf, "%d - PVOID*: %X->(%X)", argIdx, argValue, val);
            break;
        }
        case get_type_id<PSTR>(): {
            char tmp[256] = { 0 };

            uint8_t i = 0;
            for (; i < sizeof(tmp); i++) {
                if (!g_Apis.pTraceAccessMemory(&tmp[i], (ULONG_PTR)(((char*)argValue) + i), 1, 1, TRUE))
                    break;

                if (tmp[i] == 0)
                    break;
            }

            if (i > 0) {
                tmp[i] = 0; // to be safe
                string_printf(argsString, sprintf_tmp_buf, "%d - CHAR*: %s", argIdx, tmp);
            }
            break;
        }
        case get_type_id<PWSTR>(): {
            WCHAR tmp[128] = { 0 };

            uint8_t i = 0;
            for (; i < sizeof(tmp); i++) {
                if (!g_Apis.pTraceAccessMemory(&tmp[i], (ULONG_PTR)(((wchar_t*)argValue) + i), sizeof(WCHAR), sizeof(WCHAR), TRUE))
                    break;

                if (tmp[i] == 0)
                    break;
            }

            if (i > 0) {
                tmp[i] = 0; // to be safe
                string_printf(argsString, sprintf_tmp_buf, "%d - WCHAR*: %S", argIdx, tmp);
            }
            break;
        }
        case get_type_id<MY_VIRTUAL_MEMORY_INFORMATION_CLASS>(): {
            string_printf(argsString, sprintf_tmp_buf, "%d - VM_INFO: %s", argIdx, get_enum_value_name<VIRTUAL_MEMORY_INFORMATION_CLASS>(argValue));
            break;
        }
        case get_type_id<MY_PROCESSINFOCLASS>(): {
            string_printf(argsString, sprintf_tmp_buf, "%d - PROC_INFO_CLASS: %s", argIdx, get_enum_value_name<PROCESSINFOCLASS>(argValue));
            break;
        }
        case get_type_id<MY_TOKENINFOCLASS>(): {
            string_printf(argsString, sprintf_tmp_buf, "%d - TOKEN_INFO_CLASS: %s", argIdx, get_enum_value_name<TOKEN_INFO_CLASS>(argValue));
            break;
        }
        case get_type_id<MY_THREADINFOCLASS>(): {
            string_printf(argsString, sprintf_tmp_buf, "%d - THREADINFOCLASS: %s", argIdx, get_enum_value_name<THREADINFOCLASS>(argValue));
            break;
        }
        case get_type_id<MY_PMEMORY_RANGE_ENTRY>(): {
            MEMORY_RANGE_ENTRY range = readUserArgPtr<PMEMORY_RANGE_ENTRY>(argValue, g_Apis);
            string_printf(argsString, sprintf_tmp_buf, "%d - VA: %X (Size: %X)", argIdx, range.VirtualAddress, range.NumberOfBytes);
            break;
        }
        case get_type_id<MY_HANDLE>(): {
            string_printf(argsString, sprintf_tmp_buf, "%d - HANDLE: %X", argIdx, argValue);
            break;
        }
        case get_type_id<MY_PHANDLE>(): {
            HANDLE handle = readUserArgPtr<PHANDLE>(argValue, g_Apis);
            string_printf(argsString, sprintf_tmp_buf, "%d - HANDLE*: %X->(%X)", argIdx, argValue, handle);
            break;
        }
        case get_type_id<MY_ACCESS_MASK>(): {
            MY_ACCESS_MASK mask = (MY_ACCESS_MASK)argValue;
            string_printf(argsString, sprintf_tmp_buf, "%d - ACCESS_MASK: %X", argIdx, mask);
            if (mask & GENERIC_READ || mask & GENERIC_WRITE || mask & GENERIC_EXECUTE || mask & FILE_READ_DATA || mask & FILE_READ_ATTRIBUTES ||
                mask & FILE_READ_EA || mask & FILE_WRITE_DATA || mask & FILE_WRITE_ATTRIBUTES || mask & FILE_WRITE_EA || mask & FILE_APPEND_DATA || mask & FILE_EXECUTE) {
                string_printf(argsString, sprintf_tmp_buf, " (");
                if (mask & GENERIC_READ) {
                    string_printf(argsString, sprintf_tmp_buf, "GENERIC_READ|");
                }
                if (mask & GENERIC_WRITE) {
                    string_printf(argsString, sprintf_tmp_buf, "GENERIC_WRITE|");
                }
                if (mask & GENERIC_EXECUTE) {
                    string_printf(argsString, sprintf_tmp_buf, "GENERIC_EXECUTE|");
                }
                if (mask & FILE_READ_DATA) {
                    string_printf(argsString, sprintf_tmp_buf, "FILE_READ_DATA|");
                }
                if (mask & FILE_READ_ATTRIBUTES) {
                    string_printf(argsString, sprintf_tmp_buf, "FILE_READ_ATTRIBUTES|");
                }
                if (mask & FILE_READ_EA) {
                    string_printf(argsString, sprintf_tmp_buf, "FILE_READ_EA|");
                }
                if (mask & FILE_WRITE_DATA) {
                    string_printf(argsString, sprintf_tmp_buf, "FILE_WRITE_DATA|");
                }
                if (mask & FILE_WRITE_ATTRIBUTES) {
                    string_printf(argsString, sprintf_tmp_buf, "FILE_WRITE_ATTRIBUTES|");
                }
                if (mask & FILE_WRITE_EA) {
                    string_printf(argsString, sprintf_tmp_buf, "FILE_WRITE_EA|");
                }
                if (mask & FILE_APPEND_DATA) {
                    string_printf(argsString, sprintf_tmp_buf, "FILE_APPEND_DATA|");
                }
                if (mask & FILE_EXECUTE) {
                    string_printf(argsString, sprintf_tmp_buf, "FILE_EXECUTE|");
                }
                string_printf(argsString, sprintf_tmp_buf, ")");
            }
            break;
        }
        case get_type_id<PLARGE_INTEGER>(): {
            LARGE_INTEGER largeInt = readUserArgPtr<PLARGE_INTEGER>(argValue, g_Apis);
            string_printf(argsString, sprintf_tmp_buf, "%d - LARGE_INTEGER: %08X", argIdx, largeInt.QuadPart);
            break;
        }
        case get_type_id<PUNICODE_STRING>(): {
            UNICODE_STRING ustr = readUserArgPtr<PUNICODE_STRING>(argValue, g_Apis);
            string_printf(argsString, sprintf_tmp_buf, "%d - USTR: %wZ", argIdx, &ustr);
            break;
        }
        case get_type_id<POBJECT_ATTRIBUTES>(): {
            OBJECT_ATTRIBUTES attrs = readUserArgPtr<POBJECT_ATTRIBUTES>(argValue, g_Apis);
            UNICODE_STRING ustr = readUserArgPtr<PUNICODE_STRING>(attrs.ObjectName, g_Apis);
            string_printf(argsString, sprintf_tmp_buf, "%d - OBJ_ATTRS::USTR: %wZ", argIdx, &ustr);
            break;
        }
        default:
            string_printf(argsString, sprintf_tmp_buf, "%d - NOT_IMPLEMENTED", argIdx);
            break;
        }

        // seperate args if not at last one
        if (argIdx != argTypes.size() - 1) {
            string_printf(argsString, sprintf_tmp_buf, ", ");
        }
        argIdx++;
    }
    if (argsString.size()) {
        LOG_INFO("Args(%s)\r\n", argsString.data());
    }
    PrintStackTrace(callerinfo);
}
ASSERT_INTERFACE_IMPLEMENTED(StpCallbackEntry, tStpCallbackEntryPlugin, "StpCallbackEntry does not match the interface type");

/**
pService: Pointer to system service from SSDT
probeId: Identifier given in KeSetSystemServiceCallback for this syscall callback
paramCount: Number of arguments this system service uses, usually hard coded to 1
pArgs: Argument array, usually a single entry that holds return value
pArgSize: Length of argument array, usually hard coded to 1
pStackArgs: Pointer to stack area containing the rest of the arguments, if any
**/
extern "C" __declspec(dllexport) void StpCallbackReturn(ULONG64 pService, ULONG32 probeId, MachineState& ctx, CallerInfo & callerinfo) {
    if (strcmp(callerinfo.processName, "test.exe") == 0) {
        LOG_INFO("[RETURN] %s %s\r\n", get_probe_name((PROBE_IDS)probeId), callerinfo.processName);
    }
}
ASSERT_INTERFACE_IMPLEMENTED(StpCallbackReturn, tStpCallbackReturnPlugin, "StpCallbackEntry does not match the interface type");

BOOL APIENTRY Main(HMODULE hModule, DWORD  reason, LPVOID lpReserved)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

