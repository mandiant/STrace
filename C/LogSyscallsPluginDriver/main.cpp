#pragma warning(disable: 4996) //exallocatepoolwithtag
#pragma warning(disable: 4244) // conversion from uint64_t to base, possible loss of data
#pragma warning(disable: 4100) // unreferenced param
#include <ntifs.h>

#include "interface.h"
#include "utils.h"
#include "probedefs.h"

const unsigned long PLUGIN_POOL_TAG = ' xtS';

#pragma warning(disable: 6011)
PluginApis g_Apis;

#define DBGPRINT(format, ...)  DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[STRACE] " format "\n", __VA_ARGS__)
#define LOG_DEBUG(fmt,...)  g_Apis.pLogPrint(LogLevelDebug, __FUNCTION__, fmt,   __VA_ARGS__)
#define LOG_INFO(fmt,...)   g_Apis.pLogPrint(LogLevelInfo,  __FUNCTION__, fmt,   __VA_ARGS__)
#define LOG_WARN(fmt,...)   g_Apis.pLogPrint(LogLevelWarn,  __FUNCTION__, fmt,   __VA_ARGS__)
#define LOG_ERROR(fmt,...)  g_Apis.pLogPrint(LogLevelError, __FUNCTION__, fmt,   __VA_ARGS__)


extern "C" __declspec(dllexport) void StpInitialize(PluginApis & pApis) {
	g_Apis = pApis;
	LOG_INFO("Plugin Initializing...\r\n");
	g_Apis.pSetCallback("LockProductActivationKeys", PROBE_IDS::IdLockProductActivationKeys);
	g_Apis.pSetCallback("WaitHighEventPair", PROBE_IDS::IdWaitHighEventPair);
	g_Apis.pSetCallback("RegisterThreadTerminatePort", PROBE_IDS::IdRegisterThreadTerminatePort);
	g_Apis.pSetCallback("AssociateWaitCompletionPacket", PROBE_IDS::IdAssociateWaitCompletionPacket);
	g_Apis.pSetCallback("QueryPerformanceCounter", PROBE_IDS::IdQueryPerformanceCounter);
	g_Apis.pSetCallback("CompactKeys", PROBE_IDS::IdCompactKeys);
	g_Apis.pSetCallback("QuerySystemInformationEx", PROBE_IDS::IdQuerySystemInformationEx);
	g_Apis.pSetCallback("ResetEvent", PROBE_IDS::IdResetEvent);
	g_Apis.pSetCallback("GetContextThread", PROBE_IDS::IdGetContextThread);
	g_Apis.pSetCallback("QueryInformationThread", PROBE_IDS::IdQueryInformationThread);
	g_Apis.pSetCallback("WaitForSingleObject", PROBE_IDS::IdWaitForSingleObject);
	g_Apis.pSetCallback("FlushBuffersFileEx", PROBE_IDS::IdFlushBuffersFileEx);
	g_Apis.pSetCallback("UnloadKey2", PROBE_IDS::IdUnloadKey2);
	g_Apis.pSetCallback("ReadOnlyEnlistment", PROBE_IDS::IdReadOnlyEnlistment);
	g_Apis.pSetCallback("DeleteFile", PROBE_IDS::IdDeleteFile);
	g_Apis.pSetCallback("DeleteAtom", PROBE_IDS::IdDeleteAtom);
	g_Apis.pSetCallback("QueryDirectoryFile", PROBE_IDS::IdQueryDirectoryFile);
	g_Apis.pSetCallback("SetEventBoostPriority", PROBE_IDS::IdSetEventBoostPriority);
	g_Apis.pSetCallback("AllocateUserPhysicalPagesEx", PROBE_IDS::IdAllocateUserPhysicalPagesEx);
	g_Apis.pSetCallback("WriteFile", PROBE_IDS::IdWriteFile);
	g_Apis.pSetCallback("QueryInformationFile", PROBE_IDS::IdQueryInformationFile);
	g_Apis.pSetCallback("AlpcCancelMessage", PROBE_IDS::IdAlpcCancelMessage);
	g_Apis.pSetCallback("OpenMutant", PROBE_IDS::IdOpenMutant);
	g_Apis.pSetCallback("CreatePartition", PROBE_IDS::IdCreatePartition);
	g_Apis.pSetCallback("QueryTimer", PROBE_IDS::IdQueryTimer);
	g_Apis.pSetCallback("OpenEvent", PROBE_IDS::IdOpenEvent);
	g_Apis.pSetCallback("OpenObjectAuditAlarm", PROBE_IDS::IdOpenObjectAuditAlarm);
	g_Apis.pSetCallback("MakePermanentObject", PROBE_IDS::IdMakePermanentObject);
	g_Apis.pSetCallback("CommitTransaction", PROBE_IDS::IdCommitTransaction);
	g_Apis.pSetCallback("SetSystemTime", PROBE_IDS::IdSetSystemTime);
	g_Apis.pSetCallback("GetDevicePowerState", PROBE_IDS::IdGetDevicePowerState);
	g_Apis.pSetCallback("SetSystemPowerState", PROBE_IDS::IdSetSystemPowerState);
	g_Apis.pSetCallback("AlpcCreateResourceReserve", PROBE_IDS::IdAlpcCreateResourceReserve);
	g_Apis.pSetCallback("UnlockFile", PROBE_IDS::IdUnlockFile);
	g_Apis.pSetCallback("AlpcDeletePortSection", PROBE_IDS::IdAlpcDeletePortSection);
	g_Apis.pSetCallback("SetInformationResourceManager", PROBE_IDS::IdSetInformationResourceManager);
	g_Apis.pSetCallback("FreeUserPhysicalPages", PROBE_IDS::IdFreeUserPhysicalPages);
	g_Apis.pSetCallback("LoadKeyEx", PROBE_IDS::IdLoadKeyEx);
	g_Apis.pSetCallback("PropagationComplete", PROBE_IDS::IdPropagationComplete);
	g_Apis.pSetCallback("AccessCheckByTypeResultListAndAuditAlarm", PROBE_IDS::IdAccessCheckByTypeResultListAndAuditAlarm);
	g_Apis.pSetCallback("QueryInformationToken", PROBE_IDS::IdQueryInformationToken);
	g_Apis.pSetCallback("RegisterProtocolAddressInformation", PROBE_IDS::IdRegisterProtocolAddressInformation);
	g_Apis.pSetCallback("ProtectVirtualMemory", PROBE_IDS::IdProtectVirtualMemory);
	g_Apis.pSetCallback("CreateKey", PROBE_IDS::IdCreateKey);
	g_Apis.pSetCallback("AlpcSendWaitReceivePort", PROBE_IDS::IdAlpcSendWaitReceivePort);
	g_Apis.pSetCallback("OpenRegistryTransaction", PROBE_IDS::IdOpenRegistryTransaction);
	g_Apis.pSetCallback("TerminateProcess", PROBE_IDS::IdTerminateProcess);
	g_Apis.pSetCallback("PowerInformation", PROBE_IDS::IdPowerInformation);
	g_Apis.pSetCallback("otifyChangeDirectoryFile", PROBE_IDS::IdotifyChangeDirectoryFile);
	g_Apis.pSetCallback("CreateTransaction", PROBE_IDS::IdCreateTransaction);
	g_Apis.pSetCallback("CreateProfileEx", PROBE_IDS::IdCreateProfileEx);
	g_Apis.pSetCallback("QueryLicenseValue", PROBE_IDS::IdQueryLicenseValue);
	g_Apis.pSetCallback("CreateProfile", PROBE_IDS::IdCreateProfile);
	g_Apis.pSetCallback("InitializeRegistry", PROBE_IDS::IdInitializeRegistry);
	g_Apis.pSetCallback("FreezeTransactions", PROBE_IDS::IdFreezeTransactions);
	g_Apis.pSetCallback("OpenJobObject", PROBE_IDS::IdOpenJobObject);
	g_Apis.pSetCallback("SubscribeWnfStateChange", PROBE_IDS::IdSubscribeWnfStateChange);
	g_Apis.pSetCallback("GetWriteWatch", PROBE_IDS::IdGetWriteWatch);
	g_Apis.pSetCallback("GetCachedSigningLevel", PROBE_IDS::IdGetCachedSigningLevel);
	g_Apis.pSetCallback("SetSecurityObject", PROBE_IDS::IdSetSecurityObject);
	g_Apis.pSetCallback("QueryIntervalProfile", PROBE_IDS::IdQueryIntervalProfile);
	g_Apis.pSetCallback("PropagationFailed", PROBE_IDS::IdPropagationFailed);
	g_Apis.pSetCallback("CreateSectionEx", PROBE_IDS::IdCreateSectionEx);
	g_Apis.pSetCallback("RaiseException", PROBE_IDS::IdRaiseException);
	g_Apis.pSetCallback("SetCachedSigningLevel2", PROBE_IDS::IdSetCachedSigningLevel2);
	g_Apis.pSetCallback("CommitEnlistment", PROBE_IDS::IdCommitEnlistment);
	g_Apis.pSetCallback("QueryInformationByName", PROBE_IDS::IdQueryInformationByName);
	g_Apis.pSetCallback("CreateThread", PROBE_IDS::IdCreateThread);
	g_Apis.pSetCallback("OpenResourceManager", PROBE_IDS::IdOpenResourceManager);
	g_Apis.pSetCallback("ReadRequestData", PROBE_IDS::IdReadRequestData);
	g_Apis.pSetCallback("ClearEvent", PROBE_IDS::IdClearEvent);
	g_Apis.pSetCallback("TestAlert", PROBE_IDS::IdTestAlert);
	g_Apis.pSetCallback("SetInformationThread", PROBE_IDS::IdSetInformationThread);
	g_Apis.pSetCallback("SetTimer2", PROBE_IDS::IdSetTimer2);
	g_Apis.pSetCallback("SetDefaultUILanguage", PROBE_IDS::IdSetDefaultUILanguage);
	g_Apis.pSetCallback("EnumerateValueKey", PROBE_IDS::IdEnumerateValueKey);
	g_Apis.pSetCallback("OpenEnlistment", PROBE_IDS::IdOpenEnlistment);
	g_Apis.pSetCallback("SetIntervalProfile", PROBE_IDS::IdSetIntervalProfile);
	g_Apis.pSetCallback("QueryPortInformationProcess", PROBE_IDS::IdQueryPortInformationProcess);
	g_Apis.pSetCallback("QueryInformationTransactionManager", PROBE_IDS::IdQueryInformationTransactionManager);
	g_Apis.pSetCallback("SetInformationTransactionManager", PROBE_IDS::IdSetInformationTransactionManager);
	g_Apis.pSetCallback("InitializeEnclave", PROBE_IDS::IdInitializeEnclave);
	g_Apis.pSetCallback("PrepareComplete", PROBE_IDS::IdPrepareComplete);
	g_Apis.pSetCallback("QueueApcThread", PROBE_IDS::IdQueueApcThread);
	g_Apis.pSetCallback("WorkerFactoryWorkerReady", PROBE_IDS::IdWorkerFactoryWorkerReady);
	g_Apis.pSetCallback("GetCompleteWnfStateSubscription", PROBE_IDS::IdGetCompleteWnfStateSubscription);
	g_Apis.pSetCallback("AlertThreadByThreadId", PROBE_IDS::IdAlertThreadByThreadId);
	g_Apis.pSetCallback("LockVirtualMemory", PROBE_IDS::IdLockVirtualMemory);
	g_Apis.pSetCallback("DeviceIoControlFile", PROBE_IDS::IdDeviceIoControlFile);
	g_Apis.pSetCallback("CreateUserProcess", PROBE_IDS::IdCreateUserProcess);
	g_Apis.pSetCallback("QuerySection", PROBE_IDS::IdQuerySection);
	g_Apis.pSetCallback("SaveKeyEx", PROBE_IDS::IdSaveKeyEx);
	g_Apis.pSetCallback("RollbackTransaction", PROBE_IDS::IdRollbackTransaction);
	g_Apis.pSetCallback("TraceEvent", PROBE_IDS::IdTraceEvent);
	g_Apis.pSetCallback("OpenSection", PROBE_IDS::IdOpenSection);
	g_Apis.pSetCallback("RequestPort", PROBE_IDS::IdRequestPort);
	g_Apis.pSetCallback("UnsubscribeWnfStateChange", PROBE_IDS::IdUnsubscribeWnfStateChange);
	g_Apis.pSetCallback("ThawRegistry", PROBE_IDS::IdThawRegistry);
	g_Apis.pSetCallback("CreateJobObject", PROBE_IDS::IdCreateJobObject);
	g_Apis.pSetCallback("OpenKeyTransactedEx", PROBE_IDS::IdOpenKeyTransactedEx);
	g_Apis.pSetCallback("WaitForMultipleObjects", PROBE_IDS::IdWaitForMultipleObjects);
	g_Apis.pSetCallback("DuplicateToken", PROBE_IDS::IdDuplicateToken);
	g_Apis.pSetCallback("AlpcOpenSenderThread", PROBE_IDS::IdAlpcOpenSenderThread);
	g_Apis.pSetCallback("AlpcImpersonateClientContainerOfPort", PROBE_IDS::IdAlpcImpersonateClientContainerOfPort);
	g_Apis.pSetCallback("DrawText", PROBE_IDS::IdDrawText);
	g_Apis.pSetCallback("ReleaseSemaphore", PROBE_IDS::IdReleaseSemaphore);
	g_Apis.pSetCallback("SetQuotaInformationFile", PROBE_IDS::IdSetQuotaInformationFile);
	g_Apis.pSetCallback("QueryInformationAtom", PROBE_IDS::IdQueryInformationAtom);
	g_Apis.pSetCallback("EnumerateBootEntries", PROBE_IDS::IdEnumerateBootEntries);
	g_Apis.pSetCallback("ThawTransactions", PROBE_IDS::IdThawTransactions);
	g_Apis.pSetCallback("AccessCheck", PROBE_IDS::IdAccessCheck);
	g_Apis.pSetCallback("FlushProcessWriteBuffers", PROBE_IDS::IdFlushProcessWriteBuffers);
	g_Apis.pSetCallback("QuerySemaphore", PROBE_IDS::IdQuerySemaphore);
	g_Apis.pSetCallback("CreateNamedPipeFile", PROBE_IDS::IdCreateNamedPipeFile);
	g_Apis.pSetCallback("AlpcDeleteResourceReserve", PROBE_IDS::IdAlpcDeleteResourceReserve);
	g_Apis.pSetCallback("QuerySystemEnvironmentValueEx", PROBE_IDS::IdQuerySystemEnvironmentValueEx);
	g_Apis.pSetCallback("ReadFileScatter", PROBE_IDS::IdReadFileScatter);
	g_Apis.pSetCallback("OpenKeyEx", PROBE_IDS::IdOpenKeyEx);
	g_Apis.pSetCallback("SignalAndWaitForSingleObject", PROBE_IDS::IdSignalAndWaitForSingleObject);
	g_Apis.pSetCallback("ReleaseMutant", PROBE_IDS::IdReleaseMutant);
	g_Apis.pSetCallback("TerminateJobObject", PROBE_IDS::IdTerminateJobObject);
	g_Apis.pSetCallback("SetSystemEnvironmentValue", PROBE_IDS::IdSetSystemEnvironmentValue);
	g_Apis.pSetCallback("Close", PROBE_IDS::IdClose);
	g_Apis.pSetCallback("QueueApcThreadEx", PROBE_IDS::IdQueueApcThreadEx);
	g_Apis.pSetCallback("QueryMultipleValueKey", PROBE_IDS::IdQueryMultipleValueKey);
	g_Apis.pSetCallback("AlpcQueryInformation", PROBE_IDS::IdAlpcQueryInformation);
	g_Apis.pSetCallback("UpdateWnfStateData", PROBE_IDS::IdUpdateWnfStateData);
	g_Apis.pSetCallback("ListenPort", PROBE_IDS::IdListenPort);
	g_Apis.pSetCallback("FlushInstructionCache", PROBE_IDS::IdFlushInstructionCache);
	g_Apis.pSetCallback("GetNotificationResourceManager", PROBE_IDS::IdGetNotificationResourceManager);
	g_Apis.pSetCallback("QueryFullAttributesFile", PROBE_IDS::IdQueryFullAttributesFile);
	g_Apis.pSetCallback("SuspendThread", PROBE_IDS::IdSuspendThread);
	g_Apis.pSetCallback("CompareTokens", PROBE_IDS::IdCompareTokens);
	g_Apis.pSetCallback("CancelWaitCompletionPacket", PROBE_IDS::IdCancelWaitCompletionPacket);
	g_Apis.pSetCallback("AlpcAcceptConnectPort", PROBE_IDS::IdAlpcAcceptConnectPort);
	g_Apis.pSetCallback("OpenTransaction", PROBE_IDS::IdOpenTransaction);
	g_Apis.pSetCallback("ImpersonateAnonymousToken", PROBE_IDS::IdImpersonateAnonymousToken);
	g_Apis.pSetCallback("QuerySecurityObject", PROBE_IDS::IdQuerySecurityObject);
	g_Apis.pSetCallback("RollbackEnlistment", PROBE_IDS::IdRollbackEnlistment);
	g_Apis.pSetCallback("ReplacePartitionUnit", PROBE_IDS::IdReplacePartitionUnit);
	g_Apis.pSetCallback("CreateKeyTransacted", PROBE_IDS::IdCreateKeyTransacted);
	g_Apis.pSetCallback("ConvertBetweenAuxiliaryCounterAndPerformanceCounter", PROBE_IDS::IdConvertBetweenAuxiliaryCounterAndPerformanceCounter);
	g_Apis.pSetCallback("CreateKeyedEvent", PROBE_IDS::IdCreateKeyedEvent);
	g_Apis.pSetCallback("CreateEventPair", PROBE_IDS::IdCreateEventPair);
	g_Apis.pSetCallback("AddAtom", PROBE_IDS::IdAddAtom);
	g_Apis.pSetCallback("QueryOpenSubKeys", PROBE_IDS::IdQueryOpenSubKeys);
	g_Apis.pSetCallback("QuerySystemTime", PROBE_IDS::IdQuerySystemTime);
	g_Apis.pSetCallback("SetEaFile", PROBE_IDS::IdSetEaFile);
	g_Apis.pSetCallback("SetInformationProcess", PROBE_IDS::IdSetInformationProcess);
	g_Apis.pSetCallback("SetValueKey", PROBE_IDS::IdSetValueKey);
	g_Apis.pSetCallback("QuerySymbolicLinkObject", PROBE_IDS::IdQuerySymbolicLinkObject);
	g_Apis.pSetCallback("QueryOpenSubKeysEx", PROBE_IDS::IdQueryOpenSubKeysEx);
	g_Apis.pSetCallback("otifyChangeKey", PROBE_IDS::IdotifyChangeKey);
	g_Apis.pSetCallback("IsProcessInJob", PROBE_IDS::IdIsProcessInJob);
	g_Apis.pSetCallback("CommitComplete", PROBE_IDS::IdCommitComplete);
	g_Apis.pSetCallback("EnumerateDriverEntries", PROBE_IDS::IdEnumerateDriverEntries);
	g_Apis.pSetCallback("AccessCheckByTypeResultList", PROBE_IDS::IdAccessCheckByTypeResultList);
	g_Apis.pSetCallback("LoadEnclaveData", PROBE_IDS::IdLoadEnclaveData);
	g_Apis.pSetCallback("AllocateVirtualMemoryEx", PROBE_IDS::IdAllocateVirtualMemoryEx);
	g_Apis.pSetCallback("WaitForWorkViaWorkerFactory", PROBE_IDS::IdWaitForWorkViaWorkerFactory);
	g_Apis.pSetCallback("QueryInformationResourceManager", PROBE_IDS::IdQueryInformationResourceManager);
	g_Apis.pSetCallback("EnumerateKey", PROBE_IDS::IdEnumerateKey);
	g_Apis.pSetCallback("GetMUIRegistryInfo", PROBE_IDS::IdGetMUIRegistryInfo);
	g_Apis.pSetCallback("AcceptConnectPort", PROBE_IDS::IdAcceptConnectPort);
	g_Apis.pSetCallback("RecoverTransactionManager", PROBE_IDS::IdRecoverTransactionManager);
	g_Apis.pSetCallback("WriteVirtualMemory", PROBE_IDS::IdWriteVirtualMemory);
	g_Apis.pSetCallback("QueryBootOptions", PROBE_IDS::IdQueryBootOptions);
	g_Apis.pSetCallback("RollbackComplete", PROBE_IDS::IdRollbackComplete);
	g_Apis.pSetCallback("QueryAuxiliaryCounterFrequency", PROBE_IDS::IdQueryAuxiliaryCounterFrequency);
	g_Apis.pSetCallback("AlpcCreatePortSection", PROBE_IDS::IdAlpcCreatePortSection);
	g_Apis.pSetCallback("QueryObject", PROBE_IDS::IdQueryObject);
	g_Apis.pSetCallback("QueryWnfStateData", PROBE_IDS::IdQueryWnfStateData);
	g_Apis.pSetCallback("InitiatePowerAction", PROBE_IDS::IdInitiatePowerAction);
	g_Apis.pSetCallback("DirectGraphicsCall", PROBE_IDS::IdDirectGraphicsCall);
	g_Apis.pSetCallback("AcquireCrossVmMutant", PROBE_IDS::IdAcquireCrossVmMutant);
	g_Apis.pSetCallback("RollbackRegistryTransaction", PROBE_IDS::IdRollbackRegistryTransaction);
	g_Apis.pSetCallback("AlertResumeThread", PROBE_IDS::IdAlertResumeThread);
	g_Apis.pSetCallback("PssCaptureVaSpaceBulk", PROBE_IDS::IdPssCaptureVaSpaceBulk);
	g_Apis.pSetCallback("CreateToken", PROBE_IDS::IdCreateToken);
	g_Apis.pSetCallback("PrepareEnlistment", PROBE_IDS::IdPrepareEnlistment);
	g_Apis.pSetCallback("FlushWriteBuffer", PROBE_IDS::IdFlushWriteBuffer);
	g_Apis.pSetCallback("CommitRegistryTransaction", PROBE_IDS::IdCommitRegistryTransaction);
	g_Apis.pSetCallback("AccessCheckByType", PROBE_IDS::IdAccessCheckByType);
	g_Apis.pSetCallback("OpenThread", PROBE_IDS::IdOpenThread);
	g_Apis.pSetCallback("AccessCheckAndAuditAlarm", PROBE_IDS::IdAccessCheckAndAuditAlarm);
	g_Apis.pSetCallback("OpenThreadTokenEx", PROBE_IDS::IdOpenThreadTokenEx);
	g_Apis.pSetCallback("WriteRequestData", PROBE_IDS::IdWriteRequestData);
	g_Apis.pSetCallback("CreateWorkerFactory", PROBE_IDS::IdCreateWorkerFactory);
	g_Apis.pSetCallback("OpenPartition", PROBE_IDS::IdOpenPartition);
	g_Apis.pSetCallback("SetSystemInformation", PROBE_IDS::IdSetSystemInformation);
	g_Apis.pSetCallback("EnumerateSystemEnvironmentValuesEx", PROBE_IDS::IdEnumerateSystemEnvironmentValuesEx);
	g_Apis.pSetCallback("CreateWnfStateName", PROBE_IDS::IdCreateWnfStateName);
	g_Apis.pSetCallback("QueryInformationJobObject", PROBE_IDS::IdQueryInformationJobObject);
	g_Apis.pSetCallback("PrivilegedServiceAuditAlarm", PROBE_IDS::IdPrivilegedServiceAuditAlarm);
	g_Apis.pSetCallback("EnableLastKnownGood", PROBE_IDS::IdEnableLastKnownGood);
	g_Apis.pSetCallback("otifyChangeDirectoryFileEx", PROBE_IDS::IdotifyChangeDirectoryFileEx);
	g_Apis.pSetCallback("CreateWaitablePort", PROBE_IDS::IdCreateWaitablePort);
	g_Apis.pSetCallback("WaitForAlertByThreadId", PROBE_IDS::IdWaitForAlertByThreadId);
	g_Apis.pSetCallback("GetNextProcess", PROBE_IDS::IdGetNextProcess);
	g_Apis.pSetCallback("OpenKeyedEvent", PROBE_IDS::IdOpenKeyedEvent);
	g_Apis.pSetCallback("DeleteBootEntry", PROBE_IDS::IdDeleteBootEntry);
	g_Apis.pSetCallback("FilterToken", PROBE_IDS::IdFilterToken);
	g_Apis.pSetCallback("CompressKey", PROBE_IDS::IdCompressKey);
	g_Apis.pSetCallback("ModifyBootEntry", PROBE_IDS::IdModifyBootEntry);
	g_Apis.pSetCallback("SetInformationTransaction", PROBE_IDS::IdSetInformationTransaction);
	g_Apis.pSetCallback("PlugPlayControl", PROBE_IDS::IdPlugPlayControl);
	g_Apis.pSetCallback("OpenDirectoryObject", PROBE_IDS::IdOpenDirectoryObject);
	g_Apis.pSetCallback("Continue", PROBE_IDS::IdContinue);
	g_Apis.pSetCallback("PrivilegeObjectAuditAlarm", PROBE_IDS::IdPrivilegeObjectAuditAlarm);
	g_Apis.pSetCallback("QueryKey", PROBE_IDS::IdQueryKey);
	g_Apis.pSetCallback("FilterBootOption", PROBE_IDS::IdFilterBootOption);
	g_Apis.pSetCallback("YieldExecution", PROBE_IDS::IdYieldExecution);
	g_Apis.pSetCallback("ResumeThread", PROBE_IDS::IdResumeThread);
	g_Apis.pSetCallback("AddBootEntry", PROBE_IDS::IdAddBootEntry);
	g_Apis.pSetCallback("GetCurrentProcessorNumberEx", PROBE_IDS::IdGetCurrentProcessorNumberEx);
	g_Apis.pSetCallback("CreateLowBoxToken", PROBE_IDS::IdCreateLowBoxToken);
	g_Apis.pSetCallback("FlushBuffersFile", PROBE_IDS::IdFlushBuffersFile);
	g_Apis.pSetCallback("DelayExecution", PROBE_IDS::IdDelayExecution);
	g_Apis.pSetCallback("OpenKey", PROBE_IDS::IdOpenKey);
	g_Apis.pSetCallback("StopProfile", PROBE_IDS::IdStopProfile);
	g_Apis.pSetCallback("SetEvent", PROBE_IDS::IdSetEvent);
	g_Apis.pSetCallback("RestoreKey", PROBE_IDS::IdRestoreKey);
	g_Apis.pSetCallback("ExtendSection", PROBE_IDS::IdExtendSection);
	g_Apis.pSetCallback("InitializeNlsFiles", PROBE_IDS::IdInitializeNlsFiles);
	g_Apis.pSetCallback("FindAtom", PROBE_IDS::IdFindAtom);
	g_Apis.pSetCallback("DisplayString", PROBE_IDS::IdDisplayString);
	g_Apis.pSetCallback("LoadDriver", PROBE_IDS::IdLoadDriver);
	g_Apis.pSetCallback("QueryWnfStateNameInformation", PROBE_IDS::IdQueryWnfStateNameInformation);
	g_Apis.pSetCallback("CreateMutant", PROBE_IDS::IdCreateMutant);
	g_Apis.pSetCallback("FlushKey", PROBE_IDS::IdFlushKey);
	g_Apis.pSetCallback("DuplicateObject", PROBE_IDS::IdDuplicateObject);
	g_Apis.pSetCallback("CancelTimer2", PROBE_IDS::IdCancelTimer2);
	g_Apis.pSetCallback("QueryAttributesFile", PROBE_IDS::IdQueryAttributesFile);
	g_Apis.pSetCallback("CompareSigningLevels", PROBE_IDS::IdCompareSigningLevels);
	g_Apis.pSetCallback("AccessCheckByTypeResultListAndAuditAlarmByHandle", PROBE_IDS::IdAccessCheckByTypeResultListAndAuditAlarmByHandle);
	g_Apis.pSetCallback("DeleteValueKey", PROBE_IDS::IdDeleteValueKey);
	g_Apis.pSetCallback("SetDebugFilterState", PROBE_IDS::IdSetDebugFilterState);
	g_Apis.pSetCallback("PulseEvent", PROBE_IDS::IdPulseEvent);
	g_Apis.pSetCallback("AllocateReserveObject", PROBE_IDS::IdAllocateReserveObject);
	g_Apis.pSetCallback("AlpcDisconnectPort", PROBE_IDS::IdAlpcDisconnectPort);
	g_Apis.pSetCallback("QueryTimerResolution", PROBE_IDS::IdQueryTimerResolution);
	g_Apis.pSetCallback("DeleteKey", PROBE_IDS::IdDeleteKey);
	g_Apis.pSetCallback("CreateFile", PROBE_IDS::IdCreateFile);
	g_Apis.pSetCallback("ReplyPort", PROBE_IDS::IdReplyPort);
	g_Apis.pSetCallback("GetNlsSectionPtr", PROBE_IDS::IdGetNlsSectionPtr);
	g_Apis.pSetCallback("QueryInformationProcess", PROBE_IDS::IdQueryInformationProcess);
	g_Apis.pSetCallback("ReplyWaitReceivePortEx", PROBE_IDS::IdReplyWaitReceivePortEx);
	g_Apis.pSetCallback("UmsThreadYield", PROBE_IDS::IdUmsThreadYield);
	g_Apis.pSetCallback("ManagePartition", PROBE_IDS::IdManagePartition);
	g_Apis.pSetCallback("AdjustPrivilegesToken", PROBE_IDS::IdAdjustPrivilegesToken);
	g_Apis.pSetCallback("CreateCrossVmMutant", PROBE_IDS::IdCreateCrossVmMutant);
	g_Apis.pSetCallback("CreateDirectoryObject", PROBE_IDS::IdCreateDirectoryObject);
	g_Apis.pSetCallback("OpenFile", PROBE_IDS::IdOpenFile);
	g_Apis.pSetCallback("SetInformationVirtualMemory", PROBE_IDS::IdSetInformationVirtualMemory);
	g_Apis.pSetCallback("TerminateEnclave", PROBE_IDS::IdTerminateEnclave);
	g_Apis.pSetCallback("SuspendProcess", PROBE_IDS::IdSuspendProcess);
	g_Apis.pSetCallback("ReplyWaitReplyPort", PROBE_IDS::IdReplyWaitReplyPort);
	g_Apis.pSetCallback("OpenTransactionManager", PROBE_IDS::IdOpenTransactionManager);
	g_Apis.pSetCallback("CreateSemaphore", PROBE_IDS::IdCreateSemaphore);
	g_Apis.pSetCallback("UnmapViewOfSectionEx", PROBE_IDS::IdUnmapViewOfSectionEx);
	g_Apis.pSetCallback("MapViewOfSection", PROBE_IDS::IdMapViewOfSection);
	g_Apis.pSetCallback("DisableLastKnownGood", PROBE_IDS::IdDisableLastKnownGood);
	g_Apis.pSetCallback("GetNextThread", PROBE_IDS::IdGetNextThread);
	g_Apis.pSetCallback("MakeTemporaryObject", PROBE_IDS::IdMakeTemporaryObject);
	g_Apis.pSetCallback("SetInformationFile", PROBE_IDS::IdSetInformationFile);
	g_Apis.pSetCallback("CreateTransactionManager", PROBE_IDS::IdCreateTransactionManager);
	g_Apis.pSetCallback("WriteFileGather", PROBE_IDS::IdWriteFileGather);
	g_Apis.pSetCallback("QueryInformationTransaction", PROBE_IDS::IdQueryInformationTransaction);
	g_Apis.pSetCallback("FlushVirtualMemory", PROBE_IDS::IdFlushVirtualMemory);
	g_Apis.pSetCallback("QueryQuotaInformationFile", PROBE_IDS::IdQueryQuotaInformationFile);
	g_Apis.pSetCallback("SetVolumeInformationFile", PROBE_IDS::IdSetVolumeInformationFile);
	g_Apis.pSetCallback("QueryInformationEnlistment", PROBE_IDS::IdQueryInformationEnlistment);
	g_Apis.pSetCallback("CreateIoCompletion", PROBE_IDS::IdCreateIoCompletion);
	g_Apis.pSetCallback("UnloadKeyEx", PROBE_IDS::IdUnloadKeyEx);
	g_Apis.pSetCallback("QueryEaFile", PROBE_IDS::IdQueryEaFile);
	g_Apis.pSetCallback("QueryDirectoryObject", PROBE_IDS::IdQueryDirectoryObject);
	g_Apis.pSetCallback("AddAtomEx", PROBE_IDS::IdAddAtomEx);
	g_Apis.pSetCallback("SinglePhaseReject", PROBE_IDS::IdSinglePhaseReject);
	g_Apis.pSetCallback("DeleteWnfStateName", PROBE_IDS::IdDeleteWnfStateName);
	g_Apis.pSetCallback("SetSystemEnvironmentValueEx", PROBE_IDS::IdSetSystemEnvironmentValueEx);
	g_Apis.pSetCallback("ContinueEx", PROBE_IDS::IdContinueEx);
	g_Apis.pSetCallback("UnloadDriver", PROBE_IDS::IdUnloadDriver);
	g_Apis.pSetCallback("CallEnclave", PROBE_IDS::IdCallEnclave);
	g_Apis.pSetCallback("CancelIoFileEx", PROBE_IDS::IdCancelIoFileEx);
	g_Apis.pSetCallback("SetTimer", PROBE_IDS::IdSetTimer);
	g_Apis.pSetCallback("QuerySystemEnvironmentValue", PROBE_IDS::IdQuerySystemEnvironmentValue);
	g_Apis.pSetCallback("OpenThreadToken", PROBE_IDS::IdOpenThreadToken);
	g_Apis.pSetCallback("MapUserPhysicalPagesScatter", PROBE_IDS::IdMapUserPhysicalPagesScatter);
	g_Apis.pSetCallback("CreateResourceManager", PROBE_IDS::IdCreateResourceManager);
	g_Apis.pSetCallback("UnlockVirtualMemory", PROBE_IDS::IdUnlockVirtualMemory);
	g_Apis.pSetCallback("QueryInformationPort", PROBE_IDS::IdQueryInformationPort);
	g_Apis.pSetCallback("SetLowEventPair", PROBE_IDS::IdSetLowEventPair);
	g_Apis.pSetCallback("SetInformationKey", PROBE_IDS::IdSetInformationKey);
	g_Apis.pSetCallback("QuerySecurityPolicy", PROBE_IDS::IdQuerySecurityPolicy);
	g_Apis.pSetCallback("OpenProcessToken", PROBE_IDS::IdOpenProcessToken);
	g_Apis.pSetCallback("QueryVolumeInformationFile", PROBE_IDS::IdQueryVolumeInformationFile);
	g_Apis.pSetCallback("OpenTimer", PROBE_IDS::IdOpenTimer);
	g_Apis.pSetCallback("MapUserPhysicalPages", PROBE_IDS::IdMapUserPhysicalPages);
	g_Apis.pSetCallback("LoadKey", PROBE_IDS::IdLoadKey);
	g_Apis.pSetCallback("CreateWaitCompletionPacket", PROBE_IDS::IdCreateWaitCompletionPacket);
	g_Apis.pSetCallback("ReleaseWorkerFactoryWorker", PROBE_IDS::IdReleaseWorkerFactoryWorker);
	g_Apis.pSetCallback("PrePrepareComplete", PROBE_IDS::IdPrePrepareComplete);
	g_Apis.pSetCallback("ReadVirtualMemory", PROBE_IDS::IdReadVirtualMemory);
	g_Apis.pSetCallback("FreeVirtualMemory", PROBE_IDS::IdFreeVirtualMemory);
	g_Apis.pSetCallback("SetDriverEntryOrder", PROBE_IDS::IdSetDriverEntryOrder);
	g_Apis.pSetCallback("ReadFile", PROBE_IDS::IdReadFile);
	g_Apis.pSetCallback("TraceControl", PROBE_IDS::IdTraceControl);
	g_Apis.pSetCallback("OpenProcessTokenEx", PROBE_IDS::IdOpenProcessTokenEx);
	g_Apis.pSetCallback("SecureConnectPort", PROBE_IDS::IdSecureConnectPort);
	g_Apis.pSetCallback("SaveKey", PROBE_IDS::IdSaveKey);
	g_Apis.pSetCallback("SetDefaultHardErrorPort", PROBE_IDS::IdSetDefaultHardErrorPort);
	g_Apis.pSetCallback("CreateEnclave", PROBE_IDS::IdCreateEnclave);
	g_Apis.pSetCallback("OpenPrivateNamespace", PROBE_IDS::IdOpenPrivateNamespace);
	g_Apis.pSetCallback("SetLdtEntries", PROBE_IDS::IdSetLdtEntries);
	g_Apis.pSetCallback("ResetWriteWatch", PROBE_IDS::IdResetWriteWatch);
	g_Apis.pSetCallback("RenameKey", PROBE_IDS::IdRenameKey);
	g_Apis.pSetCallback("RevertContainerImpersonation", PROBE_IDS::IdRevertContainerImpersonation);
	g_Apis.pSetCallback("AlpcCreateSectionView", PROBE_IDS::IdAlpcCreateSectionView);
	g_Apis.pSetCallback("CreateCrossVmEvent", PROBE_IDS::IdCreateCrossVmEvent);
	g_Apis.pSetCallback("ImpersonateThread", PROBE_IDS::IdImpersonateThread);
	g_Apis.pSetCallback("SetIRTimer", PROBE_IDS::IdSetIRTimer);
	g_Apis.pSetCallback("CreateDirectoryObjectEx", PROBE_IDS::IdCreateDirectoryObjectEx);
	g_Apis.pSetCallback("AcquireProcessActivityReference", PROBE_IDS::IdAcquireProcessActivityReference);
	g_Apis.pSetCallback("ReplaceKey", PROBE_IDS::IdReplaceKey);
	g_Apis.pSetCallback("StartProfile", PROBE_IDS::IdStartProfile);
	g_Apis.pSetCallback("QueryBootEntryOrder", PROBE_IDS::IdQueryBootEntryOrder);
	g_Apis.pSetCallback("LockRegistryKey", PROBE_IDS::IdLockRegistryKey);
	g_Apis.pSetCallback("ImpersonateClientOfPort", PROBE_IDS::IdImpersonateClientOfPort);
	g_Apis.pSetCallback("QueryEvent", PROBE_IDS::IdQueryEvent);
	g_Apis.pSetCallback("FsControlFile", PROBE_IDS::IdFsControlFile);
	g_Apis.pSetCallback("OpenProcess", PROBE_IDS::IdOpenProcess);
	g_Apis.pSetCallback("SetIoCompletion", PROBE_IDS::IdSetIoCompletion);
	g_Apis.pSetCallback("ConnectPort", PROBE_IDS::IdConnectPort);
	g_Apis.pSetCallback("CloseObjectAuditAlarm", PROBE_IDS::IdCloseObjectAuditAlarm);
	g_Apis.pSetCallback("RequestWaitReplyPort", PROBE_IDS::IdRequestWaitReplyPort);
	g_Apis.pSetCallback("SetInformationObject", PROBE_IDS::IdSetInformationObject);
	g_Apis.pSetCallback("PrivilegeCheck", PROBE_IDS::IdPrivilegeCheck);
	g_Apis.pSetCallback("CallbackReturn", PROBE_IDS::IdCallbackReturn);
	g_Apis.pSetCallback("SetInformationToken", PROBE_IDS::IdSetInformationToken);
	g_Apis.pSetCallback("SetUuidSeed", PROBE_IDS::IdSetUuidSeed);
	g_Apis.pSetCallback("OpenKeyTransacted", PROBE_IDS::IdOpenKeyTransacted);
	g_Apis.pSetCallback("AlpcDeleteSecurityContext", PROBE_IDS::IdAlpcDeleteSecurityContext);
	g_Apis.pSetCallback("SetBootOptions", PROBE_IDS::IdSetBootOptions);
	g_Apis.pSetCallback("ManageHotPatch", PROBE_IDS::IdManageHotPatch);
	g_Apis.pSetCallback("EnumerateTransactionObject", PROBE_IDS::IdEnumerateTransactionObject);
	g_Apis.pSetCallback("SetThreadExecutionState", PROBE_IDS::IdSetThreadExecutionState);
	g_Apis.pSetCallback("WaitLowEventPair", PROBE_IDS::IdWaitLowEventPair);
	g_Apis.pSetCallback("SetHighWaitLowEventPair", PROBE_IDS::IdSetHighWaitLowEventPair);
	g_Apis.pSetCallback("QueryInformationWorkerFactory", PROBE_IDS::IdQueryInformationWorkerFactory);
	g_Apis.pSetCallback("SetWnfProcessNotificationEvent", PROBE_IDS::IdSetWnfProcessNotificationEvent);
	g_Apis.pSetCallback("AlpcDeleteSectionView", PROBE_IDS::IdAlpcDeleteSectionView);
	g_Apis.pSetCallback("CreateMailslotFile", PROBE_IDS::IdCreateMailslotFile);
	g_Apis.pSetCallback("CreateProcess", PROBE_IDS::IdCreateProcess);
	g_Apis.pSetCallback("QueryIoCompletion", PROBE_IDS::IdQueryIoCompletion);
	g_Apis.pSetCallback("CreateTimer", PROBE_IDS::IdCreateTimer);
	g_Apis.pSetCallback("FlushInstallUILanguage", PROBE_IDS::IdFlushInstallUILanguage);
	g_Apis.pSetCallback("CompleteConnectPort", PROBE_IDS::IdCompleteConnectPort);
	g_Apis.pSetCallback("AlpcConnectPort", PROBE_IDS::IdAlpcConnectPort);
	g_Apis.pSetCallback("FreezeRegistry", PROBE_IDS::IdFreezeRegistry);
	g_Apis.pSetCallback("MapCMFModule", PROBE_IDS::IdMapCMFModule);
	g_Apis.pSetCallback("AllocateUserPhysicalPages", PROBE_IDS::IdAllocateUserPhysicalPages);
	g_Apis.pSetCallback("SetInformationEnlistment", PROBE_IDS::IdSetInformationEnlistment);
	g_Apis.pSetCallback("RaiseHardError", PROBE_IDS::IdRaiseHardError);
	g_Apis.pSetCallback("CreateSection", PROBE_IDS::IdCreateSection);
	g_Apis.pSetCallback("OpenIoCompletion", PROBE_IDS::IdOpenIoCompletion);
	g_Apis.pSetCallback("SystemDebugControl", PROBE_IDS::IdSystemDebugControl);
	g_Apis.pSetCallback("TranslateFilePath", PROBE_IDS::IdTranslateFilePath);
	g_Apis.pSetCallback("CreateIRTimer", PROBE_IDS::IdCreateIRTimer);
	g_Apis.pSetCallback("CreateRegistryTransaction", PROBE_IDS::IdCreateRegistryTransaction);
	g_Apis.pSetCallback("LoadKey2", PROBE_IDS::IdLoadKey2);
	g_Apis.pSetCallback("AlpcCreatePort", PROBE_IDS::IdAlpcCreatePort);
	g_Apis.pSetCallback("DeleteWnfStateData", PROBE_IDS::IdDeleteWnfStateData);
	g_Apis.pSetCallback("SetTimerEx", PROBE_IDS::IdSetTimerEx);
	g_Apis.pSetCallback("SetLowWaitHighEventPair", PROBE_IDS::IdSetLowWaitHighEventPair);
	g_Apis.pSetCallback("AlpcCreateSecurityContext", PROBE_IDS::IdAlpcCreateSecurityContext);
	g_Apis.pSetCallback("SetCachedSigningLevel", PROBE_IDS::IdSetCachedSigningLevel);
	g_Apis.pSetCallback("SetHighEventPair", PROBE_IDS::IdSetHighEventPair);
	g_Apis.pSetCallback("ShutdownWorkerFactory", PROBE_IDS::IdShutdownWorkerFactory);
	g_Apis.pSetCallback("SetInformationJobObject", PROBE_IDS::IdSetInformationJobObject);
	g_Apis.pSetCallback("AdjustGroupsToken", PROBE_IDS::IdAdjustGroupsToken);
	g_Apis.pSetCallback("AreMappedFilesTheSame", PROBE_IDS::IdAreMappedFilesTheSame);
	g_Apis.pSetCallback("SetBootEntryOrder", PROBE_IDS::IdSetBootEntryOrder);
	g_Apis.pSetCallback("QueryMutant", PROBE_IDS::IdQueryMutant);
	g_Apis.pSetCallback("otifyChangeSession", PROBE_IDS::IdotifyChangeSession);
	g_Apis.pSetCallback("QueryDefaultLocale", PROBE_IDS::IdQueryDefaultLocale);
	g_Apis.pSetCallback("CreateThreadEx", PROBE_IDS::IdCreateThreadEx);
	g_Apis.pSetCallback("QueryDriverEntryOrder", PROBE_IDS::IdQueryDriverEntryOrder);
	g_Apis.pSetCallback("SetTimerResolution", PROBE_IDS::IdSetTimerResolution);
	g_Apis.pSetCallback("PrePrepareEnlistment", PROBE_IDS::IdPrePrepareEnlistment);
	g_Apis.pSetCallback("CancelSynchronousIoFile", PROBE_IDS::IdCancelSynchronousIoFile);
	g_Apis.pSetCallback("QueryDirectoryFileEx", PROBE_IDS::IdQueryDirectoryFileEx);
	g_Apis.pSetCallback("AddDriverEntry", PROBE_IDS::IdAddDriverEntry);
	g_Apis.pSetCallback("UnloadKey", PROBE_IDS::IdUnloadKey);
	g_Apis.pSetCallback("CreateEvent", PROBE_IDS::IdCreateEvent);
	g_Apis.pSetCallback("OpenSession", PROBE_IDS::IdOpenSession);
	g_Apis.pSetCallback("QueryValueKey", PROBE_IDS::IdQueryValueKey);
	g_Apis.pSetCallback("CreatePrivateNamespace", PROBE_IDS::IdCreatePrivateNamespace);
	g_Apis.pSetCallback("IsUILanguageComitted", PROBE_IDS::IdIsUILanguageComitted);
	g_Apis.pSetCallback("AlertThread", PROBE_IDS::IdAlertThread);
	g_Apis.pSetCallback("QueryInstallUILanguage", PROBE_IDS::IdQueryInstallUILanguage);
	g_Apis.pSetCallback("CreateSymbolicLinkObject", PROBE_IDS::IdCreateSymbolicLinkObject);
	g_Apis.pSetCallback("AllocateUuids", PROBE_IDS::IdAllocateUuids);
	g_Apis.pSetCallback("ShutdownSystem", PROBE_IDS::IdShutdownSystem);
	g_Apis.pSetCallback("CreateTokenEx", PROBE_IDS::IdCreateTokenEx);
	g_Apis.pSetCallback("QueryVirtualMemory", PROBE_IDS::IdQueryVirtualMemory);
	g_Apis.pSetCallback("AlpcOpenSenderProcess", PROBE_IDS::IdAlpcOpenSenderProcess);
	g_Apis.pSetCallback("AssignProcessToJobObject", PROBE_IDS::IdAssignProcessToJobObject);
	g_Apis.pSetCallback("RemoveIoCompletion", PROBE_IDS::IdRemoveIoCompletion);
	g_Apis.pSetCallback("CreateTimer2", PROBE_IDS::IdCreateTimer2);
	g_Apis.pSetCallback("CreateEnlistment", PROBE_IDS::IdCreateEnlistment);
	g_Apis.pSetCallback("RecoverEnlistment", PROBE_IDS::IdRecoverEnlistment);
	g_Apis.pSetCallback("CreateJobSet", PROBE_IDS::IdCreateJobSet);
	g_Apis.pSetCallback("SetIoCompletionEx", PROBE_IDS::IdSetIoCompletionEx);
	g_Apis.pSetCallback("CreateProcessEx", PROBE_IDS::IdCreateProcessEx);
	g_Apis.pSetCallback("AlpcConnectPortEx", PROBE_IDS::IdAlpcConnectPortEx);
	g_Apis.pSetCallback("WaitForMultipleObjects32", PROBE_IDS::IdWaitForMultipleObjects32);
	g_Apis.pSetCallback("RecoverResourceManager", PROBE_IDS::IdRecoverResourceManager);
	g_Apis.pSetCallback("AlpcSetInformation", PROBE_IDS::IdAlpcSetInformation);
	g_Apis.pSetCallback("AlpcRevokeSecurityContext", PROBE_IDS::IdAlpcRevokeSecurityContext);
	g_Apis.pSetCallback("AlpcImpersonateClientOfPort", PROBE_IDS::IdAlpcImpersonateClientOfPort);
	g_Apis.pSetCallback("ReleaseKeyedEvent", PROBE_IDS::IdReleaseKeyedEvent);
	g_Apis.pSetCallback("TerminateThread", PROBE_IDS::IdTerminateThread);
	g_Apis.pSetCallback("SetInformationSymbolicLink", PROBE_IDS::IdSetInformationSymbolicLink);
	g_Apis.pSetCallback("DeleteObjectAuditAlarm", PROBE_IDS::IdDeleteObjectAuditAlarm);
	g_Apis.pSetCallback("WaitForKeyedEvent", PROBE_IDS::IdWaitForKeyedEvent);
	g_Apis.pSetCallback("CreatePort", PROBE_IDS::IdCreatePort);
	g_Apis.pSetCallback("DeletePrivateNamespace", PROBE_IDS::IdDeletePrivateNamespace);
	g_Apis.pSetCallback("otifyChangeMultipleKeys", PROBE_IDS::IdotifyChangeMultipleKeys);
	g_Apis.pSetCallback("LockFile", PROBE_IDS::IdLockFile);
	g_Apis.pSetCallback("QueryDefaultUILanguage", PROBE_IDS::IdQueryDefaultUILanguage);
	g_Apis.pSetCallback("OpenEventPair", PROBE_IDS::IdOpenEventPair);
	g_Apis.pSetCallback("RollforwardTransactionManager", PROBE_IDS::IdRollforwardTransactionManager);
	g_Apis.pSetCallback("AlpcQueryInformationMessage", PROBE_IDS::IdAlpcQueryInformationMessage);
	g_Apis.pSetCallback("UnmapViewOfSection", PROBE_IDS::IdUnmapViewOfSection);
	g_Apis.pSetCallback("CancelIoFile", PROBE_IDS::IdCancelIoFile);
	g_Apis.pSetCallback("CreatePagingFile", PROBE_IDS::IdCreatePagingFile);
	g_Apis.pSetCallback("CancelTimer", PROBE_IDS::IdCancelTimer);
	g_Apis.pSetCallback("ReplyWaitReceivePort", PROBE_IDS::IdReplyWaitReceivePort);
	g_Apis.pSetCallback("CompareObjects", PROBE_IDS::IdCompareObjects);
	g_Apis.pSetCallback("SetDefaultLocale", PROBE_IDS::IdSetDefaultLocale);
	g_Apis.pSetCallback("AllocateLocallyUniqueId", PROBE_IDS::IdAllocateLocallyUniqueId);
	g_Apis.pSetCallback("AccessCheckByTypeAndAuditAlarm", PROBE_IDS::IdAccessCheckByTypeAndAuditAlarm);
	g_Apis.pSetCallback("QueryDebugFilterState", PROBE_IDS::IdQueryDebugFilterState);
	g_Apis.pSetCallback("OpenSemaphore", PROBE_IDS::IdOpenSemaphore);
	g_Apis.pSetCallback("AllocateVirtualMemory", PROBE_IDS::IdAllocateVirtualMemory);
	g_Apis.pSetCallback("ResumeProcess", PROBE_IDS::IdResumeProcess);
	g_Apis.pSetCallback("SetContextThread", PROBE_IDS::IdSetContextThread);
	g_Apis.pSetCallback("OpenSymbolicLinkObject", PROBE_IDS::IdOpenSymbolicLinkObject);
	g_Apis.pSetCallback("ModifyDriverEntry", PROBE_IDS::IdModifyDriverEntry);
	g_Apis.pSetCallback("SerializeBoot", PROBE_IDS::IdSerializeBoot);
	g_Apis.pSetCallback("RenameTransactionManager", PROBE_IDS::IdRenameTransactionManager);
	g_Apis.pSetCallback("RemoveIoCompletionEx", PROBE_IDS::IdRemoveIoCompletionEx);
	g_Apis.pSetCallback("MapViewOfSectionEx", PROBE_IDS::IdMapViewOfSectionEx);
	g_Apis.pSetCallback("FilterTokenEx", PROBE_IDS::IdFilterTokenEx);
	g_Apis.pSetCallback("DeleteDriverEntry", PROBE_IDS::IdDeleteDriverEntry);
	g_Apis.pSetCallback("QuerySystemInformation", PROBE_IDS::IdQuerySystemInformation);
	g_Apis.pSetCallback("SetInformationWorkerFactory", PROBE_IDS::IdSetInformationWorkerFactory);
	g_Apis.pSetCallback("AdjustTokenClaimsAndDeviceGroups", PROBE_IDS::IdAdjustTokenClaimsAndDeviceGroups);
	g_Apis.pSetCallback("SaveMergedKeys", PROBE_IDS::IdSaveMergedKeys);
	LOG_INFO("Plugin Initialized\r\n");
}
ASSERT_INTERFACE_IMPLEMENTED(StpInitialize, tStpInitialize, "StpInitialize does not match the interface type");

extern "C" __declspec(dllexport) void StpDeInitialize() {
	LOG_INFO("Plugin DeInitializing...\r\n");
	g_Apis.pUnsetCallback("LockProductActivationKeys");
	g_Apis.pUnsetCallback("WaitHighEventPair");
	g_Apis.pUnsetCallback("RegisterThreadTerminatePort");
	g_Apis.pUnsetCallback("AssociateWaitCompletionPacket");
	g_Apis.pUnsetCallback("QueryPerformanceCounter");
	g_Apis.pUnsetCallback("CompactKeys");
	g_Apis.pUnsetCallback("QuerySystemInformationEx");
	g_Apis.pUnsetCallback("ResetEvent");
	g_Apis.pUnsetCallback("GetContextThread");
	g_Apis.pUnsetCallback("QueryInformationThread");
	g_Apis.pUnsetCallback("WaitForSingleObject");
	g_Apis.pUnsetCallback("FlushBuffersFileEx");
	g_Apis.pUnsetCallback("UnloadKey2");
	g_Apis.pUnsetCallback("ReadOnlyEnlistment");
	g_Apis.pUnsetCallback("DeleteFile");
	g_Apis.pUnsetCallback("DeleteAtom");
	g_Apis.pUnsetCallback("QueryDirectoryFile");
	g_Apis.pUnsetCallback("SetEventBoostPriority");
	g_Apis.pUnsetCallback("AllocateUserPhysicalPagesEx");
	g_Apis.pUnsetCallback("WriteFile");
	g_Apis.pUnsetCallback("QueryInformationFile");
	g_Apis.pUnsetCallback("AlpcCancelMessage");
	g_Apis.pUnsetCallback("OpenMutant");
	g_Apis.pUnsetCallback("CreatePartition");
	g_Apis.pUnsetCallback("QueryTimer");
	g_Apis.pUnsetCallback("OpenEvent");
	g_Apis.pUnsetCallback("OpenObjectAuditAlarm");
	g_Apis.pUnsetCallback("MakePermanentObject");
	g_Apis.pUnsetCallback("CommitTransaction");
	g_Apis.pUnsetCallback("SetSystemTime");
	g_Apis.pUnsetCallback("GetDevicePowerState");
	g_Apis.pUnsetCallback("SetSystemPowerState");
	g_Apis.pUnsetCallback("AlpcCreateResourceReserve");
	g_Apis.pUnsetCallback("UnlockFile");
	g_Apis.pUnsetCallback("AlpcDeletePortSection");
	g_Apis.pUnsetCallback("SetInformationResourceManager");
	g_Apis.pUnsetCallback("FreeUserPhysicalPages");
	g_Apis.pUnsetCallback("LoadKeyEx");
	g_Apis.pUnsetCallback("PropagationComplete");
	g_Apis.pUnsetCallback("AccessCheckByTypeResultListAndAuditAlarm");
	g_Apis.pUnsetCallback("QueryInformationToken");
	g_Apis.pUnsetCallback("RegisterProtocolAddressInformation");
	g_Apis.pUnsetCallback("ProtectVirtualMemory");
	g_Apis.pUnsetCallback("CreateKey");
	g_Apis.pUnsetCallback("AlpcSendWaitReceivePort");
	g_Apis.pUnsetCallback("OpenRegistryTransaction");
	g_Apis.pUnsetCallback("TerminateProcess");
	g_Apis.pUnsetCallback("PowerInformation");
	g_Apis.pUnsetCallback("otifyChangeDirectoryFile");
	g_Apis.pUnsetCallback("CreateTransaction");
	g_Apis.pUnsetCallback("CreateProfileEx");
	g_Apis.pUnsetCallback("QueryLicenseValue");
	g_Apis.pUnsetCallback("CreateProfile");
	g_Apis.pUnsetCallback("InitializeRegistry");
	g_Apis.pUnsetCallback("FreezeTransactions");
	g_Apis.pUnsetCallback("OpenJobObject");
	g_Apis.pUnsetCallback("SubscribeWnfStateChange");
	g_Apis.pUnsetCallback("GetWriteWatch");
	g_Apis.pUnsetCallback("GetCachedSigningLevel");
	g_Apis.pUnsetCallback("SetSecurityObject");
	g_Apis.pUnsetCallback("QueryIntervalProfile");
	g_Apis.pUnsetCallback("PropagationFailed");
	g_Apis.pUnsetCallback("CreateSectionEx");
	g_Apis.pUnsetCallback("RaiseException");
	g_Apis.pUnsetCallback("SetCachedSigningLevel2");
	g_Apis.pUnsetCallback("CommitEnlistment");
	g_Apis.pUnsetCallback("QueryInformationByName");
	g_Apis.pUnsetCallback("CreateThread");
	g_Apis.pUnsetCallback("OpenResourceManager");
	g_Apis.pUnsetCallback("ReadRequestData");
	g_Apis.pUnsetCallback("ClearEvent");
	g_Apis.pUnsetCallback("TestAlert");
	g_Apis.pUnsetCallback("SetInformationThread");
	g_Apis.pUnsetCallback("SetTimer2");
	g_Apis.pUnsetCallback("SetDefaultUILanguage");
	g_Apis.pUnsetCallback("EnumerateValueKey");
	g_Apis.pUnsetCallback("OpenEnlistment");
	g_Apis.pUnsetCallback("SetIntervalProfile");
	g_Apis.pUnsetCallback("QueryPortInformationProcess");
	g_Apis.pUnsetCallback("QueryInformationTransactionManager");
	g_Apis.pUnsetCallback("SetInformationTransactionManager");
	g_Apis.pUnsetCallback("InitializeEnclave");
	g_Apis.pUnsetCallback("PrepareComplete");
	g_Apis.pUnsetCallback("QueueApcThread");
	g_Apis.pUnsetCallback("WorkerFactoryWorkerReady");
	g_Apis.pUnsetCallback("GetCompleteWnfStateSubscription");
	g_Apis.pUnsetCallback("AlertThreadByThreadId");
	g_Apis.pUnsetCallback("LockVirtualMemory");
	g_Apis.pUnsetCallback("DeviceIoControlFile");
	g_Apis.pUnsetCallback("CreateUserProcess");
	g_Apis.pUnsetCallback("QuerySection");
	g_Apis.pUnsetCallback("SaveKeyEx");
	g_Apis.pUnsetCallback("RollbackTransaction");
	g_Apis.pUnsetCallback("TraceEvent");
	g_Apis.pUnsetCallback("OpenSection");
	g_Apis.pUnsetCallback("RequestPort");
	g_Apis.pUnsetCallback("UnsubscribeWnfStateChange");
	g_Apis.pUnsetCallback("ThawRegistry");
	g_Apis.pUnsetCallback("CreateJobObject");
	g_Apis.pUnsetCallback("OpenKeyTransactedEx");
	g_Apis.pUnsetCallback("WaitForMultipleObjects");
	g_Apis.pUnsetCallback("DuplicateToken");
	g_Apis.pUnsetCallback("AlpcOpenSenderThread");
	g_Apis.pUnsetCallback("AlpcImpersonateClientContainerOfPort");
	g_Apis.pUnsetCallback("DrawText");
	g_Apis.pUnsetCallback("ReleaseSemaphore");
	g_Apis.pUnsetCallback("SetQuotaInformationFile");
	g_Apis.pUnsetCallback("QueryInformationAtom");
	g_Apis.pUnsetCallback("EnumerateBootEntries");
	g_Apis.pUnsetCallback("ThawTransactions");
	g_Apis.pUnsetCallback("AccessCheck");
	g_Apis.pUnsetCallback("FlushProcessWriteBuffers");
	g_Apis.pUnsetCallback("QuerySemaphore");
	g_Apis.pUnsetCallback("CreateNamedPipeFile");
	g_Apis.pUnsetCallback("AlpcDeleteResourceReserve");
	g_Apis.pUnsetCallback("QuerySystemEnvironmentValueEx");
	g_Apis.pUnsetCallback("ReadFileScatter");
	g_Apis.pUnsetCallback("OpenKeyEx");
	g_Apis.pUnsetCallback("SignalAndWaitForSingleObject");
	g_Apis.pUnsetCallback("ReleaseMutant");
	g_Apis.pUnsetCallback("TerminateJobObject");
	g_Apis.pUnsetCallback("SetSystemEnvironmentValue");
	g_Apis.pUnsetCallback("Close");
	g_Apis.pUnsetCallback("QueueApcThreadEx");
	g_Apis.pUnsetCallback("QueryMultipleValueKey");
	g_Apis.pUnsetCallback("AlpcQueryInformation");
	g_Apis.pUnsetCallback("UpdateWnfStateData");
	g_Apis.pUnsetCallback("ListenPort");
	g_Apis.pUnsetCallback("FlushInstructionCache");
	g_Apis.pUnsetCallback("GetNotificationResourceManager");
	g_Apis.pUnsetCallback("QueryFullAttributesFile");
	g_Apis.pUnsetCallback("SuspendThread");
	g_Apis.pUnsetCallback("CompareTokens");
	g_Apis.pUnsetCallback("CancelWaitCompletionPacket");
	g_Apis.pUnsetCallback("AlpcAcceptConnectPort");
	g_Apis.pUnsetCallback("OpenTransaction");
	g_Apis.pUnsetCallback("ImpersonateAnonymousToken");
	g_Apis.pUnsetCallback("QuerySecurityObject");
	g_Apis.pUnsetCallback("RollbackEnlistment");
	g_Apis.pUnsetCallback("ReplacePartitionUnit");
	g_Apis.pUnsetCallback("CreateKeyTransacted");
	g_Apis.pUnsetCallback("ConvertBetweenAuxiliaryCounterAndPerformanceCounter");
	g_Apis.pUnsetCallback("CreateKeyedEvent");
	g_Apis.pUnsetCallback("CreateEventPair");
	g_Apis.pUnsetCallback("AddAtom");
	g_Apis.pUnsetCallback("QueryOpenSubKeys");
	g_Apis.pUnsetCallback("QuerySystemTime");
	g_Apis.pUnsetCallback("SetEaFile");
	g_Apis.pUnsetCallback("SetInformationProcess");
	g_Apis.pUnsetCallback("SetValueKey");
	g_Apis.pUnsetCallback("QuerySymbolicLinkObject");
	g_Apis.pUnsetCallback("QueryOpenSubKeysEx");
	g_Apis.pUnsetCallback("otifyChangeKey");
	g_Apis.pUnsetCallback("IsProcessInJob");
	g_Apis.pUnsetCallback("CommitComplete");
	g_Apis.pUnsetCallback("EnumerateDriverEntries");
	g_Apis.pUnsetCallback("AccessCheckByTypeResultList");
	g_Apis.pUnsetCallback("LoadEnclaveData");
	g_Apis.pUnsetCallback("AllocateVirtualMemoryEx");
	g_Apis.pUnsetCallback("WaitForWorkViaWorkerFactory");
	g_Apis.pUnsetCallback("QueryInformationResourceManager");
	g_Apis.pUnsetCallback("EnumerateKey");
	g_Apis.pUnsetCallback("GetMUIRegistryInfo");
	g_Apis.pUnsetCallback("AcceptConnectPort");
	g_Apis.pUnsetCallback("RecoverTransactionManager");
	g_Apis.pUnsetCallback("WriteVirtualMemory");
	g_Apis.pUnsetCallback("QueryBootOptions");
	g_Apis.pUnsetCallback("RollbackComplete");
	g_Apis.pUnsetCallback("QueryAuxiliaryCounterFrequency");
	g_Apis.pUnsetCallback("AlpcCreatePortSection");
	g_Apis.pUnsetCallback("QueryObject");
	g_Apis.pUnsetCallback("QueryWnfStateData");
	g_Apis.pUnsetCallback("InitiatePowerAction");
	g_Apis.pUnsetCallback("DirectGraphicsCall");
	g_Apis.pUnsetCallback("AcquireCrossVmMutant");
	g_Apis.pUnsetCallback("RollbackRegistryTransaction");
	g_Apis.pUnsetCallback("AlertResumeThread");
	g_Apis.pUnsetCallback("PssCaptureVaSpaceBulk");
	g_Apis.pUnsetCallback("CreateToken");
	g_Apis.pUnsetCallback("PrepareEnlistment");
	g_Apis.pUnsetCallback("FlushWriteBuffer");
	g_Apis.pUnsetCallback("CommitRegistryTransaction");
	g_Apis.pUnsetCallback("AccessCheckByType");
	g_Apis.pUnsetCallback("OpenThread");
	g_Apis.pUnsetCallback("AccessCheckAndAuditAlarm");
	g_Apis.pUnsetCallback("OpenThreadTokenEx");
	g_Apis.pUnsetCallback("WriteRequestData");
	g_Apis.pUnsetCallback("CreateWorkerFactory");
	g_Apis.pUnsetCallback("OpenPartition");
	g_Apis.pUnsetCallback("SetSystemInformation");
	g_Apis.pUnsetCallback("EnumerateSystemEnvironmentValuesEx");
	g_Apis.pUnsetCallback("CreateWnfStateName");
	g_Apis.pUnsetCallback("QueryInformationJobObject");
	g_Apis.pUnsetCallback("PrivilegedServiceAuditAlarm");
	g_Apis.pUnsetCallback("EnableLastKnownGood");
	g_Apis.pUnsetCallback("otifyChangeDirectoryFileEx");
	g_Apis.pUnsetCallback("CreateWaitablePort");
	g_Apis.pUnsetCallback("WaitForAlertByThreadId");
	g_Apis.pUnsetCallback("GetNextProcess");
	g_Apis.pUnsetCallback("OpenKeyedEvent");
	g_Apis.pUnsetCallback("DeleteBootEntry");
	g_Apis.pUnsetCallback("FilterToken");
	g_Apis.pUnsetCallback("CompressKey");
	g_Apis.pUnsetCallback("ModifyBootEntry");
	g_Apis.pUnsetCallback("SetInformationTransaction");
	g_Apis.pUnsetCallback("PlugPlayControl");
	g_Apis.pUnsetCallback("OpenDirectoryObject");
	g_Apis.pUnsetCallback("Continue");
	g_Apis.pUnsetCallback("PrivilegeObjectAuditAlarm");
	g_Apis.pUnsetCallback("QueryKey");
	g_Apis.pUnsetCallback("FilterBootOption");
	g_Apis.pUnsetCallback("YieldExecution");
	g_Apis.pUnsetCallback("ResumeThread");
	g_Apis.pUnsetCallback("AddBootEntry");
	g_Apis.pUnsetCallback("GetCurrentProcessorNumberEx");
	g_Apis.pUnsetCallback("CreateLowBoxToken");
	g_Apis.pUnsetCallback("FlushBuffersFile");
	g_Apis.pUnsetCallback("DelayExecution");
	g_Apis.pUnsetCallback("OpenKey");
	g_Apis.pUnsetCallback("StopProfile");
	g_Apis.pUnsetCallback("SetEvent");
	g_Apis.pUnsetCallback("RestoreKey");
	g_Apis.pUnsetCallback("ExtendSection");
	g_Apis.pUnsetCallback("InitializeNlsFiles");
	g_Apis.pUnsetCallback("FindAtom");
	g_Apis.pUnsetCallback("DisplayString");
	g_Apis.pUnsetCallback("LoadDriver");
	g_Apis.pUnsetCallback("QueryWnfStateNameInformation");
	g_Apis.pUnsetCallback("CreateMutant");
	g_Apis.pUnsetCallback("FlushKey");
	g_Apis.pUnsetCallback("DuplicateObject");
	g_Apis.pUnsetCallback("CancelTimer2");
	g_Apis.pUnsetCallback("QueryAttributesFile");
	g_Apis.pUnsetCallback("CompareSigningLevels");
	g_Apis.pUnsetCallback("AccessCheckByTypeResultListAndAuditAlarmByHandle");
	g_Apis.pUnsetCallback("DeleteValueKey");
	g_Apis.pUnsetCallback("SetDebugFilterState");
	g_Apis.pUnsetCallback("PulseEvent");
	g_Apis.pUnsetCallback("AllocateReserveObject");
	g_Apis.pUnsetCallback("AlpcDisconnectPort");
	g_Apis.pUnsetCallback("QueryTimerResolution");
	g_Apis.pUnsetCallback("DeleteKey");
	g_Apis.pUnsetCallback("CreateFile");
	g_Apis.pUnsetCallback("ReplyPort");
	g_Apis.pUnsetCallback("GetNlsSectionPtr");
	g_Apis.pUnsetCallback("QueryInformationProcess");
	g_Apis.pUnsetCallback("ReplyWaitReceivePortEx");
	g_Apis.pUnsetCallback("UmsThreadYield");
	g_Apis.pUnsetCallback("ManagePartition");
	g_Apis.pUnsetCallback("AdjustPrivilegesToken");
	g_Apis.pUnsetCallback("CreateCrossVmMutant");
	g_Apis.pUnsetCallback("CreateDirectoryObject");
	g_Apis.pUnsetCallback("OpenFile");
	g_Apis.pUnsetCallback("SetInformationVirtualMemory");
	g_Apis.pUnsetCallback("TerminateEnclave");
	g_Apis.pUnsetCallback("SuspendProcess");
	g_Apis.pUnsetCallback("ReplyWaitReplyPort");
	g_Apis.pUnsetCallback("OpenTransactionManager");
	g_Apis.pUnsetCallback("CreateSemaphore");
	g_Apis.pUnsetCallback("UnmapViewOfSectionEx");
	g_Apis.pUnsetCallback("MapViewOfSection");
	g_Apis.pUnsetCallback("DisableLastKnownGood");
	g_Apis.pUnsetCallback("GetNextThread");
	g_Apis.pUnsetCallback("MakeTemporaryObject");
	g_Apis.pUnsetCallback("SetInformationFile");
	g_Apis.pUnsetCallback("CreateTransactionManager");
	g_Apis.pUnsetCallback("WriteFileGather");
	g_Apis.pUnsetCallback("QueryInformationTransaction");
	g_Apis.pUnsetCallback("FlushVirtualMemory");
	g_Apis.pUnsetCallback("QueryQuotaInformationFile");
	g_Apis.pUnsetCallback("SetVolumeInformationFile");
	g_Apis.pUnsetCallback("QueryInformationEnlistment");
	g_Apis.pUnsetCallback("CreateIoCompletion");
	g_Apis.pUnsetCallback("UnloadKeyEx");
	g_Apis.pUnsetCallback("QueryEaFile");
	g_Apis.pUnsetCallback("QueryDirectoryObject");
	g_Apis.pUnsetCallback("AddAtomEx");
	g_Apis.pUnsetCallback("SinglePhaseReject");
	g_Apis.pUnsetCallback("DeleteWnfStateName");
	g_Apis.pUnsetCallback("SetSystemEnvironmentValueEx");
	g_Apis.pUnsetCallback("ContinueEx");
	g_Apis.pUnsetCallback("UnloadDriver");
	g_Apis.pUnsetCallback("CallEnclave");
	g_Apis.pUnsetCallback("CancelIoFileEx");
	g_Apis.pUnsetCallback("SetTimer");
	g_Apis.pUnsetCallback("QuerySystemEnvironmentValue");
	g_Apis.pUnsetCallback("OpenThreadToken");
	g_Apis.pUnsetCallback("MapUserPhysicalPagesScatter");
	g_Apis.pUnsetCallback("CreateResourceManager");
	g_Apis.pUnsetCallback("UnlockVirtualMemory");
	g_Apis.pUnsetCallback("QueryInformationPort");
	g_Apis.pUnsetCallback("SetLowEventPair");
	g_Apis.pUnsetCallback("SetInformationKey");
	g_Apis.pUnsetCallback("QuerySecurityPolicy");
	g_Apis.pUnsetCallback("OpenProcessToken");
	g_Apis.pUnsetCallback("QueryVolumeInformationFile");
	g_Apis.pUnsetCallback("OpenTimer");
	g_Apis.pUnsetCallback("MapUserPhysicalPages");
	g_Apis.pUnsetCallback("LoadKey");
	g_Apis.pUnsetCallback("CreateWaitCompletionPacket");
	g_Apis.pUnsetCallback("ReleaseWorkerFactoryWorker");
	g_Apis.pUnsetCallback("PrePrepareComplete");
	g_Apis.pUnsetCallback("ReadVirtualMemory");
	g_Apis.pUnsetCallback("FreeVirtualMemory");
	g_Apis.pUnsetCallback("SetDriverEntryOrder");
	g_Apis.pUnsetCallback("ReadFile");
	g_Apis.pUnsetCallback("TraceControl");
	g_Apis.pUnsetCallback("OpenProcessTokenEx");
	g_Apis.pUnsetCallback("SecureConnectPort");
	g_Apis.pUnsetCallback("SaveKey");
	g_Apis.pUnsetCallback("SetDefaultHardErrorPort");
	g_Apis.pUnsetCallback("CreateEnclave");
	g_Apis.pUnsetCallback("OpenPrivateNamespace");
	g_Apis.pUnsetCallback("SetLdtEntries");
	g_Apis.pUnsetCallback("ResetWriteWatch");
	g_Apis.pUnsetCallback("RenameKey");
	g_Apis.pUnsetCallback("RevertContainerImpersonation");
	g_Apis.pUnsetCallback("AlpcCreateSectionView");
	g_Apis.pUnsetCallback("CreateCrossVmEvent");
	g_Apis.pUnsetCallback("ImpersonateThread");
	g_Apis.pUnsetCallback("SetIRTimer");
	g_Apis.pUnsetCallback("CreateDirectoryObjectEx");
	g_Apis.pUnsetCallback("AcquireProcessActivityReference");
	g_Apis.pUnsetCallback("ReplaceKey");
	g_Apis.pUnsetCallback("StartProfile");
	g_Apis.pUnsetCallback("QueryBootEntryOrder");
	g_Apis.pUnsetCallback("LockRegistryKey");
	g_Apis.pUnsetCallback("ImpersonateClientOfPort");
	g_Apis.pUnsetCallback("QueryEvent");
	g_Apis.pUnsetCallback("FsControlFile");
	g_Apis.pUnsetCallback("OpenProcess");
	g_Apis.pUnsetCallback("SetIoCompletion");
	g_Apis.pUnsetCallback("ConnectPort");
	g_Apis.pUnsetCallback("CloseObjectAuditAlarm");
	g_Apis.pUnsetCallback("RequestWaitReplyPort");
	g_Apis.pUnsetCallback("SetInformationObject");
	g_Apis.pUnsetCallback("PrivilegeCheck");
	g_Apis.pUnsetCallback("CallbackReturn");
	g_Apis.pUnsetCallback("SetInformationToken");
	g_Apis.pUnsetCallback("SetUuidSeed");
	g_Apis.pUnsetCallback("OpenKeyTransacted");
	g_Apis.pUnsetCallback("AlpcDeleteSecurityContext");
	g_Apis.pUnsetCallback("SetBootOptions");
	g_Apis.pUnsetCallback("ManageHotPatch");
	g_Apis.pUnsetCallback("EnumerateTransactionObject");
	g_Apis.pUnsetCallback("SetThreadExecutionState");
	g_Apis.pUnsetCallback("WaitLowEventPair");
	g_Apis.pUnsetCallback("SetHighWaitLowEventPair");
	g_Apis.pUnsetCallback("QueryInformationWorkerFactory");
	g_Apis.pUnsetCallback("SetWnfProcessNotificationEvent");
	g_Apis.pUnsetCallback("AlpcDeleteSectionView");
	g_Apis.pUnsetCallback("CreateMailslotFile");
	g_Apis.pUnsetCallback("CreateProcess");
	g_Apis.pUnsetCallback("QueryIoCompletion");
	g_Apis.pUnsetCallback("CreateTimer");
	g_Apis.pUnsetCallback("FlushInstallUILanguage");
	g_Apis.pUnsetCallback("CompleteConnectPort");
	g_Apis.pUnsetCallback("AlpcConnectPort");
	g_Apis.pUnsetCallback("FreezeRegistry");
	g_Apis.pUnsetCallback("MapCMFModule");
	g_Apis.pUnsetCallback("AllocateUserPhysicalPages");
	g_Apis.pUnsetCallback("SetInformationEnlistment");
	g_Apis.pUnsetCallback("RaiseHardError");
	g_Apis.pUnsetCallback("CreateSection");
	g_Apis.pUnsetCallback("OpenIoCompletion");
	g_Apis.pUnsetCallback("SystemDebugControl");
	g_Apis.pUnsetCallback("TranslateFilePath");
	g_Apis.pUnsetCallback("CreateIRTimer");
	g_Apis.pUnsetCallback("CreateRegistryTransaction");
	g_Apis.pUnsetCallback("LoadKey2");
	g_Apis.pUnsetCallback("AlpcCreatePort");
	g_Apis.pUnsetCallback("DeleteWnfStateData");
	g_Apis.pUnsetCallback("SetTimerEx");
	g_Apis.pUnsetCallback("SetLowWaitHighEventPair");
	g_Apis.pUnsetCallback("AlpcCreateSecurityContext");
	g_Apis.pUnsetCallback("SetCachedSigningLevel");
	g_Apis.pUnsetCallback("SetHighEventPair");
	g_Apis.pUnsetCallback("ShutdownWorkerFactory");
	g_Apis.pUnsetCallback("SetInformationJobObject");
	g_Apis.pUnsetCallback("AdjustGroupsToken");
	g_Apis.pUnsetCallback("AreMappedFilesTheSame");
	g_Apis.pUnsetCallback("SetBootEntryOrder");
	g_Apis.pUnsetCallback("QueryMutant");
	g_Apis.pUnsetCallback("otifyChangeSession");
	g_Apis.pUnsetCallback("QueryDefaultLocale");
	g_Apis.pUnsetCallback("CreateThreadEx");
	g_Apis.pUnsetCallback("QueryDriverEntryOrder");
	g_Apis.pUnsetCallback("SetTimerResolution");
	g_Apis.pUnsetCallback("PrePrepareEnlistment");
	g_Apis.pUnsetCallback("CancelSynchronousIoFile");
	g_Apis.pUnsetCallback("QueryDirectoryFileEx");
	g_Apis.pUnsetCallback("AddDriverEntry");
	g_Apis.pUnsetCallback("UnloadKey");
	g_Apis.pUnsetCallback("CreateEvent");
	g_Apis.pUnsetCallback("OpenSession");
	g_Apis.pUnsetCallback("QueryValueKey");
	g_Apis.pUnsetCallback("CreatePrivateNamespace");
	g_Apis.pUnsetCallback("IsUILanguageComitted");
	g_Apis.pUnsetCallback("AlertThread");
	g_Apis.pUnsetCallback("QueryInstallUILanguage");
	g_Apis.pUnsetCallback("CreateSymbolicLinkObject");
	g_Apis.pUnsetCallback("AllocateUuids");
	g_Apis.pUnsetCallback("ShutdownSystem");
	g_Apis.pUnsetCallback("CreateTokenEx");
	g_Apis.pUnsetCallback("QueryVirtualMemory");
	g_Apis.pUnsetCallback("AlpcOpenSenderProcess");
	g_Apis.pUnsetCallback("AssignProcessToJobObject");
	g_Apis.pUnsetCallback("RemoveIoCompletion");
	g_Apis.pUnsetCallback("CreateTimer2");
	g_Apis.pUnsetCallback("CreateEnlistment");
	g_Apis.pUnsetCallback("RecoverEnlistment");
	g_Apis.pUnsetCallback("CreateJobSet");
	g_Apis.pUnsetCallback("SetIoCompletionEx");
	g_Apis.pUnsetCallback("CreateProcessEx");
	g_Apis.pUnsetCallback("AlpcConnectPortEx");
	g_Apis.pUnsetCallback("WaitForMultipleObjects32");
	g_Apis.pUnsetCallback("RecoverResourceManager");
	g_Apis.pUnsetCallback("AlpcSetInformation");
	g_Apis.pUnsetCallback("AlpcRevokeSecurityContext");
	g_Apis.pUnsetCallback("AlpcImpersonateClientOfPort");
	g_Apis.pUnsetCallback("ReleaseKeyedEvent");
	g_Apis.pUnsetCallback("TerminateThread");
	g_Apis.pUnsetCallback("SetInformationSymbolicLink");
	g_Apis.pUnsetCallback("DeleteObjectAuditAlarm");
	g_Apis.pUnsetCallback("WaitForKeyedEvent");
	g_Apis.pUnsetCallback("CreatePort");
	g_Apis.pUnsetCallback("DeletePrivateNamespace");
	g_Apis.pUnsetCallback("otifyChangeMultipleKeys");
	g_Apis.pUnsetCallback("LockFile");
	g_Apis.pUnsetCallback("QueryDefaultUILanguage");
	g_Apis.pUnsetCallback("OpenEventPair");
	g_Apis.pUnsetCallback("RollforwardTransactionManager");
	g_Apis.pUnsetCallback("AlpcQueryInformationMessage");
	g_Apis.pUnsetCallback("UnmapViewOfSection");
	g_Apis.pUnsetCallback("CancelIoFile");
	g_Apis.pUnsetCallback("CreatePagingFile");
	g_Apis.pUnsetCallback("CancelTimer");
	g_Apis.pUnsetCallback("ReplyWaitReceivePort");
	g_Apis.pUnsetCallback("CompareObjects");
	g_Apis.pUnsetCallback("SetDefaultLocale");
	g_Apis.pUnsetCallback("AllocateLocallyUniqueId");
	g_Apis.pUnsetCallback("AccessCheckByTypeAndAuditAlarm");
	g_Apis.pUnsetCallback("QueryDebugFilterState");
	g_Apis.pUnsetCallback("OpenSemaphore");
	g_Apis.pUnsetCallback("AllocateVirtualMemory");
	g_Apis.pUnsetCallback("ResumeProcess");
	g_Apis.pUnsetCallback("SetContextThread");
	g_Apis.pUnsetCallback("OpenSymbolicLinkObject");
	g_Apis.pUnsetCallback("ModifyDriverEntry");
	g_Apis.pUnsetCallback("SerializeBoot");
	g_Apis.pUnsetCallback("RenameTransactionManager");
	g_Apis.pUnsetCallback("RemoveIoCompletionEx");
	g_Apis.pUnsetCallback("MapViewOfSectionEx");
	g_Apis.pUnsetCallback("FilterTokenEx");
	g_Apis.pUnsetCallback("DeleteDriverEntry");
	g_Apis.pUnsetCallback("QuerySystemInformation");
	g_Apis.pUnsetCallback("SetInformationWorkerFactory");
	g_Apis.pUnsetCallback("AdjustTokenClaimsAndDeviceGroups");
	g_Apis.pUnsetCallback("SaveMergedKeys");
	LOG_INFO("Plugin DeInitialized\r\n");
}
ASSERT_INTERFACE_IMPLEMENTED(StpDeInitialize, tStpDeInitialize, "StpDeInitialize does not match the interface type");

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

enum class LiveKernelDumpFlags : ULONG {
	KernelPages = 0,
	UserAndKernelPages = 1,
	MiniDump = 2,
	HyperVAndKernelPages = 4,
	UserAndHyperVAndKernelPages = 5 // UserAndKernelPages & HyperVAndKernelPages
};

// C:\Windows\LiveKernelReports OR path within HKLM\system\currentcontrolset\control\crashcontrol\livekernelreports
// ComponentName: Name of folder created in report directory
// BugCheckCode: Code shown to user in the generated .dmp file when loaded in windbg
// P1 - P4 arbitrary parameters, shown to user as BUGCHECK_P1-... in the generated .dmp file when loaded in windbg
extern "C" __declspec(dllimport) void NTAPI DbgkWerCaptureLiveKernelDump(const wchar_t* ComponentName, ULONG BugCheckCode, ULONG_PTR P1, ULONG_PTR P2, ULONG_PTR P3, ULONG_PTR P4, LiveKernelDumpFlags flags);

void LiveKernelDump(LiveKernelDumpFlags flags)
{
	DbgkWerCaptureLiveKernelDump(L"STRACE", MANUALLY_INITIATED_CRASH, 1, 3, 3, 7, flags);
}

extern "C" __declspec(dllexport) bool StpIsTarget(CallerInfo & callerinfo) {
	if (strcmp(callerinfo.processName, "BasicHello.exe") == 0) {
		return true;
	}
	return false;
}
ASSERT_INTERFACE_IMPLEMENTED(StpIsTarget, tStpIsTarget, "StpIsTarget does not match the interface type");

/*
This is a funny little trick. In a switch case, if you define a new scope with locals they all
get lifted to the parent scope which can allocate lots of stack space even if that case isn't
always taken. The fix for that is to not define locals in a switch case, and call a function instead.
But that's annoying and breaks cleanly putting the code in the switch body. Instead, we can define a lambda.

The lambda acts like we made a function, which we ensure is true by forcing noinline. This way stack space is only
allocated if the case is taken. This basically is a technique to declare a global function, while within a function.
*/
#define PRINTER(code) [&]() DECLSPEC_NOINLINE { char sprintf_tmp_buf[256] = { 0 }; code }()


/**
pService: Pointer to system service from SSDT
probeId: Identifier given in KeSetSystemServiceCallback for this syscall callback
paramCount: Number of arguments this system service uses
pArgs: Argument array, usually x64 fastcall registers rcx, rdx, r8, r9
pArgSize: Length of argument array, usually hard coded to 4
pStackArgs: Pointer to stack area containing the rest of the arguments, if any
**/
extern "C" __declspec(dllexport) void StpCallbackEntry(ULONG64 pService, ULONG32 probeId, MachineState & ctx, CallerInfo & callerinfo)
{
	LOG_INFO("[ENTRY] %s %s\r\n", get_probe_name((PROBE_IDS)probeId), callerinfo.processName);
	auto argTypes = get_probe_argtypes((PROBE_IDS)probeId);

	String argsString;
	uint8_t argIdx = 0;
	for (uint64_t type_id : argTypes) {
		uint64_t argValue = ctx.read_argument(argIdx);
		switch (type_id) {
		case get_type_id<MY_MEMORY_INFORMATION_CLASS>():
			PRINTER(
				string_printf(argsString, sprintf_tmp_buf, "%d - MEM_INFO: %s %d", argIdx, get_enum_value_name<COMPLETE_MEMORY_INFORMATION_CLASS>(argValue), argValue);
			);
			break;
		case get_type_id<MY_BOOLEAN>():
			PRINTER(
				string_printf(argsString, sprintf_tmp_buf, "%d - BOOLEAN: %s", argIdx, argValue ? "TRUE" : "FALSE");
			);
			break;
		case get_type_id<MY_PBOOLEAN>():
			PRINTER(
				BOOLEAN val = readUserArgPtr<PBOOLEAN>(argValue, g_Apis);
			string_printf(argsString, sprintf_tmp_buf, "%d - BOOLEAN*: %X->(%s)", argIdx, argValue, val ? "TRUE" : "FALSE");
			);
			break;
		case get_type_id<UCHAR>():
		case get_type_id<CHAR>():
			PRINTER(
				string_printf(argsString, sprintf_tmp_buf, "%d - CHAR: %02X", argIdx, argValue);
			);
			break;
		case get_type_id<UINT16>():
		case get_type_id<INT16>():
			PRINTER(
				string_printf(argsString, sprintf_tmp_buf, "%d - INT16: %04X", argIdx, argValue);
			);
			break;
		case get_type_id<PINT16>():
			PRINTER(
				UINT16 val = readUserArgPtr<PUINT16>(argValue, g_Apis);
			string_printf(argsString, sprintf_tmp_buf, "%d - INT16*: %X->(%04X)", argIdx, argValue, val);
			);
			break;
		case get_type_id<UINT32>():
		case get_type_id<INT32>():
			PRINTER(
				string_printf(argsString, sprintf_tmp_buf, "%d - INT32: %X", argIdx, argValue);
			);
			break;
		case get_type_id<PUINT32>():
		case get_type_id<PINT32>():
			PRINTER(
				UINT32 val = readUserArgPtr<PUINT32>(argValue, g_Apis);
			string_printf(argsString, sprintf_tmp_buf, "%d - INT32*: %X->(%X)", argIdx, argValue, val);
			);
			break;
		case get_type_id<ULONG>():
		case get_type_id<LONG>():
			PRINTER(
				string_printf(argsString, sprintf_tmp_buf, "%d - LONG: %X", argIdx, argValue);
			);
			break;
		case get_type_id<PULONG>():
		case get_type_id<PLONG>():
			PRINTER(
				ULONG val = readUserArgPtr<PULONG>(argValue, g_Apis);
			string_printf(argsString, sprintf_tmp_buf, "%d - LONG*: %X->(%X)", argIdx, argValue, val);
			);
			break;
		case get_type_id<ULONGLONG>():
		case get_type_id<LONGLONG>():
			PRINTER(
				string_printf(argsString, sprintf_tmp_buf, "%d - LONGLONG: %X", argIdx, argValue);
			);
			break;
		case get_type_id<PLONGLONG>():
		case get_type_id<PULONGLONG>():
			PRINTER(
				ULONGLONG val = readUserArgPtr<PULONGLONG>(argValue, g_Apis);
			string_printf(argsString, sprintf_tmp_buf, "%d - LONGLONG*: %X->(%X)", argIdx, argValue, val);
			);
			break;
		case get_type_id<PVOID>():
			PRINTER(
				string_printf(argsString, sprintf_tmp_buf, "%d - PVOID: %X", argIdx, argValue);
			);
			break;
		case get_type_id<PVOID*>():
			PRINTER(
				PVOID val = readUserArgPtr<PVOID*>(argValue, g_Apis);
			string_printf(argsString, sprintf_tmp_buf, "%d - PVOID*: %X->(%X)", argIdx, argValue, val);
			);
			break;
		case get_type_id<PSTR>():
			PRINTER(
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
			);
			break;
		case get_type_id<PWSTR>():
			PRINTER(
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
			);
			break;
		case get_type_id<MY_VIRTUAL_MEMORY_INFORMATION_CLASS>():
			PRINTER(
				string_printf(argsString, sprintf_tmp_buf, "%d - VM_INFO: %s", argIdx, get_enum_value_name<COMPLETE_VIRTUAL_MEMORY_INFORMATION_CLASS>(argValue));
			);
			break;
		case get_type_id<MY_PROCESSINFOCLASS>():
			PRINTER(
				string_printf(argsString, sprintf_tmp_buf, "%d - PROC_INFO_CLASS: %s", argIdx, get_enum_value_name<COMPLETE_PROCESSINFOCLASS>(argValue));
			);
			break;
		case get_type_id<MY_TOKENINFOCLASS>():
			PRINTER(
				string_printf(argsString, sprintf_tmp_buf, "%d - TOKEN_INFO_CLASS: %s", argIdx, get_enum_value_name<COMPLETE_TOKEN_INFO_CLASS>(argValue));
			);
			break;
		case get_type_id<MY_THREADINFOCLASS>():
			PRINTER(
				string_printf(argsString, sprintf_tmp_buf, "%d - THREADINFOCLASS: %s", argIdx, get_enum_value_name<COMPLETE_THREADINFOCLASS>(argValue));
			);
			break;
		case get_type_id<MY_PMEMORY_RANGE_ENTRY>():
			PRINTER(
				MEMORY_RANGE_ENTRY range = readUserArgPtr<PMEMORY_RANGE_ENTRY>(argValue, g_Apis);
			string_printf(argsString, sprintf_tmp_buf, "%d - VA: %X (Size: %X)", argIdx, range.VirtualAddress, range.NumberOfBytes);
			);
			break;
		case get_type_id<MY_HANDLE>():
			PRINTER(
				string_printf(argsString, sprintf_tmp_buf, "%d - HANDLE: %X", argIdx, argValue);
			);
			break;
		case get_type_id<MY_PHANDLE>():
			PRINTER(
				HANDLE handle = readUserArgPtr<PHANDLE>(argValue, g_Apis);
			string_printf(argsString, sprintf_tmp_buf, "%d - HANDLE*: %X->(%X)", argIdx, argValue, handle);
			);
			break;
		case get_type_id<MY_ACCESS_MASK>():
			PRINTER(
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
			);
			break;
		case get_type_id<PLARGE_INTEGER>():
			PRINTER(
				LARGE_INTEGER largeInt = readUserArgPtr<PLARGE_INTEGER>(argValue, g_Apis);
			string_printf(argsString, sprintf_tmp_buf, "%d - LARGE_INTEGER: %08X", argIdx, largeInt.QuadPart);
			);
			break;
		case get_type_id<PUNICODE_STRING>():
			PRINTER(
				UNICODE_STRING ustr = readUserArgPtr<PUNICODE_STRING>(argValue, g_Apis);
			string_printf(argsString, sprintf_tmp_buf, "%d - USTR: %wZ", argIdx, &ustr);
			);
			break;
		case get_type_id<POBJECT_ATTRIBUTES>():
			PRINTER(
				OBJECT_ATTRIBUTES attrs = readUserArgPtr<POBJECT_ATTRIBUTES>(argValue, g_Apis);
			UNICODE_STRING ustr = readUserArgPtr<PUNICODE_STRING>(attrs.ObjectName, g_Apis);
			string_printf(argsString, sprintf_tmp_buf, "%d - OBJ_ATTRS::USTR: %wZ", argIdx, &ustr);
			);
			break;
		default:
			PRINTER(
				string_printf(argsString, sprintf_tmp_buf, "%d - NOT_IMPLEMENTED", argIdx);
			);
			break;
		}

		// seperate args if not at last one
		if (argIdx != argTypes.size() - 1) {
			PRINTER(
				string_printf(argsString, sprintf_tmp_buf, ", ");
			);
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
extern "C" __declspec(dllexport) void StpCallbackReturn(ULONG64 pService, ULONG32 probeId, MachineState & ctx, CallerInfo & callerinfo) {
	if (strcmp(callerinfo.processName, "test.exe") == 0) {
		LOG_INFO("[RETURN] %s %s\r\n", get_probe_name((PROBE_IDS)probeId), callerinfo.processName);
	}
}
ASSERT_INTERFACE_IMPLEMENTED(StpCallbackReturn, tStpCallbackReturnPlugin, "StpCallbackEntry does not match the interface type");


NTSTATUS DeviceCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

VOID DeviceUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DBGPRINT("FileDeleteRecord::DeviceUnload");
}

/*
*   /GS- must be set to disable stack cookies and have DriverEntry
*   be the entrypoint. GsDriverEntry sets up stack cookie and calls
*   Driver Entry normally.
*/
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    // !MUST BE FIRST FOR LOGGING TO WORK!
	// we include usermode folders for the STL to work 
    // which don't link the stdio stuff correctly. 
    // We do this to fetch the correct kernel implementation....gross...yes I know
	UNICODE_STRING name = { 0 };
	RtlInitUnicodeString(&name, L"_snprintf");
	g_p_snprintf = (t_snprintf)MmGetSystemRoutineAddress(&name);

    DBGPRINT("FileDeleteRecord::DriverEntry()");
	
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DeviceCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DeviceCreateClose;
    DriverObject->DriverUnload = DeviceUnload;

    return STATUS_SUCCESS;
}
