#pragma once

#include "debug.h"
#include "helpers.h"

#include <Windows.h>
#include <winternl.h>

// yes i know, i know, macros are bad...
#define FRONG_CALL_NTDLL_EXPORT(name, ...)\
  static auto const export_func_##name = (decltype(&name))\
    GetProcAddress(GetModuleHandleA("ntdll.dll"), #name);\
  FRONG_ASSERT(export_func_##name != nullptr);\
  return export_func_##name(__VA_ARGS__)

#pragma warning(push)
#pragma warning(disable: 4201) // warning C4201: nonstandard extension used: nameless struct/union

namespace frg::nt {

// SYSTEM_INFORMATION_CLASS
static constexpr auto SystemBasicInformation = (SYSTEM_INFORMATION_CLASS)0x00;
static constexpr auto SystemProcessorInformation = (SYSTEM_INFORMATION_CLASS)0x01;
static constexpr auto SystemPerformanceInformation = (SYSTEM_INFORMATION_CLASS)0x02;
static constexpr auto SystemTimeOfDayInformation = (SYSTEM_INFORMATION_CLASS)0x03;
static constexpr auto SystemPathInformation = (SYSTEM_INFORMATION_CLASS)0x04;
static constexpr auto SystemProcessInformation = (SYSTEM_INFORMATION_CLASS)0x05;
static constexpr auto SystemCallCountInformation = (SYSTEM_INFORMATION_CLASS)0x06;
static constexpr auto SystemDeviceInformation = (SYSTEM_INFORMATION_CLASS)0x07;
static constexpr auto SystemProcessorPerformanceInformation = (SYSTEM_INFORMATION_CLASS)0x08;
static constexpr auto SystemFlagsInformation = (SYSTEM_INFORMATION_CLASS)0x09;
static constexpr auto SystemCallTimeInformation = (SYSTEM_INFORMATION_CLASS)0x0A;
static constexpr auto SystemModuleInformation = (SYSTEM_INFORMATION_CLASS)0x0B;
static constexpr auto SystemLocksInformation = (SYSTEM_INFORMATION_CLASS)0x0C;
static constexpr auto SystemStackTraceInformation = (SYSTEM_INFORMATION_CLASS)0x0D;
static constexpr auto SystemPagedPoolInformation = (SYSTEM_INFORMATION_CLASS)0x0E;
static constexpr auto SystemNonPagedPoolInformation = (SYSTEM_INFORMATION_CLASS)0x0F;
static constexpr auto SystemHandleInformation = (SYSTEM_INFORMATION_CLASS)0x10;
static constexpr auto SystemObjectInformation = (SYSTEM_INFORMATION_CLASS)0x11;
static constexpr auto SystemPageFileInformation = (SYSTEM_INFORMATION_CLASS)0x12;
static constexpr auto SystemVdmInstemulInformation = (SYSTEM_INFORMATION_CLASS)0x13;
static constexpr auto SystemVdmBopInformation = (SYSTEM_INFORMATION_CLASS)0x14;
static constexpr auto SystemFileCacheInformation = (SYSTEM_INFORMATION_CLASS)0x15;
static constexpr auto SystemPoolTagInformation = (SYSTEM_INFORMATION_CLASS)0x16;
static constexpr auto SystemInterruptInformation = (SYSTEM_INFORMATION_CLASS)0x17;
static constexpr auto SystemDpcBehaviorInformation = (SYSTEM_INFORMATION_CLASS)0x18;
static constexpr auto SystemFullMemoryInformation = (SYSTEM_INFORMATION_CLASS)0x19;
static constexpr auto SystemLoadGdiDriverInformation = (SYSTEM_INFORMATION_CLASS)0x1A;
static constexpr auto SystemUnloadGdiDriverInformation = (SYSTEM_INFORMATION_CLASS)0x1B;
static constexpr auto SystemTimeAdjustmentInformation = (SYSTEM_INFORMATION_CLASS)0x1C;
static constexpr auto SystemSummaryMemoryInformation = (SYSTEM_INFORMATION_CLASS)0x1D;
static constexpr auto SystemNextEventIdInformation = (SYSTEM_INFORMATION_CLASS)0x1E;
static constexpr auto SystemMirrorMemoryInformation = (SYSTEM_INFORMATION_CLASS)0x1E;
static constexpr auto SystemEventIdsInformation = (SYSTEM_INFORMATION_CLASS)0x1F;
static constexpr auto SystemPerformanceTraceInformation = (SYSTEM_INFORMATION_CLASS)0x1F;
static constexpr auto SystemCrashDumpInformation = (SYSTEM_INFORMATION_CLASS)0x20;
static constexpr auto SystemExceptionInformation = (SYSTEM_INFORMATION_CLASS)0x21;
static constexpr auto SystemCrashDumpStateInformation = (SYSTEM_INFORMATION_CLASS)0x22;
static constexpr auto SystemKernelDebuggerInformation = (SYSTEM_INFORMATION_CLASS)0x23;
static constexpr auto SystemContextSwitchInformation = (SYSTEM_INFORMATION_CLASS)0x24;
static constexpr auto SystemRegistryQuotaInformation = (SYSTEM_INFORMATION_CLASS)0x25;
static constexpr auto SystemExtendServiceTableInformation = (SYSTEM_INFORMATION_CLASS)0x26;
static constexpr auto SystemPrioritySeperation = (SYSTEM_INFORMATION_CLASS)0x27;
static constexpr auto SystemPlugPlayBusInformation = (SYSTEM_INFORMATION_CLASS)0x28;
static constexpr auto SystemVerifierAddDriverInformation = (SYSTEM_INFORMATION_CLASS)0x28;
static constexpr auto SystemDockInformation = (SYSTEM_INFORMATION_CLASS)0x29;
static constexpr auto SystemVerifierRemoveDriverInformation = (SYSTEM_INFORMATION_CLASS)0x29;
static constexpr auto SystemPowerInformation = (SYSTEM_INFORMATION_CLASS)0x2A;
static constexpr auto SystemProcessorIdleInformation = (SYSTEM_INFORMATION_CLASS)0x2A;
static constexpr auto SystemProcessorSpeedInformation = (SYSTEM_INFORMATION_CLASS)0x2B;
static constexpr auto SystemLegacyDriverInformation = (SYSTEM_INFORMATION_CLASS)0x2B;
static constexpr auto SystemCurrentTimeZoneInformation = (SYSTEM_INFORMATION_CLASS)0x2C;
static constexpr auto SystemLookasideInformation = (SYSTEM_INFORMATION_CLASS)0x2D;
static constexpr auto SystemTimeSlipNotification = (SYSTEM_INFORMATION_CLASS)0x2E;
static constexpr auto SystemSessionCreate = (SYSTEM_INFORMATION_CLASS)0x2F;
static constexpr auto SystemSessionDetach = (SYSTEM_INFORMATION_CLASS)0x30;
static constexpr auto SystemSessionInformation = (SYSTEM_INFORMATION_CLASS)0x31;
static constexpr auto SystemRangeStartInformation = (SYSTEM_INFORMATION_CLASS)0x32;
static constexpr auto SystemVerifierInformation = (SYSTEM_INFORMATION_CLASS)0x33;
static constexpr auto SystemVerifierThunkExtend = (SYSTEM_INFORMATION_CLASS)0x34;
static constexpr auto SystemSessionProcessInformation = (SYSTEM_INFORMATION_CLASS)0x35;
//static constexpr auto SystemObjectSecurityMode = (SYSTEM_INFORMATION_CLASS)0x36;
static constexpr auto SystemLoadGdiDriverInSystemSpace = (SYSTEM_INFORMATION_CLASS)0x36;
static constexpr auto SystemNumaProcessorMap = (SYSTEM_INFORMATION_CLASS)0x37;
static constexpr auto SystemPrefetcherInformation = (SYSTEM_INFORMATION_CLASS)0x38;
static constexpr auto SystemExtendedProcessInformation = (SYSTEM_INFORMATION_CLASS)0x39;
static constexpr auto SystemRecommendedSharedDataAlignment = (SYSTEM_INFORMATION_CLASS)0x3A;
static constexpr auto SystemComPlusPackage = (SYSTEM_INFORMATION_CLASS)0x3B;
static constexpr auto SystemNumaAvailableMemory = (SYSTEM_INFORMATION_CLASS)0x3C;
static constexpr auto SystemProcessorPowerInformation = (SYSTEM_INFORMATION_CLASS)0x3D;
static constexpr auto SystemEmulationBasicInformation = (SYSTEM_INFORMATION_CLASS)0x3E;
static constexpr auto SystemEmulationProcessorInformation = (SYSTEM_INFORMATION_CLASS)0x3F;
static constexpr auto SystemExtendedHandleInformation = (SYSTEM_INFORMATION_CLASS)0x40;
static constexpr auto SystemLostDelayedWriteInformation = (SYSTEM_INFORMATION_CLASS)0x41;
static constexpr auto SystemBigPoolInformation = (SYSTEM_INFORMATION_CLASS)0x42;
static constexpr auto SystemSessionPoolTagInformation = (SYSTEM_INFORMATION_CLASS)0x43;
static constexpr auto SystemSessionMappedViewInformation = (SYSTEM_INFORMATION_CLASS)0x44;
static constexpr auto SystemHotpatchInformation = (SYSTEM_INFORMATION_CLASS)0x45;
static constexpr auto SystemObjectSecurityMode = (SYSTEM_INFORMATION_CLASS)0x46;
static constexpr auto SystemWatchdogTimerHandler = (SYSTEM_INFORMATION_CLASS)0x47;
static constexpr auto SystemWatchdogTimerInformation = (SYSTEM_INFORMATION_CLASS)0x48;
static constexpr auto SystemLogicalProcessorInformation = (SYSTEM_INFORMATION_CLASS)0x49;
static constexpr auto SystemWow = (SYSTEM_INFORMATION_CLASS)0x4A;
static constexpr auto SystemRegisterFirmwareTableInformationHandler = (SYSTEM_INFORMATION_CLASS)0x4B;
static constexpr auto SystemFirmwareTableInformation = (SYSTEM_INFORMATION_CLASS)0x4C;
static constexpr auto SystemModuleInformationEx = (SYSTEM_INFORMATION_CLASS)0x4D;
static constexpr auto SystemVerifierTriageInformation = (SYSTEM_INFORMATION_CLASS)0x4E;
static constexpr auto SystemSuperfetchInformation = (SYSTEM_INFORMATION_CLASS)0x4F;
static constexpr auto SystemMemoryListInformation = (SYSTEM_INFORMATION_CLASS)0x50;
static constexpr auto SystemFileCacheInformationEx = (SYSTEM_INFORMATION_CLASS)0x51;
static constexpr auto SystemThreadPriorityClientIdInformation = (SYSTEM_INFORMATION_CLASS)0x52;
static constexpr auto SystemProcessorIdleCycleTimeInformation = (SYSTEM_INFORMATION_CLASS)0x53;
static constexpr auto SystemVerifierCancellationInformation = (SYSTEM_INFORMATION_CLASS)0x54;
static constexpr auto SystemProcessorPowerInformationEx = (SYSTEM_INFORMATION_CLASS)0x55;
static constexpr auto SystemRefTraceInformation = (SYSTEM_INFORMATION_CLASS)0x56;
static constexpr auto SystemSpecialPoolInformation = (SYSTEM_INFORMATION_CLASS)0x57;
static constexpr auto SystemProcessIdInformation = (SYSTEM_INFORMATION_CLASS)0x58;
static constexpr auto SystemErrorPortInformation = (SYSTEM_INFORMATION_CLASS)0x59;
static constexpr auto SystemBootEnvironmentInformation = (SYSTEM_INFORMATION_CLASS)0x5A;
static constexpr auto SystemHypervisorInformation = (SYSTEM_INFORMATION_CLASS)0x5B;
static constexpr auto SystemVerifierInformationEx = (SYSTEM_INFORMATION_CLASS)0x5C;
static constexpr auto SystemTimeZoneInformation = (SYSTEM_INFORMATION_CLASS)0x5D;
static constexpr auto SystemImageFileExecutionOptionsInformation = (SYSTEM_INFORMATION_CLASS)0x5E;
static constexpr auto SystemCoverageInformation = (SYSTEM_INFORMATION_CLASS)0x5F;
static constexpr auto SystemPrefetchPatchInformation = (SYSTEM_INFORMATION_CLASS)0x60;
static constexpr auto SystemVerifierFaultsInformation = (SYSTEM_INFORMATION_CLASS)0x61;
static constexpr auto SystemSystemPartitionInformation = (SYSTEM_INFORMATION_CLASS)0x62;
static constexpr auto SystemSystemDiskInformation = (SYSTEM_INFORMATION_CLASS)0x63;
static constexpr auto SystemProcessorPerformanceDistribution = (SYSTEM_INFORMATION_CLASS)0x64;
static constexpr auto SystemNumaProximityNodeInformation = (SYSTEM_INFORMATION_CLASS)0x65;
static constexpr auto SystemDynamicTimeZoneInformation = (SYSTEM_INFORMATION_CLASS)0x66;
static constexpr auto SystemCodeIntegrityInformation = (SYSTEM_INFORMATION_CLASS)0x67;
static constexpr auto SystemProcessorMicrocodeUpdateInformation = (SYSTEM_INFORMATION_CLASS)0x68;
static constexpr auto SystemProcessorBrandString = (SYSTEM_INFORMATION_CLASS)0x69;
static constexpr auto SystemVirtualAddressInformation = (SYSTEM_INFORMATION_CLASS)0x6A;
static constexpr auto SystemLogicalProcessorAndGroupInformation = (SYSTEM_INFORMATION_CLASS)0x6B;
static constexpr auto SystemProcessorCycleTimeInformation = (SYSTEM_INFORMATION_CLASS)0x6C;
static constexpr auto SystemStoreInformation = (SYSTEM_INFORMATION_CLASS)0x6D;
static constexpr auto SystemRegistryAppendString = (SYSTEM_INFORMATION_CLASS)0x6E;
static constexpr auto SystemAitSamplingValue = (SYSTEM_INFORMATION_CLASS)0x6F;
static constexpr auto SystemVhdBootInformation = (SYSTEM_INFORMATION_CLASS)0x70;
static constexpr auto SystemCpuQuotaInformation = (SYSTEM_INFORMATION_CLASS)0x71;
static constexpr auto SystemNativeBasicInformation = (SYSTEM_INFORMATION_CLASS)0x72;
static constexpr auto SystemErrorPortTimeouts = (SYSTEM_INFORMATION_CLASS)0x73;
static constexpr auto SystemLowPriorityIoInformation = (SYSTEM_INFORMATION_CLASS)0x74;
static constexpr auto SystemBootEntropyInformation = (SYSTEM_INFORMATION_CLASS)0x75;
static constexpr auto SystemVerifierCountersInformation = (SYSTEM_INFORMATION_CLASS)0x76;
static constexpr auto SystemPagedPoolInformationEx = (SYSTEM_INFORMATION_CLASS)0x77;
static constexpr auto SystemSystemPtesInformationEx = (SYSTEM_INFORMATION_CLASS)0x78;
static constexpr auto SystemNodeDistanceInformation = (SYSTEM_INFORMATION_CLASS)0x79;
static constexpr auto SystemAcpiAuditInformation = (SYSTEM_INFORMATION_CLASS)0x7A;
static constexpr auto SystemBasicPerformanceInformation = (SYSTEM_INFORMATION_CLASS)0x7B;
static constexpr auto SystemQueryPerformanceCounterInformation = (SYSTEM_INFORMATION_CLASS)0x7C;
static constexpr auto SystemSessionBigPoolInformation = (SYSTEM_INFORMATION_CLASS)0x7D;
static constexpr auto SystemBootGraphicsInformation = (SYSTEM_INFORMATION_CLASS)0x7E;
static constexpr auto SystemScrubPhysicalMemoryInformation = (SYSTEM_INFORMATION_CLASS)0x7F;
static constexpr auto SystemBadPageInformation = (SYSTEM_INFORMATION_CLASS)0x80;
static constexpr auto SystemProcessorProfileControlArea = (SYSTEM_INFORMATION_CLASS)0x81;
static constexpr auto SystemCombinePhysicalMemoryInformation = (SYSTEM_INFORMATION_CLASS)0x82;
static constexpr auto SystemEntropyInterruptTimingInformation = (SYSTEM_INFORMATION_CLASS)0x83;
static constexpr auto SystemConsoleInformation = (SYSTEM_INFORMATION_CLASS)0x84;
static constexpr auto SystemPlatformBinaryInformation = (SYSTEM_INFORMATION_CLASS)0x85;
static constexpr auto SystemThrottleNotificationInformation = (SYSTEM_INFORMATION_CLASS)0x86;
static constexpr auto SystemPolicyInformation = (SYSTEM_INFORMATION_CLASS)0x86;
static constexpr auto SystemHypervisorProcessorCountInformation = (SYSTEM_INFORMATION_CLASS)0x87;
static constexpr auto SystemDeviceDataInformation = (SYSTEM_INFORMATION_CLASS)0x88;
static constexpr auto SystemDeviceDataEnumerationInformation = (SYSTEM_INFORMATION_CLASS)0x89;
static constexpr auto SystemMemoryTopologyInformation = (SYSTEM_INFORMATION_CLASS)0x8A;
static constexpr auto SystemMemoryChannelInformation = (SYSTEM_INFORMATION_CLASS)0x8B;
static constexpr auto SystemBootLogoInformation = (SYSTEM_INFORMATION_CLASS)0x8C;
static constexpr auto SystemProcessorPerformanceInformationEx = (SYSTEM_INFORMATION_CLASS)0x8D;
static constexpr auto SystemCriticalProcessErrorLogInformation = (SYSTEM_INFORMATION_CLASS)0x8E;
static constexpr auto SystemSecureBootPolicyInformation = (SYSTEM_INFORMATION_CLASS)0x8F;
static constexpr auto SystemPageFileInformationEx = (SYSTEM_INFORMATION_CLASS)0x90;
static constexpr auto SystemSecureBootInformation = (SYSTEM_INFORMATION_CLASS)0x91;
static constexpr auto SystemEntropyInterruptTimingRawInformation = (SYSTEM_INFORMATION_CLASS)0x92;
static constexpr auto SystemPortableWorkspaceEfiLauncherInformation = (SYSTEM_INFORMATION_CLASS)0x93;
static constexpr auto SystemFullProcessInformation = (SYSTEM_INFORMATION_CLASS)0x94;
static constexpr auto SystemKernelDebuggerInformationEx = (SYSTEM_INFORMATION_CLASS)0x95;
static constexpr auto SystemBootMetadataInformation = (SYSTEM_INFORMATION_CLASS)0x96;
static constexpr auto SystemSoftRebootInformation = (SYSTEM_INFORMATION_CLASS)0x97;
static constexpr auto SystemElamCertificateInformation = (SYSTEM_INFORMATION_CLASS)0x98;
static constexpr auto SystemOfflineDumpConfigInformation = (SYSTEM_INFORMATION_CLASS)0x99;
static constexpr auto SystemProcessorFeaturesInformation = (SYSTEM_INFORMATION_CLASS)0x9A;
static constexpr auto SystemRegistryReconciliationInformation = (SYSTEM_INFORMATION_CLASS)0x9B;
static constexpr auto SystemEdidInformation = (SYSTEM_INFORMATION_CLASS)0x9C;
static constexpr auto SystemManufacturingInformation = (SYSTEM_INFORMATION_CLASS)0x9D;
static constexpr auto SystemEnergyEstimationConfigInformation = (SYSTEM_INFORMATION_CLASS)0x9E;
static constexpr auto SystemHypervisorDetailInformation = (SYSTEM_INFORMATION_CLASS)0x9F;
static constexpr auto SystemProcessorCycleStatsInformation = (SYSTEM_INFORMATION_CLASS)0xA0;
static constexpr auto SystemVmGenerationCountInformation = (SYSTEM_INFORMATION_CLASS)0xA1;
static constexpr auto SystemTrustedPlatformModuleInformation = (SYSTEM_INFORMATION_CLASS)0xA2;
static constexpr auto SystemKernelDebuggerFlags = (SYSTEM_INFORMATION_CLASS)0xA3;
static constexpr auto SystemCodeIntegrityPolicyInformation = (SYSTEM_INFORMATION_CLASS)0xA4;
static constexpr auto SystemIsolatedUserModeInformation = (SYSTEM_INFORMATION_CLASS)0xA5;
static constexpr auto SystemHardwareSecurityTestInterfaceResultsInformation = (SYSTEM_INFORMATION_CLASS)0xA6;
static constexpr auto SystemSingleModuleInformation = (SYSTEM_INFORMATION_CLASS)0xA7;
static constexpr auto SystemAllowedCpuSetsInformation = (SYSTEM_INFORMATION_CLASS)0xA8;
static constexpr auto SystemDmaProtectionInformation = (SYSTEM_INFORMATION_CLASS)0xA9;
static constexpr auto SystemInterruptCpuSetsInformation = (SYSTEM_INFORMATION_CLASS)0xAA;
static constexpr auto SystemSecureBootPolicyFullInformation = (SYSTEM_INFORMATION_CLASS)0xAB;
static constexpr auto SystemCodeIntegrityPolicyFullInformation = (SYSTEM_INFORMATION_CLASS)0xAC;
static constexpr auto SystemAffinitizedInterruptProcessorInformation = (SYSTEM_INFORMATION_CLASS)0xAD;
static constexpr auto SystemRootSiloInformation = (SYSTEM_INFORMATION_CLASS)0xAE;
static constexpr auto SystemCpuSetInformation = (SYSTEM_INFORMATION_CLASS)0xAF;
static constexpr auto SystemCpuSetTagInformation = (SYSTEM_INFORMATION_CLASS)0xB0;
static constexpr auto SystemWin = (SYSTEM_INFORMATION_CLASS)0xB1;
static constexpr auto SystemSecureKernelProfileInformation = (SYSTEM_INFORMATION_CLASS)0xB2;
static constexpr auto SystemCodeIntegrityPlatformManifestInformation = (SYSTEM_INFORMATION_CLASS)0xB3;
static constexpr auto SystemInterruptSteeringInformation = (SYSTEM_INFORMATION_CLASS)0xB4;
static constexpr auto SystemSuppportedProcessorArchitectures = (SYSTEM_INFORMATION_CLASS)0xB5;
static constexpr auto SystemMemoryUsageInformation = (SYSTEM_INFORMATION_CLASS)0xB6;
static constexpr auto SystemCodeIntegrityCertificateInformation = (SYSTEM_INFORMATION_CLASS)0xB7;
static constexpr auto SystemPhysicalMemoryInformation = (SYSTEM_INFORMATION_CLASS)0xB8;
static constexpr auto SystemControlFlowTransition = (SYSTEM_INFORMATION_CLASS)0xB9;
static constexpr auto SystemKernelDebuggingAllowed = (SYSTEM_INFORMATION_CLASS)0xBA;
static constexpr auto SystemActivityModerationExeState = (SYSTEM_INFORMATION_CLASS)0xBB;
static constexpr auto SystemActivityModerationUserSettings = (SYSTEM_INFORMATION_CLASS)0xBC;
static constexpr auto SystemCodeIntegrityPoliciesFullInformation = (SYSTEM_INFORMATION_CLASS)0xBD;
static constexpr auto SystemCodeIntegrityUnlockInformation = (SYSTEM_INFORMATION_CLASS)0xBE;
static constexpr auto SystemIntegrityQuotaInformation = (SYSTEM_INFORMATION_CLASS)0xBF;
static constexpr auto SystemFlushInformation = (SYSTEM_INFORMATION_CLASS)0xC0;
static constexpr auto SystemProcessorIdleMaskInformation = (SYSTEM_INFORMATION_CLASS)0xC1;
static constexpr auto SystemSecureDumpEncryptionInformation = (SYSTEM_INFORMATION_CLASS)0xC2;
static constexpr auto SystemWriteConstraintInformation = (SYSTEM_INFORMATION_CLASS)0xC3;
static constexpr auto SystemKernelVaShadowInformation = (SYSTEM_INFORMATION_CLASS)0xC4;
static constexpr auto SystemHypervisorSharedPageInformation = (SYSTEM_INFORMATION_CLASS)0xC5;
static constexpr auto SystemFirmwareBootPerformanceInformation = (SYSTEM_INFORMATION_CLASS)0xC6;
static constexpr auto SystemCodeIntegrityVerificationInformation = (SYSTEM_INFORMATION_CLASS)0xC7;
static constexpr auto SystemFirmwarePartitionInformation = (SYSTEM_INFORMATION_CLASS)0xC8;
static constexpr auto SystemSpeculationControlInformation = (SYSTEM_INFORMATION_CLASS)0xC9;
static constexpr auto SystemDmaGuardPolicyInformation = (SYSTEM_INFORMATION_CLASS)0xCA;
static constexpr auto SystemEnclaveLaunchControlInformation = (SYSTEM_INFORMATION_CLASS)0xCB;

// OBJECT_INFORMATION_CLASS
static constexpr auto ObjectNameInformation = OBJECT_INFORMATION_CLASS(1);

enum THREADINFOCLASS {
  ThreadBasicInformation,
  ThreadTimes,
  ThreadPriority,
  ThreadBasePriority,
  ThreadAffinityMask,
  ThreadImpersonationToken,
  ThreadDescriptorTableEntry,
  ThreadEnableAlignmentFaultFixup,
  ThreadEventPair,
  ThreadQuerySetWin32StartAddress,
  ThreadZeroTlsCell,
  ThreadPerformanceCount,
  ThreadAmILastThread,
  ThreadIdealProcessor,
  ThreadPriorityBoost,
  ThreadSetTlsArrayAddress,
  ThreadIsIoPending,
  ThreadHideFromDebugger
};

template <size_t PtrSize>
struct UNICODE_STRING {
  using ptr = ptr_from_size<PtrSize>;

  uint16_t Length;
  uint16_t MaximumLength;
  ptr Buffer;
};

// doubly linked list entry
template <size_t PtrSize>
struct LIST_ENTRY {
  using ptr = ptr_from_size<PtrSize>;

  ptr Flink;
  ptr Blink;
};

// PEB_LDR_DATA::InMemoryOrderModuleList
template <size_t PtrSize>
struct LDR_DATA_TABLE_ENTRY {
  using ptr = ptr_from_size<PtrSize>;
private:
  ptr Padding1[2];
public:
  LIST_ENTRY<PtrSize> InMemoryOrderLinks;
private:
  ptr Padding2[2];
public:
  ptr DllBase;
private:
  ptr Padding3[2];
public:
  UNICODE_STRING<PtrSize> FullDllName;
private:
  uint8_t Padding4[8];
  ptr     Padding5[3];
public:
  union {
    ptr Alignment1;
    uint32_t CheckSum;
  };
  uint32_t TimeDateStamp;
};

// PEB::Ldr
template <size_t PtrSize>
struct PEB_LDR_DATA {
  using ptr = ptr_from_size<PtrSize>;
private:
  uint8_t Padding1[8];
  ptr     Padding2[3];
public:
  LIST_ENTRY<PtrSize> InMemoryOrderModuleList; // LDR_DATA_TABLE_ENTRY
};

// ApiSet structs are taken from https://lucasg.github.io/2017/10/15/Api-set-resolution/
struct API_SET_NAMESPACE {
  ULONG Version;     // v2 on Windows 7, v4 on Windows 8.1  and v6 on Windows 10
  ULONG Size;        // apiset map size (usually the .apiset section virtual size)
  ULONG Flags;       // according to Geoff Chappell,  tells if the map is sealed or not.
  ULONG Count;       // hash table entry count
  ULONG EntryOffset; // Offset to the api set entries values
  ULONG HashOffset;  // Offset to the api set entries hash indexes
  ULONG HashFactor;  // multiplier to use when computing hash 
};

// Hash table value
struct API_SET_NAMESPACE_ENTRY {
  ULONG Flags;        // sealed flag in bit 0
  ULONG NameOffset;   // Offset to the ApiSet library name PWCHAR (e.g. "api-ms-win-core-job-l2-1-1")
  ULONG NameLength;   // Ignored
  ULONG HashedLength; // Apiset library name length
  ULONG ValueOffset;  // Offset the list of hosts library implement the apiset contract (points to API_SET_VALUE_ENTRY array)
  ULONG ValueCount;   // Number of hosts libraries 
};

// Host Library entry
struct API_SET_VALUE_ENTRY {
  ULONG Flags;        // sealed flag in bit 0
  ULONG NameOffset;   // Offset to the ApiSet library name PWCHAR (e.g. "api-ms-win-core-job-l2-1-1")
  ULONG NameLength;   // Apiset library name length
  ULONG ValueOffset;  // Offset to the Host library name PWCHAR (e.g. "ucrtbase.dll")
  ULONG ValueLength;  // Host library name length
};

// process environment block
template <size_t PtrSize>
struct PEB {
  using ptr = ptr_from_size<PtrSize>;

  union {
    ptr Alignment1;
    struct {
      uint8_t InheritedAddressSpace;
      uint8_t ReadImageFileExecOptions;
      uint8_t BeingDebugged;
      uint8_t BitField;
    };
  };

  ptr Mutant;
  ptr ImageBaseAddress;
  ptr Ldr; // PEB_LDR_DATA

private:
  ptr     Padding1[8];
  uint8_t Padding2[8];

public:
  ptr ApiSetMap; // API_SET_NAMESPACE
};

struct SYSTEM_HANDLE_TABLE_ENTRY_INFO {
  DWORD       ProcessId;
  BYTE        ObjectTypeNumber;
  BYTE        Flags;
  WORD        Handle;
  PVOID       ObjectAddress;
  ACCESS_MASK GrantedAccess;
};

struct SYSTEM_HANDLE_INFORMATION {
  DWORD                          HandleCount;
  SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
};

struct OBJECT_NAME_INFORMATION {
  ::UNICODE_STRING Name;
  WCHAR            NameBuffer[1];
};

struct SYSTEM_BIGPOOL_ENTRY {
  union {
    PVOID     VirtualAddress;
    ULONG_PTR NonPaged : 1;
  };

  ULONG_PTR   SizeInBytes;

  union {
    UCHAR     Tag[4];
    ULONG     TagUlong;
  };
};

struct SYSTEM_BIGPOOL_INFORMATION {
  ULONG                Count;
  SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1];
};

// ntdll!NtQueryInformationProcess
inline NTSTATUS NTAPI 
NtQueryInformationProcess(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength) {
  FRONG_CALL_NTDLL_EXPORT(NtQueryInformationProcess,
    ProcessHandle,
    ProcessInformationClass,
    ProcessInformation, 
    ProcessInformationLength, 
    ReturnLength);
}

// ntdll!NtQueryInformationThread
inline NTSTATUS NTAPI 
NtQueryInformationThread(
    HANDLE          ThreadHandle, 
    THREADINFOCLASS ThreadInformationClass,
    PVOID           ThreadInformation, 
    ULONG           ThreadInformationLength, 
    PULONG          ReturnLength) {
  FRONG_CALL_NTDLL_EXPORT(NtQueryInformationThread,
    ThreadHandle,
    ThreadInformationClass,
    ThreadInformation,
    ThreadInformationLength,
    ReturnLength);
}

// ntdll!NtQuerySystemInformation
inline NTSTATUS NTAPI
NtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength) {
  FRONG_CALL_NTDLL_EXPORT(NtQuerySystemInformation,
    SystemInformationClass,
    SystemInformation,
    SystemInformationLength,
    ReturnLength);
}

// ntdll!NtQueryObject
inline NTSTATUS NTAPI
NtQueryObject(
    HANDLE                   ObjectHandle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID                    ObjectInformation,
    ULONG                    Length,
    PULONG                   ResultLength) {
  FRONG_CALL_NTDLL_EXPORT(NtQueryObject,
    ObjectHandle,
    ObjectInformationClass,
    ObjectInformation,
    Length,
    ResultLength);
}

} // namespace frg::nt

#pragma warning(pop)