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

static constexpr auto SystemHandleInformation = SYSTEM_INFORMATION_CLASS(0x10);

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