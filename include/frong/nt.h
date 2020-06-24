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

namespace frg::nt {

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
  ptr Padding5[3];
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
  ptr Padding2[3];
public:
  LIST_ENTRY<PtrSize> InMemoryOrderModuleList; // LDR_DATA_TABLE_ENTRY
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
};

// ntdll!NtQueryInformationProcess
inline NTSTATUS NTAPI NtQueryInformationProcess(
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

} // namespace frg::nt