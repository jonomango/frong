#pragma once

#include "debug.h"

#include <Windows.h>
#include <winternl.h>

#include <cstdint>
#include <type_traits>

// yes i know, i know, macros are bad...
#define FRONG_CALL_NTDLL_EXPORT(name, ...)\
  static auto const export_func_##name = (decltype(&name))\
    GetProcAddress(GetModuleHandleA("ntdll.dll"), #name);\
  FRONG_ASSERT(export_func_##name != nullptr);\
  return export_func_##name(__VA_ARGS__)

namespace frg::nt {

// process environment block
template <size_t PtrSize>
struct PEB {
  using Ptr = std::conditional_t<PtrSize == 8, uint64_t, uint32_t>;

  union {
    Ptr Alignment1;
    struct {
      uint8_t InheritedAddressSpace;
      uint8_t ReadImageFileExecOptions;
      uint8_t BeingDebugged;
      uint8_t BitField;
    };
  };

  Ptr Mutant;
  Ptr ImageBaseAddress;
  Ptr Ldr;
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