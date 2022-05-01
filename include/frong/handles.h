#pragma once

#include "nt.h"

#include <memory>

namespace frg {

struct handle_info {
  uint32_t    pid;
  HANDLE      handle;
  ACCESS_MASK access;
  uint8_t     type;
  void*       object;
};

// iterate over every open handle in the system
template <typename Callback>
void iterate_handles(Callback&& callback);


//
//
// implementation below
//
//


// iterate over every open handle in the system
template <typename Callback>
inline void iterate_handles(Callback&& callback) {
  DWORD size = 0;
  nt::SYSTEM_HANDLE_INFORMATION tmp;

  // STATUS_INFO_LENGTH_MISMATCH
  if (0xC0000004 != nt::NtQuerySystemInformation(
    nt::SystemHandleInformation, &tmp, sizeof(tmp), &size)) {
    FRONG_DEBUG_ERROR("Failed to query handle information.");
    return;
  }

  auto const buffer = std::make_unique<uint8_t[]>(size + 0x1000);
  auto const info = (nt::SYSTEM_HANDLE_INFORMATION*)buffer.get();

  // query again now that we have our buffer big enough
  if (!NT_SUCCESS(nt::NtQuerySystemInformation(
    nt::SystemHandleInformation, buffer.get(), size + 0x1000, nullptr))) {
    FRONG_DEBUG_ERROR("Failed to query handle information.");
    return;
  }

  for (size_t i = 0; i < info->HandleCount; ++i) {
    auto const& entry = info->Handles[i];

    // call the callback
    if (!callback(handle_info{ entry.ProcessId, (HANDLE)entry.Handle,
        entry.GrantedAccess, entry.ObjectTypeNumber, entry.ObjectAddress }))
      break;
  }
}

} // namespace frg

