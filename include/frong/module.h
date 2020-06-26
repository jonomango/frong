#pragma once

#include "process.h"
#include "debug.h"
#include "nt.h"

#include <string>


namespace frg {

// return the address of a module's IMAGE_NT_HEADER
void* ntheader(process const& proc, module_base const base);

// the size of an image
template <size_t PtrSize>
size_t module_size(process const& proc, module_base const base);


//
//
// implementation below
//
//


// return the address of a module's IMAGE_NT_HEADER
inline void* ntheader(process const& proc, module_base const base) {
  FRONG_ASSERT(proc.valid());
  FRONG_ASSERT(base != nullptr);
  
  // base + IMAGE_DOS_HEADER::e_lfanew
  return (uint8_t*)base + proc.read<uint32_t>(
    (uint8_t*)base + offsetof(IMAGE_DOS_HEADER, e_lfanew));
}

// the size of an image
template <size_t PtrSize>
inline size_t module_size(process const& proc, module_base const base) {
  using nt_header = std::conditional_t<PtrSize == 8, IMAGE_NT_HEADERS64, IMAGE_NT_HEADERS32>;

  // read the nt header
  auto const nth = proc.read<nt_header>(ntheader(proc, base));
  return nth.OptionalHeader.SizeOfImage;
}

} // namespace frg