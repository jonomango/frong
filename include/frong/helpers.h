#pragma once

#include <cstdint>
#include <type_traits>


namespace frg {

// uint32_t if 4
// uint64_t if 8
template <size_t PtrSize>
using ptr_from_size = std::enable_if_t<PtrSize == 4 || PtrSize == 8, 
  std::conditional_t<PtrSize == 8, uint64_t, uint32_t>>;

// cast to void* (to stop annoying warnings about casting to larger size)
template <typename T>
void* cast_ptr(T const ptr) {
  if constexpr (sizeof(ptr) < sizeof(void*))
    return (void*)(uint64_t)ptr;
  else
    return (void*)ptr;
}

} // namespace frg