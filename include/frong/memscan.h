#pragma once

#include "nt.h"
#include "debug.h"
#include "process.h"

#include <array>
#include <vector>
#include <memory>
#include <algorithm>
#include <string_view>


namespace frg {

// defines a region of memory
struct region {
  void* base;
  size_t size;
};

// doesn't filter any region out
struct filter_none {
  constexpr size_t operator()(MEMORY_BASIC_INFORMATION const& info) const { return info.RegionSize; }
};

// search for a value
template <typename T>
struct simple_compare {
  constexpr simple_compare(T const& value)
    : value_to_search_for(value) {}

  // look for da value
  bool operator()(void* address, void* const buffer, size_t const size) const;

private:
  T value_to_search_for;
};

// search for a specific pattern
template <size_t Size>
class pattern {
public:
  // construct a pattern from an ida style sig
  constexpr pattern(char const (&ptrn)[Size]);

  // does the pattern match?
  bool operator()(void*, void* buffer, size_t size) const;

  // return the pattern in a pretty string
  std::string display() const;

private:
  // parse an ascii hex character as a number
  static constexpr uint8_t parse_hex(char letter);

private:
  // the number of bytes in the pattern/mask
  size_t size_ = 0;

  // only set bits in the mask are checked
  std::array<bool, Size - 1> mask_;

  // bytes to search for
  std::array<uint8_t, Size - 1> pattern_;
};

// get memory regions that pass the Filter test
template <typename Filter, typename OutIt>
size_t regions(process const& proc, OutIt dest, Filter const& filter);

// returns an std::vector of memory ranges
template <typename Filter>
std::vector<region> regions(process const& proc, Filter const& filter);

// scan memory for stuffs
template <typename Compare, typename Regions, typename OutIt, void*>
size_t memscan(process const& proc, OutIt dest, Compare const& compare, Regions const& regions);

// returns the results in an std::vector
template <typename Compare, typename Regions, void*>
std::vector<void*> memscan(process const& proc, Compare const& compare, Regions const& regions);

// scan memory for stuffs (only memory inside of the specified module will be scanned)
template <typename Compare, typename OutIt>
size_t memscan(process const& proc, OutIt dest, Compare const& compare, std::wstring_view module_name);

// returns the results in an std::vector (only memory inside of the specified module will be scanned)
template <typename Compare>
std::vector<void*> memscan(process const& proc, Compare const& compare, std::wstring_view module_name);


//
//
// implementation below
//
//


namespace impl {

// checks whether this container is suitable for memscan()
// note: this check is not perfect or even close to it-- it doesn't check
//       whether the container has begin() and end() and lots of more stuff
//       but it is suitable enough to distiniguish between std::wstring_view
//       and a region container
template <typename Container>
static constexpr bool valid_scan_container = std::is_same_v<
  std::remove_reference_t<decltype(std::declval<Container>()[0])>, region>;

} // namespace impl

// look for da value
template <typename T>
inline bool simple_compare<T>::operator()(void* const address, void* const buffer, size_t const size) const {
  if constexpr (alignof(T) != 1)
    // make sure address is aligned correctly
    if ((uintptr_t)address & (alignof(T) - 1))
      return false;

  // too smol
  if (size < sizeof(T))
    return false;

  return *(T*)buffer == value_to_search_for;
}

// construct a pattern from an ida style sig
template <size_t Size>
inline constexpr pattern<Size>::pattern(char const (&ptrn)[Size]) {
  size_ = 0;

  // parse the pattern
  for (size_t i = 0; i < Size - 1; ++i) {
    // ignore whitespace
    if (ptrn[i] == ' ')
      continue;

    size_ += 1;

    // wildcard
    if (ptrn[i] == '?') {
      mask_[size_ - 1] = false;
      continue;
    }

    // enable this byte
    mask_[size_ - 1] = true;

    // parse the next two letters as a byte
    pattern_[size_ - 1] = parse_hex(ptrn[i + 1]) +
      parse_hex(ptrn[i]) * 0x10;

    // skip the next letter since we will be consuming two letters
    i += 1;
  }
}

// does the pattern match?
template <size_t Size>
inline bool pattern<Size>::operator()(void*, void* const buffer, size_t const size) const {
  if (size < size_)
    return false;

  for (size_t i = 0; i < size_; ++i) {
    // wildcard
    if (!mask_[i])
      continue;

    if (pattern_[i] != *((uint8_t*)buffer + i))
      return false;
  }

  return true;
}

// return the pattern in a pretty string
template <size_t Size>
inline std::string pattern<Size>::display() const {
  std::string str = "";

  for (size_t i = 0; i < size_; ++i) {
    if (!str.empty())
      str += ' ';

    if (!mask_[i])
      str += '?';
    else {
      str += pattern_[i] / 0x10;
      str.back() += str.back() <= 9 ? '0' : 'A' - 10;

      str += pattern_[i] % 0x10;
      str.back() += str.back() <= 9 ? '0' : 'A' - 10;
    }
  }

  return str;
}

// parse an ascii hex character as a number
template <size_t Size>
inline constexpr uint8_t pattern<Size>::parse_hex(char const letter) {
  if (letter >= '0' && letter <= '9')
    return letter - '0';
  else if (letter >= 'A' && letter <= 'F')
    return letter - 'A' + 0xA;
  else if (letter >= 'a' && letter <= 'f')
    return letter - 'a' + 0xA;
  return 0;
}

// get memory regions that pass the Filter test
template <typename Filter, typename OutIt>
inline size_t regions(process const& proc, OutIt dest, Filter const& filter) {
  // number of regions added
  size_t count = 0;

  MEMORY_BASIC_INFORMATION mbi{};
  mbi.BaseAddress = nullptr;

  for (; true; mbi.BaseAddress = (uint8_t*)mbi.BaseAddress + mbi.RegionSize) {
    // query the next memory region
    if (VirtualQueryEx(proc.handle(), mbi.BaseAddress, &mbi, sizeof(mbi)) != sizeof(mbi))
      break;

    // not backed by physical memory
    if (mbi.State != MEM_COMMIT)
      continue;

    // we cant read this memory :(
    if (mbi.Protect & PAGE_GUARD || mbi.Protect & PAGE_NOACCESS)
      continue;

    // ignore this region
    auto const size = filter(mbi);
    if (size == 0)
      continue;

    // add this region
    (count++, dest++) = {
      mbi.BaseAddress,
      size
    };
  }

  return count;
}

// returns an std::vector of memory ranges
template <typename Filter>
inline std::vector<region> regions(process const& proc, Filter const& filter) {
  std::vector<region> r;
  regions(proc, back_inserter(r), filter);
  return r;
}

// scan memory for stuffs
template <typename Compare, typename Regions, typename OutIt,
  // ugly af but needed for the module_name overload to work properly
  std::enable_if_t<impl::valid_scan_container<Regions>>* = nullptr>
inline size_t memscan(process const& proc, OutIt dest, Compare const& compare, Regions const& regions) {
  // memory regions to search in
  if (regions.empty())
    return 0;

  // get the biggest region size
  auto const buffer_size = max_element(std::begin(regions), std::end(regions), 
      [](region const& a, region const& b) {
    return a.size < b.size;
  })->size;

  // allocate a buffer to read memory into
  auto const buffer = std::make_unique<uint8_t[]>(buffer_size);

  // number of matches
  size_t count = 0;

  // iterate over every region
  for (auto [base, size] : regions) {
    // read
    size = proc.read(base, buffer.get(), size);

    if (size == 0) {
      FRONG_DEBUG_WARNING("Failed to read memory: <%p>", base);
      continue;
    }

    for (size_t offset = 0; offset < size; ++offset) {
      // does this match?
      if (!compare((uint8_t*)base + offset, (uint8_t*)buffer.get() + offset, size - offset))
        continue;

      (count++, dest++) = (uint8_t*)base + offset;
    }
  }

  return count;
}

// returns the results in an std::vector
template <typename Compare, typename Regions,
  // ugly af but needed for the module_name overload to work properly
  std::enable_if_t<impl::valid_scan_container<Regions>>* = nullptr>
inline std::vector<void*> memscan(process const& proc, Compare const& compare, Regions const& regions) {
  std::vector<void*> r;
  memscan(proc, back_inserter(r), compare, regions);
  return r;
}

// scan memory for stuffs (only memory inside of the specified module will be scanned)
template <typename Compare, typename OutIt>
inline size_t memscan(process const& proc, OutIt dest, Compare const& compare, std::wstring_view const module_name) {
  auto const m = proc.module(module_name);

  if (!m)
    // module not found...
    return 0;

  return memscan(proc, dest, compare, regions(proc, 
    [&m](MEMORY_BASIC_INFORMATION const& info) -> size_t {
    // address is not within module
    if (info.BaseAddress < m->base() || info.BaseAddress >= (uint8_t*)m->base() + m->size())
      return 0;

    // TODO: not thoroughly tested
    return min((uint8_t*)info.BaseAddress + info.RegionSize, 
      (uint8_t*)m->base() + m->size()) - (uint8_t*)info.BaseAddress;
  }));
}

// returns the results in an std::vector (only memory inside of the specified module will be scanned)
template <typename Compare>
inline std::vector<void*> memscan(process const& proc, Compare const& compare, std::wstring_view const module_name) {
  std::vector<void*> r;
  memscan(proc, back_inserter(r), compare, module_name);
  return r;
}

} // namespace frg