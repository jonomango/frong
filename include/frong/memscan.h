#pragma once

#include "debug.h"
#include "nt.h"

#include "process.h"
#include "module.h"

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
  constexpr bool operator()(MEMORY_BASIC_INFORMATION const&) const { return true; }
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
  constexpr pattern(char const (&string)[Size])
    : string_(build(string, std::make_index_sequence<Size - 1>{})) {}

  // does the pattern match?
  bool operator()(void*, void* const buffer, size_t const size) const;

private:
  // create the std::array from the string
  template <size_t ...indices>
  static constexpr auto build(char const* string, std::index_sequence<indices...>) {
    return std::array{ string[indices]... };
  }

private:
  std::array<char, Size - 1> const string_;
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
bool simple_compare<T>::operator()(void* address, void* const buffer, size_t const size) const {
  if constexpr (alignof(T) != 1)
    // make sure address is aligned correctly
    if ((uintptr_t)address & (alignof(T) - 1))
      return false;

  // too smol
  if (size < sizeof(T))
    return false;

  return *(T*)buffer == value_to_search_for;
}

// does the pattern match?
template <size_t Size>
inline bool pattern<Size>::operator()(void*, void* const buffer, size_t const size) const {
  // of course this doesn't match, it's not big enough!
  if (size < string_.size())
    return false;

  for (size_t offset = 0, i = 0; i < string_.size(); ++i) {
    // ignore spaces
    if (string_[i] == ' ')
      continue;

    // wildcard
    if (string_[i] == '?') {
      offset += 1;
      continue;
    }

    static auto const hex2int = [](char const c) -> unsigned {
      if (c >= '0' && c <= '9')
        return c - '0';
      else if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
      else if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
      return 0;
    };

    // the byte value
    auto const value = hex2int(string_[i]) << 4 | hex2int(string_[i + 1]);

    // value doesn't match :(
    if (value != ((uint8_t*)buffer)[offset])
      return false;

    i += 1;
    offset += 1;
  }

  return true;
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
    if (!filter(mbi))
      continue;

    // add this region
    (count++, dest++) = {
      mbi.BaseAddress,
      mbi.RegionSize
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
  // compare function that filters by biggest size
  struct {
    bool operator()(region const& a, region const& b) const {
      return a.size < b.size;
    }
  } region_compare;

  // memory regions to search in
  if (regions.empty())
    return 0;

  // get the biggest region size
  auto const buffer_size = max_element(
    begin(regions), end(regions), region_compare)->size;

  // allocate a buffer to read memory into
  auto const buffer = std::make_unique<uint8_t[]>(buffer_size);

  // number of matches
  size_t count = 0;

  // iterate over every region
  for (auto [base, size] : regions) {
    // read
    size = proc.read(base, buffer.get(), size);

    if (size == 0)
      // error reading memory
      continue;

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
  // TODO: implement...
  auto const m = proc.module(module_name);

  if (!m)
    // module not found...
    return 0;

  std::array const regions{ region{
    // base
    m->base,

    // size
    proc.x64() ?
      module_size<8>(proc, m->base) :
      module_size<4>(proc, m->base)
  } };

  return memscan(proc, dest, compare, regions);
}

// returns the results in an std::vector (only memory inside of the specified module will be scanned)
template <typename Compare>
inline std::vector<void*> memscan(process const& proc, Compare const& compare, std::wstring_view const module_name) {
  std::vector<void*> r;
  memscan(proc, back_inserter(r), compare, module_name);
  return r;
}

} // namespace frg