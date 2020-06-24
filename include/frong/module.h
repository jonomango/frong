#pragma once

#include <string>


namespace frg {

using module_base = void*;

// represents a module loaded in memory
struct module {
  // full path to the DLL
  std::wstring path;

  // base address of the image in memory
  module_base base = nullptr;
};

} // namespace frg