#pragma once

#include "debug.h"
#include "nt.h"

#include <cstdint>
#include <utility>
#include <vector>
#include <string>
#include <string_view>
#include <optional>
#include <memory>

// for WTS* functions
#include <WtsApi32.h>
#pragma comment(lib, "Wtsapi32.lib")


namespace frg {

struct module_export {
  std::string name;
  void* address;
  uint16_t ordinal;
};

// represents a module loaded in memory
class module {
public:
  module() = default;
  module(void* base, class process const& proc);

  // the base address of the module in memory
  void* base() const;

  // the size of the module
  size_t size() const;

  // name of the module
  std::wstring name(class process const& proc) const;

  // 32 or 64 bit
  // note:
  //   32 bit programs running under wow64 will still have 64bit modules loaded
  //   in memory, e.g. ntdll
  bool x86() const;
  bool x64() const;

  // get all of the module's exports
  template <typename OutIt>
  size_t exports(class process const& proc, OutIt dest) const;

  // returns a vector of exports
  std::vector<module_export> exports(class process const& proc) const;

  // get the address of an export
  void* get_proc_addr(class process const& proc, char const* name) const;

private:
  void* base_ = nullptr;
  size_t size_ = 0;
  bool x64_ = false;

private:
  // the address of the IMAGE_NT_HEADERS
  uint8_t* ntheader(class process const& proc) const;

  // iterate over every export in a loaded module
  template <size_t PtrSize, typename Callback>
  void iterate_exports(class process const& proc, Callback&& callback) const;

  // finds a forwarder export
  void* resolve_forwarder(class process const& proc, std::wstring_view parent, std::string_view forwarder) const;
};

// wrapper over a process handle
class process {
public:
  process() = default;

  // this is explicitly not explicit:
  // we want to be able to pass a HANDLE where a process is expected
  // note: handle requires atleast PROCESS_QUERY_LIMITED_INFORMATION
  //       but without PROCESS_VM_READ most functions wont work
  process(HANDLE handle) noexcept;

  // opens a handle to a process
  explicit process(uint32_t pid);

  // we cant copy but we can move
  process(process&& other) noexcept;
  process& operator=(process&& other) noexcept;

  // close our handle if we were the one that opened it
  ~process();

  // is this process class initialized?
  bool valid() const noexcept;
  explicit operator bool() const noexcept;

  // 32 or 64 bit code
  bool x86() const noexcept;
  bool x64() const noexcept;

  // is this process running under wow64?
  bool wow64() const noexcept;

  // return the underlying handle
  HANDLE handle() const noexcept;

  // get the process's pid
  uint32_t pid() const noexcept;

  // get the name of the process
  std::wstring name() const;

  // get the address of the peb
  template <size_t PtrSize>
  void* peb_addr() const noexcept;

  // read the peb
  template <size_t PtrSize>
  auto peb() const;

  // get a single module
  template <size_t PtrSize>
  std::optional<frg::module> module(std::wstring_view name, std::wstring_view parent = L"") const;

  // calls module() with PtrSize set to 4 if x86() or 8 if x64()
  std::optional<frg::module> module(std::wstring_view name, std::wstring_view parent = L"") const;

  // get a list of loaded modules
  template <size_t PtrSize, typename OutIt>
  size_t modules(OutIt dest) const;

  // calls modules() with PtrSize set to 4 if x86() or 8 if x64()
  template <typename OutIt>
  size_t modules(OutIt dest) const;

  // returns an std::vector of loaded modules
  template <size_t PtrSize>
  std::vector<std::pair<std::wstring, frg::module>> modules() const;

  // calls modules() with PtrSize set to 4 if x86() or 8 if x64()
  std::vector<std::pair<std::wstring, frg::module>> modules() const;

  // external GetProcAddress()
  template <size_t PtrSize>
  void* get_proc_addr(std::wstring_view mod_name, char const* name) const;

  // calls get_proc_addr() with PtrSize set to 4 if x86() or 8 if x64()
  void* get_proc_addr(std::wstring_view mod_name, char const* name) const;

  // read/write memory (returns the number of bytes read/written)
  size_t read(void const* address, void* buffer, size_t size) const;
  size_t write(void* address, void const* buffer, size_t size) const;

  // wrapper for read()
  template <typename T>
  T read(void const* address, size_t* bytes_read = nullptr) const;

  // wrapper for write()
  template <typename T>
  size_t write(void* address, T const& value) const;

  // allocate virtual memory in the process
  void* allocate(size_t size, uint32_t protection = PAGE_READWRITE) const;

  // free memory returned from allocate()
  void free(void* address) const;

private:
  // *****
  // WARNING: any new instance variable must also be added in the move 
  //          assignment operator or else bad things will happen!
  // *****

  HANDLE handle_ = nullptr;

  // the process id
  uint32_t pid_ = 0;

  // process env block
  void* peb32_address_ = nullptr,
    *peb64_address_ = nullptr;

  // should we close the handle ourselves?
  bool close_handle_ = false;

  // x64 vs x86
  bool x64_ = false;

  // a 32-bit process running on a 64-bit machine
  bool wow64_ = false;

private:
  // no copying -_-
  process(process const&) = delete;
  process& operator=(process const&) = delete;

  // cache some stuff
  void initialize();

  // call callback() for every module loaded
  template <size_t PtrSize, typename Callback>
  void iterate_modules(Callback&& callback) const;

  // is this an api set schema dll?
  static bool is_api_set_schema(std::wstring_view name);

  // resolve an api stub dll to it's real dll
  static std::wstring resolve_api_name(std::wstring_view name, std::wstring_view parent = L"");

  // if constexpr is so fucking shit pls fix
  template <size_t PtrSize>
  static nt::API_SET_NAMESPACE* get_api_set_map();
};

// get the pids that have the target process name
template <typename OutIt>
size_t pids_from_name(std::wstring_view name, OutIt dest);

// returns a vector of pids
std::vector<uint32_t> pids_from_name(std::wstring_view name);

// get a process with it's name
// note: an invalid process will be returned if 0 or more
//       than 1 processes are found with a matching name
// if force is true, it will return the first process found
// when multiple processes match the provided name
process process_from_name(std::wstring_view name, bool force = false);


//
//
// implementation below
//
//


// get the pids that have the target process name
template <typename OutIt>
inline size_t pids_from_name(std::wstring_view const name, OutIt dest) {
  DWORD count = 0;
  PWTS_PROCESS_INFOW processes = nullptr;

  // query every active process
  if (!WTSEnumerateProcessesW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &processes, &count)) {
    FRONG_DEBUG_ERROR("Call to WTSEnumerateProcessesA failed.");
    return 0;
  }

  // number of matching processes
  size_t matching = 0;

  for (size_t i = 0; i < count; ++i) {
    // names dont match, continue!
    if (!name.empty() && 0 != _wcsncoll(processes[i].pProcessName, name.data(), name.size()))
      continue;

    (matching++, dest++) = processes[i].ProcessId;
  }

  WTSFreeMemory(processes);
  return matching;
}

// returns a vector of pids
inline std::vector<uint32_t> pids_from_name(std::wstring_view const name) {
  std::vector<uint32_t> pids;
  pids_from_name(name, back_inserter(pids));
  return pids;
}

// get a process with it's name
// note: an invalid process will be returned if 0 or more
//       than 1 processes are found with a matching name
// if force is true, it will return the first process found
// when multiple processes match the provided name
inline process process_from_name(std::wstring_view const name, bool const force) {
  auto const pids = pids_from_name(name);
  
  // process not found
  if (pids.empty()) {
    FRONG_DEBUG_WARNING("No processes found with the name \"%.*ws\"", 
      (int)name.size(), name.data());
    return {};
  }

  // nore than one matching process found
  if (pids.size() > 1 && !force) {
    FRONG_DEBUG_WARNING("Multiple processes found with the name \"%.*ws\"",
      (int)name.size(), name.data());
    return {};
  }

  return process(pids.front());
}

// constructor
module::module(void* base, process const& proc) : base_(base) {
  auto const nth = ntheader(proc);

  // image size
  size_ = proc.read<uint32_t>(nth +
    offsetof(IMAGE_NT_HEADERS, OptionalHeader) +
    offsetof(IMAGE_OPTIONAL_HEADER, SizeOfImage));

  // 64 or 32 bit
  x64_ = IMAGE_FILE_MACHINE_AMD64 ==
    proc.read<uint16_t>(nth +
    offsetof(IMAGE_NT_HEADERS, FileHeader) +
    offsetof(IMAGE_FILE_HEADER, Machine));
}

// the base address of the module in memory
inline void* module::base() const {
  return base_;
}

// the size of the module
inline size_t module::size() const {
  return size_;
}

// name of the module
inline std::wstring module::name(process const& proc) const {
  // cancer cuz im sick of templates
  auto const dir = proc.read<IMAGE_DATA_DIRECTORY>(cast_ptr(ntheader(proc) + 
    offsetof(IMAGE_NT_HEADERS, OptionalHeader) + (x64() ?
    offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) : 
    offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory))));

  if (!dir.VirtualAddress) {
    FRONG_DEBUG_WARNING("Module has no export directory: 0x%p", base_);
    return L"";
  }

  auto const data = proc.read<IMAGE_EXPORT_DIRECTORY>((uint8_t*)base_ + dir.VirtualAddress);

  if (!data.Name) {
    FRONG_DEBUG_WARNING("Module has no export name: 0x%p", base_);
    return L"";
  }

  char buffer[256] = { 0 };
  proc.read((uint8_t*)base_ + data.Name, buffer, sizeof(buffer) - 1);

  // convert to wstring for convenience
  return std::wstring(std::begin(buffer), std::begin(buffer) + strlen(buffer));
}

// 32 or 64 bit
inline bool module::x86() const {
  return !x64_;
}
inline bool module::x64() const {
  return x64_;
}

// get all of the module's exports
template <typename OutIt>
inline size_t module::exports(process const& proc, OutIt dest) const {
  size_t count = 0;

  // name of this module, for resolving forwarded exports
  auto const module_name = name(proc);

  auto const callback = [&](char const* name, 
      uint16_t ordinal, void* address, char const* forwarder) {

    if (forwarder)
      address = resolve_forwarder(proc, module_name, forwarder);

    (count++, dest++) = module_export{
      name,
      address,
      ordinal
    };

    return true;
  };

  x86() ?
    iterate_exports<4>(proc, callback) :
    iterate_exports<8>(proc, callback);

  return count;
}

// returns a vector of exports
inline std::vector<module_export> module::exports(process const& proc) const {
  std::vector<module_export> vec;
  exports(proc, back_inserter(vec));
  return vec;
}

// get the address of an export
inline void* module::get_proc_addr(process const& proc, char const* name) const {
  void* proc_addr = nullptr;

  // search for matching export
  auto const callback = [&](char const* routine, 
      uint16_t ordinal, void* address, char const* forwarder) {
    if (((uintptr_t)name & ~0xFFFF) == 0) {
      // search by ordinal
      if (name != (void*)ordinal)
        return true;
    } else {
      // search by name
      if (strcmp(routine, name))
        return true;
    }

    proc_addr = forwarder ? resolve_forwarder(
      proc, this->name(proc), forwarder) : address;

    return false;
  };

  x86() ?
    iterate_exports<4>(proc, callback) :
    iterate_exports<8>(proc, callback);

  return proc_addr;
}

// the address of the IMAGE_NT_HEADERS
inline uint8_t* module::ntheader(process const& proc) const {
  FRONG_ASSERT(base_ != nullptr);

  // base + IMAGE_DOS_HEADER::e_lfanew
  return (uint8_t*)base_ + proc.read<uint32_t>(
    (uint8_t*)base_ + offsetof(IMAGE_DOS_HEADER, e_lfanew));
}

// iterate over every export in a loaded module
template <size_t PtrSize, typename Callback>
inline void module::iterate_exports(process const& proc, Callback&& callback) const {
  // read the nt header
  auto const nth = proc.read<std::conditional_t<PtrSize == 8,
    IMAGE_NT_HEADERS64, IMAGE_NT_HEADERS32>>(ntheader(proc));

  auto const export_data = nth.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

  // cmon bruh
  if (export_data.Size <= 0)
    return;

  auto const export_buffer = std::make_unique<uint8_t[]>(export_data.Size);

  // read everything at once for huge performance gains
  proc.read((uint8_t*)base_ + export_data.VirtualAddress, 
    export_buffer.get(), export_data.Size);

  auto const export_dir = (PIMAGE_EXPORT_DIRECTORY)export_buffer.get();

  // parallel arrays
  auto const ordinals = (uint16_t*)(&export_buffer[
    export_dir->AddressOfNameOrdinals - export_data.VirtualAddress]);
  auto const name_rvas = (uint32_t*)(&export_buffer[
    export_dir->AddressOfNames - export_data.VirtualAddress]);
  auto const function_rvas = (uint32_t*)(&export_buffer[
    export_dir->AddressOfFunctions - export_data.VirtualAddress]);

  // iterate over every export
  for (size_t i = 0; i < export_dir->NumberOfNames; ++i) {
    // the exported function's name
    auto const name = (char const*)(
      &export_buffer[name_rvas[i] - export_data.VirtualAddress]);

    // the index into the address array
    auto const ordinal = ordinals[i];

    // rva to the exported function
    auto const func_rva = function_rvas[ordinal];

    // does func_rva point to an import name instead
    auto const is_forwarder = func_rva >= export_data.VirtualAddress &&
      func_rva < export_data.VirtualAddress + export_data.Size;

    // the string in our memory space
    auto const forwarder_name = is_forwarder ? (char const*)&export_buffer[
      func_rva - export_data.VirtualAddress] : nullptr;

    // call the callback
    if (!callback(name, (uint16_t)export_dir->Base +
        ordinal, (uint8_t*)base_ + func_rva, forwarder_name))
      break;
  }
}

// finds a forwarder export
inline void* module::resolve_forwarder(process const& proc, 
    std::wstring_view parent, std::string_view forwarder) const {
  auto const split = forwarder.find_first_of('.');
  
  // the name of the module (without the .dll extension)
  std::wstring module_name(begin(forwarder), begin(forwarder) + split);
  module_name += L".dll";
  
  // the name of the import
  auto const import_name = forwarder.data() + split + 1;

  auto const mod = x86() ? 
    proc.module<4>(module_name, parent) :
    proc.module<8>(module_name, parent);

  // rip
  if (!mod)
    return nullptr;

  if (import_name[0] == '#')
    // resolve by ordinal
    return mod->get_proc_addr(proc, (char const*)(uintptr_t)atoi(import_name + 1));

  // resolve by name
  return mod->get_proc_addr(proc, import_name);
}

// this is explicitly not explicit:
// we want to be able to pass a HANDLE where a process is expected
// note: handle requires atleast PROCESS_QUERY_LIMITED_INFORMATION
//       but without PROCESS_VM_READ most functions wont work
inline process::process(HANDLE const handle) noexcept
  : handle_(handle), close_handle_(false) {
  initialize();
}

// opens a handle to a process
inline process::process(uint32_t const pid) {
  static auto constexpr access = 
    PROCESS_VM_READ  |
    PROCESS_VM_WRITE |
    PROCESS_VM_OPERATION |
    PROCESS_QUERY_LIMITED_INFORMATION;

  handle_ = OpenProcess(access, FALSE, pid);

  // rip
  if (!handle_) {
    FRONG_DEBUG_ERROR("Failed to open process with pid %u", pid);
    return;
  }

  close_handle_ = true;
  initialize();
}

// we cant copy but we can move
inline process::process(process&& other) noexcept {
  *this = std::forward<process>(other);
}
inline process& process::operator=(process&& other) noexcept {
  // we can just swap all our instance variables since other's destructor
  // will cleanup our (old) process instance for us :)
  std::swap(handle_,        other.handle_);
  std::swap(pid_,           other.pid_);
  std::swap(peb32_address_, other.peb32_address_);
  std::swap(peb64_address_, other.peb64_address_);
  std::swap(close_handle_,  other.close_handle_);
  std::swap(x64_,           other.x64_);
  std::swap(wow64_,         other.wow64_);

  return *this;
}

// close our handle if we were the one that opened it
inline process::~process() {
  if (valid() && close_handle_)
    CloseHandle(handle_);
}

// is this process class initialized?
inline bool process::valid() const noexcept { 
  return handle_ != nullptr; 
}
inline process::operator bool() const noexcept { 
  return valid(); 
}

// 32 or 64 bit code
inline bool process::x86() const noexcept {
  return !x64_;
}
inline bool process::x64() const noexcept {
  return x64_;
}

// is this process running under wow64?
inline bool process::wow64() const noexcept {
  return wow64_;
}

// return the underlying handle
inline HANDLE process::handle() const noexcept {
  return handle_; 
}

// get the process's pid
inline uint32_t process::pid() const noexcept {
  return pid_;
}

// get the name of the process
inline std::wstring process::name() const {
  wchar_t buffer[512] = { L'\0' };
  unsigned long size = 512;

  // query the process path
  if (!QueryFullProcessImageNameW(handle_, 0, buffer, &size))
    return L"";

  // trim the start of the path
  for (int i = size - 2; i >= 0; --i) {
    if (buffer[i] == L'\\' || buffer[i] == L'/')
      return &buffer[i + 1];
  }

  return buffer;
}

// get the address of the peb
template <size_t PtrSize>
inline void* process::peb_addr() const noexcept {
  FRONG_ASSERT(PtrSize == 4 || PtrSize == 8);

  if constexpr (PtrSize == 8) {
    FRONG_ASSERT(sizeof(void*) == 8);
    return peb64_address_;
  } else {
    FRONG_ASSERT(x86());
    return peb32_address_;
  }
}

// read the peb
template <size_t PtrSize>
inline auto process::peb() const {
  return read<nt::PEB<PtrSize>>(peb_addr<PtrSize>());
}

// get a single module
template <size_t PtrSize>
inline std::optional<frg::module> process::module(
    std::wstring_view const name, std::wstring_view const parent) const {
  FRONG_ASSERT(!name.empty());

  std::wstring real_name(name);

  // api redirection
  if (is_api_set_schema(name))
    real_name = resolve_api_name(name, parent);

  std::optional<frg::module> found_module = {};

  iterate_modules<PtrSize>([&](std::wstring&& path, void* base) {
    // not big enough
    if (path.size() < real_name.size())
      return true;

    auto const bslash = path.find_last_of(L'\\');
    auto const fslash = path.find_last_of(L'/');

    auto n = std::wstring_view(path);

    // we only want the name
    if (bslash != n.npos || fslash != n.npos) {
      if (bslash != n.npos && fslash != n.npos)
        n = n.substr(max(fslash, bslash) + 1);
      else if (fslash != n.npos)
        n = n.substr(fslash + 1);
      else
        n = n.substr(bslash + 1);
    }

    if (n.size() != real_name.size())
      return true;

    // does the name match?
    if (0 == _wcsnicmp(n.data(), real_name.data(), real_name.size())) {
      found_module = frg::module(base, *this);
      return false;
    }

    return true;
  });

  // rip
  if (!found_module) {
    FRONG_DEBUG_WARNING("Failed to find module: %.*ws", 
      (int)name.size(), name.data());
  }

  return found_module;
}

// calls module() with PtrSize set to 4 if x86() or 8 if x64()
inline std::optional<frg::module> process::module(
    std::wstring_view const name, std::wstring_view const parent) const {
  return x64() ? module<8>(name, parent) : module<4>(name, parent);
}

// get a list of loaded modules
template <size_t PtrSize, typename OutIt>
inline size_t process::modules(OutIt dest) const {
  size_t count = 0;

  // iterate over every module and add it to the list
  iterate_modules<PtrSize>([&](std::wstring&& path, void* base) {
    (count++, dest++) = std::pair(std::move(path), frg::module(base, *this));
    return true;
  });

  return count;
}

// calls modules() with PtrSize set to 4 if x86() or 8 if x64()
template <typename OutIt>
inline size_t process::modules(OutIt dest) const {
  return x64() ? modules<8>(dest) : modules<4>(dest);
}

// returns an std::vector of loaded modules
template <size_t PtrSize>
inline std::vector<std::pair<std::wstring, 
    frg::module>> process::modules() const {
  std::vector<std::pair<std::wstring, frg::module>> m;
  modules<PtrSize>(back_inserter(m));
  return m;
}

// calls modules() with PtrSize set to 4 if x86() or 8 if x64()
inline std::vector<std::pair<std::wstring, 
    frg::module>> process::modules() const {
  return x64() ? modules<8>() : modules<4>();
}

// external GetProcAddress()
template <size_t PtrSize>
inline void* process::get_proc_addr(std::wstring_view const mod_name, char const* const name) const {
  auto const mod = module(mod_name);

  if (!mod) {
    FRONG_DEBUG_WARNING("Failed to find module: %.*ws", 
      (int)mod_name.size(), mod_name.data());
    return nullptr;
  }

  return mod->get_proc_addr(*this, name);
}

// calls get_proc_addr() with PtrSize set to 4 if x86() or 8 if x64()
inline void* process::get_proc_addr(std::wstring_view const mod_name, char const* const name) const {
  return x86() ? 
    get_proc_addr<4>(mod_name, name) : 
    get_proc_addr<8>(mod_name, name);
}

// read/write memory (returns the number of bytes read/written)
inline size_t process::read(void const* const address, 
    void* const buffer, size_t const size) const {
  FRONG_ASSERT(size > 0);
  FRONG_ASSERT(buffer != nullptr);
  FRONG_ASSERT(address != nullptr);

  SIZE_T bytes_read = 0;
  if (!ReadProcessMemory(handle_, address, buffer, size, &bytes_read)
      && GetLastError() != ERROR_PARTIAL_COPY) {
    FRONG_DEBUG_ERROR("Failed to read memory at address %p.", address);
    return 0;
  }

  return bytes_read;
}
inline size_t process::write(void* const address, 
    void const* const buffer, size_t const size) const {
  FRONG_ASSERT(size > 0);
  FRONG_ASSERT(buffer != nullptr);
  FRONG_ASSERT(address != nullptr);

  SIZE_T bytes_written = 0;
  if (!WriteProcessMemory(handle_, address, buffer, size, &bytes_written)
      && GetLastError() != ERROR_PARTIAL_COPY) {
    FRONG_DEBUG_ERROR("Failed to write memory at address %p.", address);
    return 0;
  }

  return bytes_written;
}

// wrapper for read()
template <typename T>
inline T process::read(void const* address, size_t* bytes_read) const {
  T buffer{};

  if (bytes_read)
    *bytes_read = read(address, &buffer, sizeof(buffer));
  else
    read(address, &buffer, sizeof(buffer));

  return buffer;
}

// wrapper for write()
template <typename T>
inline size_t process::write(void* const address, T const& value) const {
  return write(address, &value, sizeof(value));
}

// allocate virtual memory in the process
inline void* process::allocate(size_t const size, uint32_t const protection) const {
  FRONG_ASSERT(size > 0);

  return VirtualAllocEx(handle_, nullptr, size, MEM_COMMIT | MEM_RESERVE, protection);
}

// free memory returned from allocate()
inline void process::free(void* const address) const {
  FRONG_ASSERT(address != nullptr);

  VirtualFreeEx(handle_, address, 0, MEM_RELEASE);
}

// cache some stuff
inline void process::initialize() {
  pid_ = GetProcessId(handle_);

  // is this process running under wow64?
  BOOL wow64 = FALSE;
  if (!IsWow64Process(handle_, &wow64))
    FRONG_DEBUG_WARNING("Call to IsWow64Process failed.");

  wow64_ = wow64 != FALSE;

  if (wow64_) {
    // a 32-bit program on a 64-bit machine
    x64_ = false;
  } else {
    // what architecture is this machine?
    SYSTEM_INFO info;
    GetNativeSystemInfo(&info);
    x64_ = (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64);
  }

  // dont "attach" to a 64-bit process from a 32-bit process
  FRONG_ASSERT(sizeof(void*) == 8 || !x64());

  PROCESS_BASIC_INFORMATION info{};

  // for the peb
  if (NT_ERROR(nt::NtQueryInformationProcess(handle_,
      ProcessBasicInformation, &info, sizeof(info), nullptr)))
    FRONG_DEBUG_ERROR("Failed to query basic process information.");

  if constexpr (sizeof(void*) == 8) {
    peb64_address_ = info.PebBaseAddress;

    if (wow64_) {
      // get the 32bit peb as well
      if (NT_ERROR(nt::NtQueryInformationProcess(handle_,
          ProcessWow64Information, &peb32_address_, sizeof(peb32_address_), nullptr)))
        FRONG_DEBUG_ERROR("Failed to query wow64 information.");
    }
  } else {
    peb32_address_ = info.PebBaseAddress;
  }
}

// call callback() for every module loaded
template <size_t PtrSize, typename Callback>
inline void process::iterate_modules(Callback&& callback) const {
  using ldr_data = nt::PEB_LDR_DATA<PtrSize>;
  using ldr_entry = nt::LDR_DATA_TABLE_ENTRY<PtrSize>;
  using list_entry = nt::LIST_ENTRY<PtrSize>;

  // the address of PEB::Ldr::InMemoryOrderModuleList
  auto const list_head = peb<PtrSize>().Ldr +
    offsetof(ldr_data, InMemoryOrderModuleList);

  // first entry
  auto current = read<list_entry>(cast_ptr(list_head)).Flink;

  // iterate over the linked list
  while (current != list_head) {
    // basically just CONTAINING_RECORD(current, ldr_entry, InMemoryOrderLinks)
    auto const entry = read<ldr_entry>(cast_ptr(
      current - offsetof(ldr_entry, InMemoryOrderLinks)));

    // create a std::wstring object big enough to hold the dll name
    std::wstring fullpath(entry.FullDllName.Length / 2, L' ');

    // read the full dll path
    auto const bytes_read = read(
      cast_ptr(entry.FullDllName.Buffer),
      fullpath.data(),
      entry.FullDllName.Length);

    // error reading memory
    if (bytes_read != entry.FullDllName.Length) {
      FRONG_DEBUG_WARNING("Failed to read module's FullDllName.");
      continue;
    }

    // process this module
    if (!callback(std::move(fullpath), cast_ptr(entry.DllBase)))
      break;

    // go to the next node
    current = read<list_entry>(cast_ptr(current)).Flink;
  }
}

// is this an api set schema dll?
inline bool process::is_api_set_schema(std::wstring_view const name) {
  // cmon bruh
  if (name.size() < 4)
    return false;

  return (0 == _wcsnicmp(name.data(), L"api-", 4)) ||
    (0 == _wcsnicmp(name.data(), L"ext-", 4));
}

// resolve an api stub dll to it's real dll
inline std::wstring process::resolve_api_name(std::wstring_view name, std::wstring_view const parent) {
  FRONG_ASSERT(is_api_set_schema(name));

  // remove everything past the last version number
  // e.g. api-ms-win-core-apiquery-l1-1-0.dll -> api-ms-win-core-apiquery-l1-1
  if (auto const end = name.find_last_of(L'-'); end != name.npos)
    name = name.substr(0, end);

  // should be the same for every process
  auto const map = get_api_set_map<sizeof(void*)>();
  FRONG_ASSERT(map->Version == 6);

  auto const entries = (nt::API_SET_NAMESPACE_ENTRY*)(
    (uint8_t*)map + map->EntryOffset);

  for (size_t i = 0; i < map->Count; ++i) {
    auto const& entry = entries[i];

    // cmon bruh
    if (entry.ValueCount <= 0)
      continue;

    // prob not null terminated idfk
    auto const entry_name = (wchar_t*)((uint8_t*)map + entry.NameOffset);
    size_t name_size = entry.NameLength / 2;

    // find the real size
    for (size_t j = 0; j < name_size; ++j) {
      if (entry_name[name_size - j - 1] != L'-')
        continue;

      name_size = name_size - j - 1;
      break;
    }

    // name doesn't match
    if (name.size() != name_size || _wcsnicmp(entry_name, name.data(), name.size()))
      continue;

    auto const values = (nt::API_SET_VALUE_ENTRY*)(
      (uint8_t*)map + entry.ValueOffset);

    // default host
    auto value = &values[0];

    // maybe we don't want the default host
    if (entry.ValueCount > 1 && !parent.empty()) {
      // search for matching parents
      for (size_t j = 1; j < entry.ValueCount; ++j) {
        std::wstring_view const pname((wchar_t const*)((uint8_t*)map + 
          values[j].NameOffset), values[j].NameLength / 2);

        // name doesn't match
        if (pname.size() != parent.size() || _wcsnicmp(
            pname.data(), parent.data(), parent.size()))
          continue;

        value = &values[j];
        break;
      }
    }

    return std::wstring((wchar_t*)((uint8_t*)map +
      value->ValueOffset), value->ValueLength / 2);
  }

  FRONG_DEBUG_WARNING("Failed to resolve api: %.*ws",
    (int)name.size(), name.data());
  return L"";
}

// if constexpr is so fucking shit pls fix
template <size_t PtrSize>
inline nt::API_SET_NAMESPACE* process::get_api_set_map() {
  if constexpr (PtrSize == 8) {
    return (nt::API_SET_NAMESPACE*)((nt::PEB<PtrSize>*)
      __readgsqword(0x60 + PtrSize - PtrSize))->ApiSetMap;
  } else {
    return (nt::API_SET_NAMESPACE*)((nt::PEB<PtrSize>*)
      __readfsdword(0x30 + PtrSize - PtrSize))->ApiSetMap;
  }
}

} // namespace frg