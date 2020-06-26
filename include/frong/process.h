#pragma once

#include "debug.h"
#include "nt.h"

#include <cstdint>
#include <utility>
#include <vector>
#include <string>
#include <string_view>
#include <optional>

// for WTS* functions
#include <WtsApi32.h>
#pragma comment(lib, "Wtsapi32.lib")


namespace frg {

using module_base = void*;

// represents a module loaded in memory
struct module {
  // full path to the DLL
  std::wstring path;

  // base address of the image in memory
  module_base base = nullptr;
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

  // get the address of the peb
  template <size_t PtrSize>
  void* peb_addr() const noexcept;

  // read the peb
  template <size_t PtrSize>
  auto peb() const;

  // get a single module
  template <size_t PtrSize>
  std::optional<frg::module> module(std::wstring_view name) const;

  // calls module() with PtrSize set to 4 if x86() or 8 if x64()
  std::optional<frg::module> module(std::wstring_view name) const;

  // get a list of loaded modules
  template <size_t PtrSize, typename OutIt>
  size_t modules(OutIt dest) const;

  // calls modules() with PtrSize set to 4 if x86() or 8 if x64()
  template <typename OutIt>
  size_t modules(OutIt dest) const;

  // returns an std::vector of loaded modules
  template <size_t PtrSize>
  std::vector<frg::module> modules() const;

  // calls modules() with PtrSize set to 4 if x86() or 8 if x64()
  std::vector<frg::module> modules() const;

  // read/write memory (returns the number of bytes read/written)
  size_t read(void const* address, void* buffer, size_t size) const;
  size_t write(void* address, void const* buffer, size_t size) const;

  // wrapper for read()
  template <typename T>
  T read(void const* address, size_t* bytes_read = nullptr) const;

  // wrapper for write()
  template <typename T>
  size_t write(void* address, T const& value) const;

private:
  // *****
  // WARNING: any new instance variable must also be added in the move 
  //          assignment operator or else bad things will happen!
  // *****

  HANDLE handle_ = nullptr;

  // the process id
  uint32_t pid_ = 0;

  // address of the native peb 
  // eg. 64bit peb if called from a 64bit process
  //     32bit peb if called from a 32bit process
  void* peb_address_ = nullptr;

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
};

// get the pids that have the target process name
template <typename OutIt>
size_t pids_from_name(std::string_view name, OutIt dest);

// returns a vector of pids
std::vector<uint32_t> pids_from_name(std::string_view name);

// get a process with it's name
// note: an invalid process will be returned if 0 or more
//       than 1 processes are found with a matching name
// if force is true, it will return the first process found
// when multiple processes match the provided name
process process_from_name(std::string_view name, bool force = false);


//
//
// implementation below
//
//


// get the pids that have the target process name
template <typename OutIt>
inline size_t pids_from_name(std::string_view const name, OutIt dest) {
  DWORD count = 0;
  PWTS_PROCESS_INFOA processes = nullptr;

  // query every active process
  if (!WTSEnumerateProcessesA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &processes, &count)) {
    FRONG_DEBUG_ERROR("Call to WTSEnumerateProcessesA failed.");
    return 0;
  }

  // number of matching processes
  size_t matching = 0;

  for (size_t i = 0; i < count; ++i) {
    // names dont match, continue!
    if (0 != strncmp(processes[i].pProcessName, name.data(), name.size()))
      continue;

    (matching++, dest++) = processes[i].ProcessId;
  }

  WTSFreeMemory(processes);
  return matching;
}

// returns a vector of pids
inline std::vector<uint32_t> pids_from_name(std::string_view const name) {
  std::vector<uint32_t> pids;
  pids_from_name(name, back_inserter(pids));
  return pids;
}

// get a process with it's name
// note: an invalid process will be returned if 0 or more
//       than 1 processes are found with a matching name
// if force is true, it will return the first process found
// when multiple processes match the provided name
inline process process_from_name(std::string_view const name, bool const force) {
  auto const pids = pids_from_name(name);
  
  // process not found
  if (pids.empty()) {
    FRONG_DEBUG_WARNING("No processes found with the name \"%.*s\"", 
      (int)name.size(), name.data());
    return {};
  }

  // nore than one matching process found
  if (pids.size() > 1 && !force) {
    FRONG_DEBUG_WARNING("Multiple processes found with the name \"%.*s\"",
      (int)name.size(), name.data());
    return {};
  }

  return process(pids.front());
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
    PROCESS_QUERY_LIMITED_INFORMATION;

  if (handle_ = OpenProcess(access, FALSE, pid)) {
    close_handle_ = true;
    initialize();
  } else
    FRONG_DEBUG_ERROR("Failed to open process with pid %u", pid);
}

// we cant copy but we can move
inline process::process(process&& other) noexcept {
  *this = std::forward<process>(other);
}
inline process& process::operator=(process&& other) noexcept {
  // we can just swap all our instance variables since other's destructor
  // will cleanup our (old) process instance for us :)
  std::swap(handle_,       other.handle_);
  std::swap(pid_,          other.pid_);
  std::swap(peb_address_,  other.peb_address_);
  std::swap(close_handle_, other.close_handle_);
  std::swap(x64_,          other.x64_);
  std::swap(wow64_,        other.wow64_);

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
  FRONG_ASSERT(valid());
  return !x64_;
}
inline bool process::x64() const noexcept {
  FRONG_ASSERT(valid());
  return x64_;
}

// is this process running under wow64?
inline bool process::wow64() const noexcept {
  FRONG_ASSERT(valid());
  return wow64_;
}

// return the underlying handle
inline HANDLE process::handle() const noexcept {
  FRONG_ASSERT(valid());
  return handle_; 
}

// get the process's pid
inline uint32_t process::pid() const noexcept {
  FRONG_ASSERT(valid());
  return pid_;
}

// get the address of the peb
template <size_t PtrSize>
inline void* process::peb_addr() const noexcept {
  FRONG_ASSERT(PtrSize == 4 || PtrSize == 8);

  // peb_address_ is 64bit
  if constexpr (sizeof(void*) == 8) {
    if constexpr (PtrSize == 8)
      return peb_address_;
    else {
      // only a wow64 process will have a 32bit peb
      FRONG_ASSERT(wow64());
      return (uint8_t*)peb_address_ + 0x1000;
    }
  } 
  // peb_address_ is 32bit
  else {
    // currently doesn't support getting the 64bit peb from a 32bit process
    FRONG_ASSERT(PtrSize == 4);
    return peb_address_;
  }
}

// read the peb
template <size_t PtrSize>
inline auto process::peb() const {
  return read<nt::PEB<PtrSize>>(peb_addr<PtrSize>());
}

// get a single module
template <size_t PtrSize>
inline std::optional<frg::module> process::module(std::wstring_view const name) const {
  // bruh -_-
  if (name.empty())
    return {};

  struct {
    std::wstring_view const name;
    std::optional<frg::module> found;

    // search for a matching module
    bool operator()(frg::module&& m) {
      // not big enough
      if (m.path.size() < name.size())
        return true;

      // cut off the beginning part
      auto const n = m.path.c_str() + (m.path.size() - name.size());

      // does the name match?
      if (0 == _wcsnicmp(n, name.data(), name.size())) {
        found = m;
        return false;
      }

      return true;
    }
  } callback{ name };

  iterate_modules<PtrSize>(callback);
  return callback.found;
}

// calls module() with PtrSize set to 4 if x86() or 8 if x64()
inline std::optional<frg::module> process::module(std::wstring_view const name) const {
  return x64() ? module<8>(name) : module<4>(name);
}

// get a list of loaded modules
template <size_t PtrSize, typename OutIt>
inline size_t process::modules(OutIt dest) const {
  struct {
    OutIt dest;
    size_t count;

    // add every module
    bool operator()(frg::module&& m) {
      (count++, dest++) = m;
      return true;
    }
  } callback{ dest, 0 };

  // iterate over every module and add it to the list
  iterate_modules<PtrSize>(callback);

  return callback.count;
}

// calls modules() with PtrSize set to 4 if x86() or 8 if x64()
template <typename OutIt>
inline size_t process::modules(OutIt dest) const {
  return x64() ? modules<8>(dest) : modules<4>(dest);
}

// returns an std::vector of loaded modules
template <size_t PtrSize>
inline std::vector<frg::module> process::modules() const {
  std::vector<frg::module> m;
  modules(back_inserter(m));
  return m;
}

// calls modules() with PtrSize set to 4 if x86() or 8 if x64()
inline std::vector<frg::module> process::modules() const {
  return x64() ? modules<8>() : modules<4>();
}

// read/write memory (returns the number of bytes read/written)
inline size_t process::read(void const* const address, void* const buffer, size_t const size) const {
  FRONG_ASSERT(valid());
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
inline size_t process::write(void* const address, void const* const buffer, size_t const size) const {
  FRONG_ASSERT(valid());
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
inline size_t process::write(void* address, T const& value) const {
  return write(address, &value, sizeof(value));
}

// cache some stuff
inline void process::initialize() {
  FRONG_ASSERT(valid());
  FRONG_ASSERT(sizeof(void*) == 8 || !x64());

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

  PROCESS_BASIC_INFORMATION info{};

  // get the address of the process's peb
  if (NT_SUCCESS(nt::NtQueryInformationProcess(handle_,
      ProcessBasicInformation, &info, sizeof(info), nullptr)))
    peb_address_ = info.PebBaseAddress;
  else
    FRONG_DEBUG_WARNING("Failed to query basic process information.");
}

// call callback() for every module loaded
template <size_t PtrSize, typename Callback>
inline void process::iterate_modules(Callback&& callback) const {
  FRONG_ASSERT(valid());

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
    if (!callback(frg::module{
        std::move(fullpath),
        cast_ptr(entry.DllBase) }))
      break;

    // go to the next node
    current = read<list_entry>(cast_ptr(current)).Flink;
  }
}

} // namespace frg