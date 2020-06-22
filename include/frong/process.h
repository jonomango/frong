#pragma once

#include "debug.h"

#include <Windows.h>
#include <cstdint>
#include <utility>
#include <vector>
#include <string_view>

// for WTS* functions
#include <WtsApi32.h>
#pragma comment(lib, "Wtsapi32.lib")


namespace frg {

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

  // get a list of loaded modules
  template <typename OutIt>
  size_t modules(OutIt dest) const;

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
  HANDLE handle_ = nullptr;

  // the process id
  uint32_t pid_ = 0;

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
};

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

// get a process with it's name
// note: an invalid process will be returned if 0 or more
//       than 1 processes are found with a matching name
// if force is true, it will return the first process found
// when multiple processes match the provided name
inline process process_from_name(std::string_view const name, bool const force = false) {
  std::vector<uint32_t> pids;
  auto const count = pids_from_name(name, back_inserter(pids));
  
  // process not found
  if (!count) {
    FRONG_DEBUG_WARNING("No processes found with the name \"%.*s\"", 
      (int)name.size(), name.data());
    return {};
  }

  // nore than one matching process found
  if (count > 1 && !force) {
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

// get a list of loaded modules
template <typename OutIt>
inline size_t process::modules(OutIt dest) const {
  FRONG_ASSERT(valid());

  // TODO: actually implement lol

  return 0;
}

// read/write memory (returns the number of bytes read/written)
inline size_t process::read(void const* const address, void* const buffer, size_t const size) const {
  FRONG_ASSERT(valid());
  FRONG_ASSERT(size > 0);
  FRONG_ASSERT(buffer != nullptr);
  FRONG_ASSERT(address != nullptr);

  SIZE_T bytes_read = 0;
  if (!ReadProcessMemory(handle_, address, buffer, size, &bytes_read)) {
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
  if (!WriteProcessMemory(handle_, address, buffer, size, &bytes_written)) {
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
}

} // namespace frg