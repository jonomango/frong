#pragma once

#include "debug.h"

#include <Windows.h>
#include <cstdint>
#include <utility>


namespace frg {

// wrapper over a process handle
class process {
public:
  process() = default;

  // this is explicitly not explicit:
  // we want to be able to pass a HANDLE where a process is expected
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

// this is explicitly not explicit:
// we want to be able to pass a HANDLE where a process is expected
process::process(HANDLE const handle) noexcept
  : handle_(handle), close_handle_(false) {
  initialize();
}

// opens a handle to a process
process::process(uint32_t const pid) {
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
process::process(process&& other) noexcept {
  *this = std::forward<process>(other);
}
process& process::operator=(process&& other) noexcept {
  handle_ = other.handle_;
  close_handle_ = other.close_handle_;

  // make sure the temporary's destructor doesn't do any bad poop
  other.handle_ = nullptr;
  other.close_handle_ = false;

  return *this;
}

// close our handle if we were the one that opened it
process::~process() {
  if (valid() && close_handle_)
    CloseHandle(handle_);
}

// is this process class initialized?
bool process::valid() const noexcept { 
  return handle_ != nullptr; 
}
process::operator bool() const noexcept { 
  return valid(); 
}

// 32 or 64 bit code
bool process::x86() const noexcept {
  FRONG_ASSERT(valid());
  return !x64_;
}
bool process::x64() const noexcept {
  FRONG_ASSERT(valid());
  return x64_;
}

// is this process running under wow64?
bool process::wow64() const noexcept {
  FRONG_ASSERT(valid());
  return wow64_;
}

// return the underlying handle
HANDLE process::handle() const noexcept { 
  FRONG_ASSERT(valid());
  return handle_; 
}

// get the process's pid
uint32_t process::pid() const noexcept {
  FRONG_ASSERT(valid());
  return pid_;
}

// get a list of loaded modules
template <typename OutIt>
size_t process::modules(OutIt dest) const {
  FRONG_ASSERT(valid());

  // TODO: actually implement lol

  return 0;
}

// read/write memory (returns the number of bytes read/written)
size_t process::read(void const* const address, void* const buffer, size_t const size) const {
  FRONG_ASSERT(valid());
  FRONG_ASSERT(size > 0);
  FRONG_ASSERT(buffer != nullptr);
  FRONG_ASSERT(address != nullptr);

  SIZE_T bytes_read = 0;
  if (!ReadProcessMemory(handle_, address, buffer, size, &bytes_read)) {
    FRONG_DEBUG_ERROR("Failed to read memory at address %p", address);
    return 0;
  }

  return bytes_read;
}
size_t process::write(void* const address, void const* const buffer, size_t const size) const {
  FRONG_ASSERT(valid());
  FRONG_ASSERT(size > 0);
  FRONG_ASSERT(buffer != nullptr);
  FRONG_ASSERT(address != nullptr);

  SIZE_T bytes_written = 0;
  if (!WriteProcessMemory(handle_, address, buffer, size, &bytes_written)) {
    FRONG_DEBUG_ERROR("Failed to write memory at address %p", address);
    return 0;
  }

  return bytes_written;
}

// cache some stuff
void process::initialize() {
  FRONG_ASSERT(valid());

  pid_ = GetProcessId(handle_);

  // is this process running under wow64?
  BOOL wow64 = FALSE;
  if (!IsWow64Process(handle_, &wow64))
    FRONG_DEBUG_WARNING("Call to IsWow64Process failed");

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