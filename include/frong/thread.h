#pragma once

#include "debug.h"
#include "nt.h"


namespace frg {

enum class hwbp_type {
  execute   = 0b00,
  write     = 0b01,
  readwrite = 0b11
};

enum class hwbp_size {
  one   = 0b00,
  two   = 0b01,
  four  = 0b11,
  eight = 0b10
};

// represents a running thread
class thread {
public:
  thread() = default;

  // use an existing thread handle
  thread(HANDLE handle);

  // opens a handle to the thread
  explicit thread(uint32_t tid);

  // we cant copy but we can move
  thread(thread&& other) noexcept;
  thread& operator=(thread&& other) noexcept;

  // close our handle if we were the one that opened it
  ~thread();

  // is this process class initialized?
  bool valid() const noexcept;
  explicit operator bool() const noexcept;

  // get the underlying handle
  HANDLE handle() const noexcept;

  // get the thread id
  uint32_t tid() const noexcept;

  // this is where the thread started execution at
  void* start_address() const;

  // enable or disable a debug breakpoint on the specified address
  bool hwbp(void const* address, bool enable, hwbp_type type = 
    hwbp_type::execute, hwbp_size size = hwbp_size::one) const;

private:
  // *****
  // WARNING: any new instance variable must also be added in the move 
  //          assignment operator or else bad things will happen!
  // *****

  HANDLE handle_ = nullptr;

  // did we create this handle?
  bool close_handle_ = false;

  // the thread id
  uint32_t tid_ = 0;

private:
  // no copying -_-
  thread(thread const&) = delete;
  thread& operator=(thread const&) = delete;
};


//
//
// implementation below
//
//


// use an existing thread handle
inline thread::thread(HANDLE const handle)
  : handle_(handle), close_handle_(false), tid_(GetThreadId(handle)) {}

// open a handle to the thread
inline thread::thread(uint32_t const tid)
  : close_handle_(true), tid_(tid) {
  static auto constexpr access = THREAD_ALL_ACCESS;

  handle_ = OpenThread(access, FALSE, tid);

  if (!handle_) {
    FRONG_DEBUG_ERROR("Failed to open thread with tid %u", tid);
    return;
  }
}

// we cant copy but we can move
inline thread::thread(thread&& other) noexcept {
  *this = std::forward<thread>(other);
}
inline thread& thread::operator=(thread&& other) noexcept {
  // we can just swap all our instance variables since other's destructor
  // will cleanup our (old) thread instance for us :)
  std::swap(handle_, other.handle_);
  std::swap(close_handle_, other.close_handle_);
  std::swap(tid_, other.tid_);

  return *this;
}

// close our handle if we were the one that opened it
inline thread::~thread() {
  if (valid() && close_handle_)
    CloseHandle(handle_);
}

// is this process class initialized?
inline bool thread::valid() const noexcept {
  return handle_ != nullptr;
}
inline thread::operator bool() const noexcept {
  return valid();
}

// get the underlying handle
inline HANDLE thread::handle() const noexcept {
  return handle_;
}

// get the thread id
inline uint32_t thread::tid() const noexcept {
  return tid_;
}

// this is where the thread started execution at
inline void* thread::start_address() const {
  void* address = nullptr;

  // query the address
  auto const status = nt::NtQueryInformationThread(handle_, 
    nt::ThreadQuerySetWin32StartAddress, &address, sizeof(address), nullptr);

  if (NT_ERROR(status)) {
    FRONG_DEBUG_WARNING("Failed to query thread's start address.");
    return nullptr;
  }

  return address;
}

// enable or disable a debug breakpoint on the specified address
inline bool thread::hwbp(void const* const address, bool const enable, 
    hwbp_type const type, hwbp_size const size) const {

  CONTEXT ctx{};
  ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

  // get the current values of Dr0-Dr7
  if (!GetThreadContext(handle_, &ctx)) {
    FRONG_DEBUG_ERROR("Failed to get thread context.");
    return false;
  }

  bool success = false;

  if (enable) {
    for (size_t i = 0; i < 4; ++i) {
      // is this bp already being used
      if (ctx.Dr7 & (size_t(1) << (i * 2)))
        continue;

      // set the address
      (&ctx.Dr0)[i] = (uintptr_t)address;

      // enable the dr7 flag
      ctx.Dr7 |= size_t(1) << (i * 2);

      // specify the breakpoint size and when should it trigger
      const auto type_size_mask((size_t(size) << 2) | size_t(type));
      ctx.Dr7 &= ~(0b1111 << (16 + i * 4)); // clear old value
      ctx.Dr7 |= type_size_mask << (16 + i * 4);

      success = true;
    }
  } else {
    for (size_t i = 0; i < 4; ++i) {
      // matching address?
      if (cast_ptr((&ctx.Dr0)[i]) != address)
        continue;

      // clear the debug register
      (&ctx.Dr0)[i] = 0;
      
      // disable the dr7 flag
      ctx.Dr7 &= ~(1 << (i * 2));

      // clear out the size/type as well cuz we're nice people
      ctx.Dr7 &= ~(0b1111 << (16 + i * 4));

      success = true;
    }
  }

  // set the new debug register values
  if (!SetThreadContext(handle_, &ctx)) {
    FRONG_DEBUG_ERROR("Failed to set thread context.");
    return false;
  }

  return success;
}

} // namespace frg