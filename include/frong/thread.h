#pragma once

#include "debug.h"
#include "nt.h"


namespace frg {

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

  // get the thread id
  uint32_t tid() const noexcept;

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

// get the thread id
inline uint32_t thread::tid() const noexcept {
  return tid_;
}

} // namespace frg