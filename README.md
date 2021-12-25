# Frong

![made with c++17](https://img.shields.io/static/v1?label=made+with&message=c%2B%2B17&color=blue&logo=c%2B%2B&logoColor=blue&style=for-the-badge)
![mit license](https://img.shields.io/static/v1?label=license&message=MIT&color=blue&style=for-the-badge)

A ***header-only*** memory library written in modern c++. Only supports Windows.

---

## Example Usage:

```cpp
// print the pid of every process with the name "Discord.exe"
for (auto const pid : frg::pids_from_name(L"Discord.exe"))
  printf("%u\n", pid);

frg::process const process(L"Discord.exe", true);
if (!process)
  return 0;

// allocate 4 bytes of read/write virtual memory
auto const address = process.allocate(4);

// write to the newly allocated memory
assert(4 == process.write(address, 69));

// prints "69"
printf("%i\n", process.read<int>(address));

// print the base address and path of every loaded module
for (auto const& [path, m] : process.modules())
  printf("0x%p %S\n", m.base(), path.c_str());

// print the id and start address of every thread in the process
for (auto const& t : process.threads())
  printf("%u 0x%p\n", t.tid(), t.start_address());

// print the value and access of every handle in the process
for (auto const& h : process.handles())
  printf("0x%p 0x%X\n", h.handle, h.access);

// search for the specified pattern in the module "kernel32.dll"
auto const results = frg::memscan(process,
  frg::pattern("AA ? ? BB CC"), L"kernel32.dll");

// get the address of an exported routine
auto const load_library_a = process.get_proc_addr(L"kernel32.dll", "LoadLibraryA");
printf("LoadLibraryA: 0x%p\n", load_library_a);

// get the address of the process's native PEB (on x64 machines)
printf("PEB64: 0x%p\n", process.peb_addr<8>());

// get the address of the process's WOW64 PEB (on x64 machines)
printf("PEB32: 0x%p\n", process.peb_addr<4>());

// get the address of the process's kernel EPROCESS structure
printf("EPROCESS: 0x%p\n", process.eprocess());
```

## Custom Memory Functions

It is possible to override virtual methods in `frg::process` for manipulating 
memory if `FRONG_VIRTUAL_PROCESS` is defined before including `frong.h`.
Specifically, the following methods:

```cpp
// read from memory and return the number of bytes read
size_t read(void const* address, void* buffer, size_t size) const;

// write to memory and return the number of bytes written
size_t write(void* address, void const* buffer, size_t size) const;

// allocate memory in the process
void* allocate(size_t size, uint32_t protection) const;

// free memory returned from allocate()
void free(void* address) const;
```

## Example Usage:
```cpp
#define FRONG_VIRTUAL_PROCESS
#include <frong.h>

class custom_process : public frg::process {
public:
  // this lets us inherit every base constructor
  using frg::process::process;

  // this unhides the overloaded read() function (that isn't virtual)
  using frg::process::read;

  // override the read() function to use our own method
  virtual size_t read(void const* address, void* buffer, size_t size) const override {
    // custom implementation here...
  }
};
```
