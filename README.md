# Frong

![made with c++17](https://img.shields.io/static/v1?label=made+with&message=c%2B%2B17&color=blue&logo=c%2B%2B&logoColor=blue&style=for-the-badge)
![mit license](https://img.shields.io/static/v1?label=license&message=MIT&color=blue&style=for-the-badge)

A ***header-only*** memory library written in modern c++. Only supports Windows.

---

## Example usage

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

// prints out "69"
printf("%i\n", process.read<int>(address));

// print the base address and path of every loaded module
for (auto const& [path, m] : process.modules())
  printf("%p %S\n", m.base(), path.c_str());

// print the thread id and start address of every thread in the process
for (auto const& t : process.threads())
  printf("%u %p\n", t.tid(), t.start_address());

// search for the specified pattern in the module "kernel32.dll"
auto const results = frg::memscan(process,
  frg::pattern("AA ? ? BB CC"), L"kernel32.dll");

// get the address of an exported routine
auto const load_library_a = process.get_proc_addr(L"kernel32.dll", "LoadLibraryA");
printf("LoadLibraryA: %p\n", load_library_a);

// get the address of the process's native PEB (on x64 machines)
printf("PEB64: %p\n", process.peb_addr<8>());

// get the address of the process's WOW64 PEB (on x64 machines)
printf("PEB32: %p\n", process.peb_addr<4>());

// get the address of the process's kernel EPROCESS structure
printf("EPROCESS: %p\n", process.eprocess());
```
