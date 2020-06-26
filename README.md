# Frong

![made with c++17](https://img.shields.io/static/v1?label=made+with&message=c%2B%2B17&color=blue&logo=c%2B%2B&logoColor=blue&style=for-the-badge)
![mit license](https://img.shields.io/static/v1?label=license&message=MIT&color=blue&style=for-the-badge)

A ***header-only*** memory library written in modern c++. Currently only supports Windows.

---

## Examples

* Enumerating running processes:

```cpp
// every process
for (auto const pid : frg::pids_from_name("")) {
  // do stuff with the pid...
}

// only processes with the name "Discord.exe"
for (auto const pid : frg::pids_from_name("Discord.exe")) {
  // do stuff with the pid...
}
```

* Creating a new `frg::process` from a process name:

```cpp
// create a frg::process with the name "Discord.exe"
// note: this will return an INVALID process if there are 0
//       or more than 1 processes with a matching name
auto process(frg::process_from_name("Discord.exe"));

// same as above except this will use the first found process
// if more than 1 processes have a matching name
process = frg::process_from_name("Discord.exe", true);
```

* Alternatively, using your own process handle:

```cpp
if (auto const handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 4)) {
  frg::process const process(handle);
  // do stuff with process...
}
```

* Getting modules:

```cpp
// you can get a single module
if (auto const module = process.module(L"ntdll.dll")) {
  // do stuff with module->base and module->path...
}

// or you can get every module
for (auto const& [path, base] : process.modules()) {
  // do stuff with path and base...
}

// you can use any container that has an inserter (std::deque, std::list, etc)
std::vector<frg::module> modules;  
process.modules(back_inserter(modules));
```

* Searching memory:

```cpp
// search for the specified pattern in the module "Discord.exe"
auto results = memscan(process,
  frg::pattern("E8 ? ? ? ? E9 ? ? ? ? 8B 0D ? ? ? ? 56"), L"Discord.exe");

// search for a specific value
results = memscan(process, frg::simple_compare(69), L"ntdll.dll");

for (auto const address : results) {
  // do stuff...
}
```

* User-defined compare when searching memory:

```cpp
struct {
  bool operator()(void* const address, void* const buffer, size_t const size) const {
    // make sure the address is aligned properly
    if ((uintptr_t)address & (alignof(uint64_t) - 1))
      return false;

    // make sure we have enough space
    if (size < sizeof(uint64_t))
      return false;

    auto const value = *(uint64_t*)buffer;
    return value >= 100 && value <= 150 && value % 13 == 0;
  }
} custom_compare;

// this returns any addresses that point to an uin64_t that has a value
// in the range [100, 150] and is a multiple of 13
auto const results = memscan(process, custom_compare, L"Discord.exe");
```
