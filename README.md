# Frong

![made with c++17](https://img.shields.io/static/v1?label=made+with&message=c%2B%2B17&color=blue&logo=c%2B%2B&logoColor=blue&style=for-the-badge)
![mit license](https://img.shields.io/static/v1?label=license&message=MIT&color=blue&style=for-the-badge)

A ***header-only*** memory library written in ***modern c++***. Currently only supports Windows.

---

### Example usage:

```cpp
// #define FRONG_DEBUG
#include <frong.h>

int main() {
  // print every pid that matches with Discord.exe
  for (auto const pid : frg::pids_from_name("Discord.exe"))
    printf("PID: %u\n", pid);

  // get the first Discord.exe process
  auto const process(frg::process_from_name("Discord.exe", true));
  if (!process) {
    // uh oh, Discord.exe not running
    return 0;
  }

  printf("Discord.exe (pid=%u) is a %s-bit process.\n", 
    process.pid(), process.x64() ? "64" : "32");

  // print every module that discord has loaded
  for (auto const& [path, base] : process.modules())
    printf("0x%p - %S\n", base, path.c_str());
}
```
