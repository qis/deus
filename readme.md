# DEUS
Windows 10 KMDF driver for memory manipulation.

```cpp
#include <deus.hpp>
#include <format>
#include <iostream>
#include <cstdlib>

int main(int argc, char* argv[])
{
  try {
    // Create test data.
    const std::vector<unsigned char> data{
      0x00, 0xDE, 0x01, 0xBE, 0x0EF, 0x00, 0x00, 0x42, 0x00,
    };

    // Create device.
    deus::device device;
    if (const auto rv = device.create(); !rv) {
      throw std::system_error(rv.error(), "create");
    }

    // Open process.
    if (const auto rv = device.open(GetCurrentProcessId()); !rv) {
      throw std::system_error(rv.error(), "open");
    }

    // Query process memory regions.
    const auto regions = device.query();
    if (!regions) {
      throw std::system_error(regions.error(), "query");
    }

    // Scan process memory regions for signature.
    const deus::signature signature("DE ?? BE EF 00");
    for (auto& region : *regions) {
      const auto begin = region.base_address;
      const auto end = region.base_address + region.region_size;
      const auto scan = device.scan(begin, end, signature, [&](UINT_PTR address) {
        // Copy process memory to application memory.
        unsigned char value = 0;
        const auto read = device.read(address + 6, &value, sizeof(value));
        if (!read) {
          throw std::system_error(read.error(), "read");
        }
        std::cout << "read: " << std::format("0x{:02X}", value) << std::endl;
        return true;
      });
      if (!scan) {
        throw std::system_error(scan.error(), "scan");
      }
    }
  }
  catch (const std::system_error& e) {
    std::cerr << e.code().category().name() << ' ' << e.what() << std::endl;
    return EXIT_FAILURE;
  }
  catch (const std::exception& e) {
    std::cerr << e.what() << std::endl;
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
```

## Build
1. Install [Windows 11 WDK][wdk].
2. Clone this repository to `C:\Workspace\deus`.

```cmd
git clone git@github.com:qis/deus C:/Workspace/deus
cd C:\Workspace\deus
git submodule update --init --depth 1
```

3. Build project in `x64 Native Tools Command Prompt for VS 2022`.

```cmd
cd C:\Workspace\deus
cmake -B build --preset release
cmake --build build --target install
```

<details>
<summary><b>Debugging</b></summary>

Install [SandboxBootkit][sandbox] and run `sandbox.wsb`.

<!--
cd C:\Program Files (x86)\Windows Kits\10\Debuggers\x64
CmDiag DevelopmentMode -On
CmDiag Debug -On -Net
windbg.exe -k net:port=50100,key=cl.ea.rt.ext,target=127.0.0.1 -v
C:\Workspace\deus\sandbox.wsb
-->

```cmd
rem Start driver.
sc start deus

rem Run tests.
C:\Workspace\deus\build\debug\deus.exe

rem Stop driver.
sc stop deus

rem Query driver.
sc query deus
```

</details>

## Install
1. Boot system using [EfiGuard][efiguard].
2. Run `deus.exe` to install and load the driver.

[wdk]: https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
[sandbox]: https://github.com/thesecretclub/SandboxBootkit
[efiguard]: https://github.com/Mattiwatti/EfiGuard
