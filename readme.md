# DEUS
Windows 10 KMDF driver for memory and HID manipulation.

```cpp
// Find process.
const auto pids = deus::find_process("notepad.exe");
if (!pids || pids.value().empty()) {
  return;
}
const auto pid = pids.value().front();

// Open device.
deus::device device;
if (const auto ec = device.open()) {
  return;
}

// Query process memory regions.
const auto regions = device.query(pid);
if (!regions) {
  return;
}

// Prepare scan searcher.
const auto text = L"Lorem ipsum dolor sit amet.";
const auto data = reinterpret_cast<const char*>(text);
const auto size = sizeof(wchar_t) * 27;
const auto searcher = std::boyer_moore_horspool_searcher(data, data + size);

// Prepare copy operations.
std::vector<char> buffer;
auto copy = deus::create_copy(pid, 1);

// Copy and scan memory regions.
for (const auto& region : regions.value()) {
  // Skip non-committed, non-accessible and guarded regions.
  if (region.state != MEM_COMMIT || (region.protect & (PAGE_NOACCESS | PAGE_GUARD))) {
    continue;
  }

  // Skip regions that are too small.
  if (region.size < size) {
    continue;
  }

  // Match known state, protect and type values.
  if (region.state != 0x1000 || region.protect != 0x4 || region.type != 0x20000) {
    continue;
  }

  // Copy memory region.
  if (buffer.size() < region.size) {
    buffer.resize(region.size);
  }
  copy->operations[0].src = region.address;
  copy->operations[0].dst = reinterpret_cast<UINT_PTR>(buffer.data());
  copy->operations[0].bytes = region.size;
  if (!device.copy(copy.get())) {
    continue;
  }

  // Skip region copies that are too small.
  if (copy->operations[0].copied < size) {
    continue;
  }

  // Scan memory region.
  const auto s = buffer.data();
  const auto e = s + copy->operations[0].copied;
  if (const auto i = std::search(s, e, searcher); i != e) {
    const auto match = region.address + static_cast<UINT_PTR>(i - s);
    std::cout << "match: " << match << std::endl;
  }
}
```

See [src/test.cpp](src/test.cpp) for a more detailed example.

## Requirements
1. Install [Visual Studio][vsc].
2. Install [Windows 11 WDK][wdk].
3. Open [solution.sln](solution.sln) and build the `deus` project.
4. View kernel debug messages with [DebugView][dbg].
5. Load the driver with [KDU][kdu] as administrator.

```cmd
kdu -map deus.sys
```

**WARNING**: Loading the driver multiple times should work, but causes blue screens for now.

6. Add DEUS to your CMake project.

```cmake
list(APPEND CMAKE_PREFIX_PATH path/to/deus/cmake)
find_package(deus REQUIRED)
target_link_libraries(main PRIVATE deus::deus)
```

7. Add DEUS to your VS project.
  - Add `%PATH_TO_DEUS%/include` to include directories.
  - Add `UMDF_USING_NTSTATUS` to definitions.
  - Add `/std:c++latest` to compiler option.
  - Add `ntdll.lib` to link libraries.

[vsc]: https://visualstudio.microsoft.com/vs/community/
[wdk]: https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
[dbg]: https://learn.microsoft.com/en-us/sysinternals/downloads/debugview
[kdu]: https://github.com/hfiref0x/KDU
