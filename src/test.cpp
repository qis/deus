#include <deus/device.hpp>
#include <deus/utility.hpp>
#include <algorithm>
#include <format>
#include <functional>
#include <vector>
#include <cstdio>
#include <cstdlib>

template <>
struct std::formatter<std::error_code, char> : std::formatter<std::string_view> {
  template <class Context>
  auto format(std::error_code ec, Context& context) const
  {
    const auto c = static_cast<std::uint64_t>(ec.value());
    const auto s = std::format("{} {:08X}: {}", ec.category().name(), c, ec.message());
    return std::formatter<std::string_view>::format({ s.data(), s.size() }, context);
  }
};

int main()
{
  // Find process.
  const auto pids = deus::find_process("notepad.exe");
  if (!pids) {
    std::fputs(std::format("Could not find process.\r\n{}\r\n", pids.error()).data(), stderr);
    return EXIT_FAILURE;
  }
  if (pids.value().empty()) {
    std::fputs("Process not found.\r\n", stderr);
    return EXIT_FAILURE;
  }
  const auto pid = pids.value().front();

  // Open device.
  deus::device device;
  if (const auto ec = device.open()) {
    std::fputs(std::format("Could not open device.\r\n{}\r\n", ec).data(), stderr);
    return EXIT_FAILURE;
  }

  // Query process memory regions.
  const auto regions = device.query(pid);
  if (!regions) {
    std::fputs(std::format("Could not query memory regions.\r\n{}\r\n", regions.error()).data(), stderr);
    return EXIT_FAILURE;
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
  std::size_t scanned = 0;
  std::size_t matches = 0;
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
      const auto ec = deus::make_error_code(GetLastError());
      std::fputs(std::format("0x{:016X}: {}\r\n", region.address, ec).data(), stderr);
      continue;
    }

    // Skip region copies that are too small.
    if (copy->operations[0].copied < size) {
      continue;
    }

    // Scan memory region.
    const auto s = buffer.data();
    const auto e = s + copy->operations[0].copied;
    if (std::search(s, e, searcher) != e) {
      matches++;
    }

    scanned++;
  }

  std::puts(std::format("Found {} matches in {} regions.", matches, scanned).data());
  return EXIT_SUCCESS;
}