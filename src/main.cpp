#include <deus.hpp>
#include <format>
#include <iostream>
#include <cstdlib>

#include <process.h>

int main(int argc, char* argv[])
{
  system("sc start deus");
  std::atexit([]() noexcept {
    system("sc stop deus");
  });
  std::puts("");
  try {
    // Create test data.
    const std::vector<unsigned char> data{
      0x00, 0xDE, 0x01, 0xBE, 0x0EF, 0x00, 0x00, 0x42, 0x00,
    };

    // Create test signature.
    const deus::signature signature("DE ?? BE EF 00");

    // Scan for signature in test data.
    signature.scan(data.data(), data.data() + data.size(), [](const void* data) noexcept {
      const auto value = reinterpret_cast<const unsigned char*>(data) + 6;
      std::cout << "scan: " << std::format("0x{:02X}", *value) << std::endl;
      return true;
    });

    // Create device.
    deus::device device;
    if (const auto rv = device.create(); !rv) {
      throw std::system_error(rv.error(), "create");
    }

    // Open process.
    if (const auto rv = device.open(GetCurrentProcessId()); !rv) {
      throw std::system_error(rv.error(), "open");
    }

    // Query regions.
    const auto regions = device.query();
    if (!regions) {
      throw std::system_error(regions.error(), "query");
    }

    // Scan for signature in process memory.
    for (auto& region : *regions) {
      const auto begin = region.base_address;
      const auto end = region.base_address + region.region_size;
      const auto scan = device.scan(begin, end, signature, [&](UINT_PTR address) {
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