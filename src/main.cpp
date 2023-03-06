#include <deus.hpp>
#include <chrono>
#include <format>
#include <system_error>
#include <cstdio>
#include <cstdlib>

int print_error(const std::exception& e) noexcept
{
  std::fputs(e.what(), stderr);
  std::fputs("\r\n", stderr);
  std::fflush(stderr);
  return EXIT_FAILURE;
}

int print_error(const std::system_error& e)
{
  std::fputs(e.code().category().name(), stderr);
  std::fputs(" ", stderr);
  return print_error(static_cast<const std::exception&>(e));
}

#include <process.h>

int main(int argc, char* argv[])
{
  if (!system("sc start deus")) {
    std::atexit([]() noexcept {
      system("sc stop deus");
    });
  }
  std::puts("");
  try {
    using clock = std::chrono::high_resolution_clock;
    using milliseconds = std::chrono::duration<double, std::chrono::milliseconds::period>;
    using std::chrono::duration_cast;

    std::vector<std::uint64_t> data;
    data.push_back(0xDEADBEEFDEADBEEF);
    data.push_back(0);
    data.push_back(0);

    deus::device device;
    if (const auto rv = device.create(); !rv) {
      throw std::system_error(rv.error(), "create");
    }

    if (const auto rv = device.open(GetCurrentProcessId()); !rv) {
      throw std::system_error(rv.error(), "open");
    }

    const auto tp0 = clock::now();
    const auto regions = device.query();
    if (!regions) {
      throw std::system_error(regions.error(), "query");
    } else {
      const auto ms = duration_cast<milliseconds>(clock::now() - tp0).count();
      std::puts(std::format("deus query: {} regions in {:.03f} ms", regions->size(), ms).data());
    }

    std::size_t size = 0;
    for (auto& region : *regions) {
      size += region.region_size;
    }
    std::puts(std::format("deus query: {:.03f} MiB", size / 1024.0 / 1024.0).data());

    std::puts(std::format("0: {:016X}", data[0]).data());
    std::puts(std::format("1: {:016X}", data[1]).data());
    std::puts(std::format("2: {:016X}", data[2]).data());

    const auto tp1 = clock::now();
    UINT_PTR address = deus::npos;
    const deus::signature signature("DE??BEEF");
    for (auto& region : *regions) {
      if (const auto rv = device.scan(region.base_address, region.region_size, signature); rv && *rv != deus::npos) {
        address = *rv;
        break;
      } else if (!rv && rv.error().value() != 0x490) {
        throw std::system_error(rv.error(), "find");
      }
    }
    const auto ms = duration_cast<milliseconds>(clock::now() - tp1).count();
    std::puts(std::format("deus find: {:016X}", reinterpret_cast<UINT_PTR>(&data[0])).data());
    std::puts(std::format("deus find: {:016X} in {:.03f} ms", address, ms).data());

    UINT_PTR src = 0;
    UINT_PTR dst = 0;

    src = reinterpret_cast<UINT_PTR>(&data[0]);
    dst = reinterpret_cast<UINT_PTR>(&data[1]);

    const auto tp2 = clock::now();
    if (const auto rv = device.read(src, dst, sizeof(std::uint64_t)); !rv) {
      throw std::system_error(rv.error(), "read");
    } else {
      const auto ms = duration_cast<milliseconds>(clock::now() - tp2).count();
      std::puts(std::format("deus read: {:.03f} ms", ms).data());
    }

    src = reinterpret_cast<UINT_PTR>(&data[0]);
    dst = reinterpret_cast<UINT_PTR>(&data[2]);

    const auto tp3 = clock::now();
    if (const auto rv = device.write(src, dst, sizeof(std::uint64_t)); !rv) {
      throw std::system_error(rv.error(), "write");
    } else {
      const auto ms = duration_cast<milliseconds>(clock::now() - tp3).count();
      std::puts(std::format("deus write: {:.03f} ms", ms).data());
    }

    std::puts(std::format("0: {:016X}", data[0]).data());
    std::puts(std::format("1: {:016X}", data[1]).data());
    std::puts(std::format("2: {:016X}", data[2]).data());

    std::vector<deus::copy> copy;
    copy.emplace_back(
      reinterpret_cast<UINT_PTR>(&data[0]),
      reinterpret_cast<UINT_PTR>(&data[1]),
      sizeof(std::uint64_t));
    copy.emplace_back(
      reinterpret_cast<UINT_PTR>(&data[0]),
      reinterpret_cast<UINT_PTR>(&data[2]),
      sizeof(std::uint64_t));

    const auto tp4 = clock::now();
    if (const auto rv = device.watch(copy); !rv) {
      throw std::system_error(rv.error(), "watch");
    } else {
      const auto ms = duration_cast<milliseconds>(clock::now() - tp4).count();
      std::puts(std::format("deus watch: {:.03f} ms", ms).data());
    }

    for (std::uint64_t i = 1; i < 5; i++) {
      data[0] = i;

      const auto tp5 = clock::now();
      if (const auto rv = device.update(); !rv) {
        throw std::system_error(rv.error(), "update");
      } else {
        const auto ms = duration_cast<milliseconds>(clock::now() - tp5).count();
        std::puts(std::format("deus update {}: {:.03f} ms", i, ms).data());
      }

      std::puts(std::format("0: {:016X}", data[0]).data());
      std::puts(std::format("1: {:016X}", data[1]).data());
      std::puts(std::format("2: {:016X}", data[2]).data());
    }

    if (const auto rv = device.stop(); !rv) {
      throw std::system_error(rv.error(), "stop");
    }

    if (const auto rv = device.close(); !rv) {
      throw std::system_error(rv.error(), "close");
    }

    if (const auto rv = device.destroy(); !rv) {
      throw std::system_error(rv.error(), "destroy");
    }
  }
  catch (const std::system_error& e) {
    return print_error(e);
  }
  catch (const std::exception& e) {
    return print_error(e);
  }
  return EXIT_SUCCESS;
}