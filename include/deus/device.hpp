#pragma once
#include <deus.hpp>
#include <deus/error.hpp>
#include <deus/list.hpp>
#include <deus/result.hpp>
#include <memory>

namespace deus {

class device {
public:
  device() noexcept = default;

  device(device&& other) noexcept : device_(std::exchange(other.device_, INVALID_HANDLE_VALUE)) {}
  device(const device& other) = delete;

  device& operator=(device&& other) noexcept
  {
    close();
    device_ = std::exchange(other.device_, INVALID_HANDLE_VALUE);
    return *this;
  }

  device& operator=(const device& other) = delete;

  std::error_code open() noexcept
  {
    UNICODE_STRING device_name{};
    RtlInitUnicodeString(&device_name, DEUS_DEVICE_NAME);

    OBJECT_ATTRIBUTES attributes{};
    InitializeObjectAttributes(&attributes, &device_name, 0, nullptr, nullptr);

    if (device_ != INVALID_HANDLE_VALUE) {
      CloseHandle(std::exchange(device_, INVALID_HANDLE_VALUE));
    }

    IO_STATUS_BLOCK isb{};
    const auto status = NtOpenFile(&device_, GENERIC_WRITE, &attributes, &isb, FILE_SHARE_WRITE, 0);
    if (!NT_SUCCESS(status)) {
      if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
        return make_error_code(STATUS_DEVICE_DOES_NOT_EXIST);
      }
      return make_error_code(status);
    }
    if (!NT_SUCCESS(isb.Status)) {
      CloseHandle(std::exchange(device_, INVALID_HANDLE_VALUE));
      return make_error_code(isb.Status);
    }

    DWORD driver_version = 0;
    constexpr auto code = static_cast<ULONG>(io::code::version);
    if (!DeviceIoControl(device_, code, nullptr, 0, nullptr, 0, &driver_version, nullptr)) {
      CloseHandle(std::exchange(device_, INVALID_HANDLE_VALUE));
      return make_error_code(GetLastError());
    }
    if (driver_version != io::version) {
      CloseHandle(std::exchange(device_, INVALID_HANDLE_VALUE));
      return make_error_code(errc::version_mismatch);
    }
    return {};
  }

  void close() noexcept
  {
    if (device_ != INVALID_HANDLE_VALUE) {
      CloseHandle(device_);
    }
    device_ = INVALID_HANDLE_VALUE;
  }

  result<list<io::region>> query(HANDLE pid, UINT_PTR min = io::memory::min, UINT_PTR max = io::memory::max) noexcept
  {
    list<io::region> regions;
    io::query query{ pid, min, max, regions.header() };
    constexpr auto code = static_cast<ULONG>(io::code::query);
    if (!DeviceIoControl(device_, code, &query, sizeof(query), nullptr, 0, nullptr, nullptr)) {
      return error(make_error_code(GetLastError()));
    }
    return regions;
  }

  BOOL copy(io::copy* copy) noexcept
  {
    constexpr auto code = static_cast<ULONG>(io::code::copy);
    return DeviceIoControl(device_, code, copy, sizeof(*copy), nullptr, 0, nullptr, nullptr);
  }

  constexpr HANDLE handle() const noexcept
  {
    return device_;
  }

private:
  HANDLE device_{ INVALID_HANDLE_VALUE };
};

std::unique_ptr<io::copy, decltype(&_aligned_free)> create_copy(HANDLE from, SIZE_T count)
{
  const size_t additional_operations = count > 0 ? count - 1 : count;
  const size_t allocation_size = sizeof(io::copy) + sizeof(io::copy::operation) * additional_operations;
  const auto copy = static_cast<io::copy*>(_aligned_malloc(allocation_size, MEMORY_ALLOCATION_ALIGNMENT));
  if (!copy) {
    throw std::bad_alloc{};
  }
  copy->from = from;
  copy->count = count;
  std::memset(copy->operations, 0, sizeof(io::copy::operation) * (additional_operations + 1));
  return { copy, &_aligned_free };
}

}  // namespace deus