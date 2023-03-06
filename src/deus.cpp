#include "deus.hpp"
#include <algorithm>
#include <format>
#include <cassert>

namespace deus {

class error_category_impl : public std::error_category {
public:
  const char* name() const noexcept override final
  {
    return "deus";
  }

  std::string message(int ev) const override final
  {
    const auto code = static_cast<DWORD>(ev);
    const auto status = static_cast<NTSTATUS>(ev);
    auto text = std::format("error 0x{:08X} ({}): ", code, status);
    char* data = nullptr;
    DWORD size = FormatMessage(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
      nullptr,
      code,
      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      reinterpret_cast<LPSTR>(&data),
      0,
      nullptr);
    if (data) {
      if (size) {
        text.append(data, size);
      }
      LocalFree(data);
      if (size) {
        return text;
      }
    }
    switch (code >> 30) {
    case 0:
      text.append("Unknown success.");
      break;
    case 1:
      text.append("Unknown information.");
      break;
    case 2:
      text.append("Unknown warning.");
      break;
    case 3:
      text.append("Unknown error.");
      break;
    default:
      text.append("Unknown status.");
      break;
    }
    return text;
  }
};

std::error_category& error_category() noexcept
{
  static error_category_impl category;
  return category;
}

device& device::operator=(device&& other) noexcept
{
  destroy();
  handle_ = std::exchange(other.handle_, INVALID_HANDLE_VALUE);
  return *this;
}

device::~device()
{
  destroy();
}

device::result<void> device::create() noexcept
{
  if (handle_ != INVALID_HANDLE_VALUE) {
    return error(STATUS_ALREADY_INITIALIZED);
  }
  const DWORD access = GENERIC_READ | GENERIC_WRITE;
  const DWORD share_mode = OPEN_EXISTING;
  const DWORD attributes = FILE_ATTRIBUTE_NORMAL;
  handle_ = CreateFile("\\\\.\\Deus", access, 0, nullptr, share_mode, attributes, nullptr);
  if (handle_ == INVALID_HANDLE_VALUE) {
    return error(static_cast<NTSTATUS>(GetLastError()));
  }
  auto v = version;
  if (const auto rv = control(code::version, &v, sizeof(v)); !rv) {
    CloseHandle(std::exchange(handle_, INVALID_HANDLE_VALUE));
    return error(rv.error());
  }
  return {};
}

device::result<void> device::destroy() noexcept
{
  if (handle_ == INVALID_HANDLE_VALUE) {
    return error(STATUS_INVALID_HANDLE);
  }
  if (!CloseHandle(std::exchange(handle_, INVALID_HANDLE_VALUE))) {
    return error(GetLastError());
  }
  return {};
}

}  // namespace deus