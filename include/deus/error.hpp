#pragma once
#include <deus.hpp>
#include <format>
#include <string>
#include <system_error>
#include <utility>

namespace deus {

enum class errc {
  version_mismatch = 1,
};

namespace detail {

class error_category : public std::error_category {
public:
  const char* name() const noexcept override final
  {
    return "DEUS";
  }

  std::string message(int code) const override final
  {
    switch (static_cast<errc>(code)) {
    case errc::version_mismatch:
      return "Driver version mismatch.";
    }
    return std::format("0x{:08X}", static_cast<unsigned>(code));
  }
};

class system_error_category : public std::error_category {
public:
  const char* name() const noexcept override final
  {
    return "DEUS System";
  }

  std::string message(int error) const override final
  {
    std::string text;
    LPWSTR wtext = nullptr;
    const auto buffer = reinterpret_cast<LPWSTR>(&wtext);
    constexpr auto language = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);
    constexpr auto flags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;
    const auto wsize = FormatMessageW(flags, nullptr, static_cast<DWORD>(error), language, buffer, 0, nullptr);
    if (wtext) {
      if (auto size = WideCharToMultiByte(CP_UTF8, 0, wtext, wsize, nullptr, 0, nullptr, nullptr); size > 0) {
        text.resize(static_cast<std::size_t>(size) + 1);
        size = WideCharToMultiByte(CP_UTF8, 0, wtext, wsize, text.data(), size + 1, nullptr, nullptr);
        if (size > 0) {
          text.resize(static_cast<std::size_t>(size));
          if (const auto pos = text.find_last_not_of("\f\t\v\r\n"); pos != std::string::npos) {
            text.resize(pos + 1);
          }
        } else {
          text.clear();
        }
      }
      LocalFree(wtext);
    }
    if (text.empty()) {
      text.assign(std::format("0x{:08X}", static_cast<unsigned>(error)));
    }
    return text;
  }
};

class driver_error_category : public std::error_category {
public:
  const char* name() const noexcept override final
  {
    return "DEUS Driver";
  }

  std::string message(int status) const override final
  {
    std::string text;
    LPWSTR wtext = nullptr;
    const auto handle = GetModuleHandleW(L"ntdll.dll");
    const auto buffer = reinterpret_cast<LPWSTR>(&wtext);
    constexpr auto language = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);
    constexpr auto flags = FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS;
    const auto wsize = FormatMessageW(flags, handle, static_cast<DWORD>(status), language, buffer, 0, nullptr);
    if (wtext) {
      if (auto size = WideCharToMultiByte(CP_UTF8, 0, wtext, wsize, nullptr, 0, nullptr, nullptr); size > 0) {
        text.resize(static_cast<std::size_t>(size) + 1);
        size = WideCharToMultiByte(CP_UTF8, 0, wtext, wsize, text.data(), size + 1, nullptr, nullptr);
        if (size > 0) {
          text.resize(static_cast<std::size_t>(size));
          if (const auto pos = text.find_last_not_of("\f\t\v\r\n"); pos != std::string::npos) {
            text.resize(pos + 1);
          }
        } else {
          text.clear();
        }
      }
      LocalFree(wtext);
    }
    if (text.empty()) {
      text.assign(std::format("NTSTATUS Error 0x{:08X}", static_cast<unsigned>(status)));
    }
    return text;
  }
};

}  // namespace detail

inline std::error_category& error_category() noexcept
{
  static detail::error_category category;
  return category;
}

inline std::error_category& system_error_category() noexcept
{
  static detail::system_error_category category;
  return category;
}

inline std::error_category& driver_error_category() noexcept
{
  static detail::driver_error_category category;
  return category;
}

inline std::error_code make_error_code(errc code) noexcept
{
  return { static_cast<int>(code), error_category() };
}

inline std::error_code make_error_code(DWORD code) noexcept
{
  return { static_cast<int>(code), system_error_category() };
}

inline std::error_code make_error_code(NTSTATUS status) noexcept
{
  return { static_cast<int>(status), driver_error_category() };
}

}  // namespace deus