#pragma once
#include "deus.h"
#include <winioctl.h>
#include <winternl.h>
#include <algorithm>
#include <concepts>
#include <expected>
#include <format>
#include <functional>
#include <iterator>
#include <span>
#include <string_view>
#include <system_error>
#include <vector>
#include <cassert>
#include <cstddef>

namespace deus {
namespace detail {

class error_category : public std::error_category {
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

}  // namespace detail

inline std::error_category& error_category() noexcept
{
  static detail::error_category category;
  return category;
}

inline std::error_code error(DWORD code) noexcept
{
  return { static_cast<int>(code), error_category() };
}

inline std::error_code error(NTSTATUS status) noexcept
{
  return { static_cast<int>(status), error_category() };
}

template <typename T>
using result = std::expected<T, std::error_code>;

template <class T>
concept ListEntry = std::is_base_of<SLIST_ENTRY, T>::value;

template <ListEntry T>
class list {
public:
  class iterator {
  public:
    using iterator_category = std::input_iterator_tag;
    using difference_type = std::size_t;
    using value_type = T;
    using reference = value_type&;
    using pointer = value_type*;

    constexpr iterator() noexcept = default;
    constexpr iterator(PSLIST_ENTRY entry) noexcept : entry_(entry) {}

    constexpr bool operator==(const iterator& other) const noexcept
    {
      return entry_ == other.entry_;
    }

    constexpr bool operator!=(const iterator& other) const noexcept
    {
      return !(*this == other);
    }

    constexpr iterator& operator++() noexcept
    {
      entry_ = entry_->Next;
      return *this;
    }

    iterator operator++(int) = delete;

    constexpr reference operator*() noexcept
    {
      return *operator->();
    }

    constexpr pointer operator->() noexcept
    {
      return static_cast<T*>(entry_);
    }

  private:
    PSLIST_ENTRY entry_ = nullptr;
  };

  list() noexcept
  {
    constexpr size_t size = sizeof(SLIST_HEADER);
    constexpr size_t alignment = MEMORY_ALLOCATION_ALIGNMENT;
    header_ = static_cast<PSLIST_HEADER>(_aligned_malloc(size, alignment));
    if (header_) {
      InitializeSListHead(header_);
    }
  }

  constexpr list(list&& other) noexcept : header_(std::exchange(other.header_, nullptr)) {}

  list(const list& other) = delete;

  list& operator=(list&& other) noexcept
  {
    clear();
    if (const auto header = std::exchange(header_, std::exchange(other.header_, nullptr))) {
      _aligned_free(header);
    }
    return *this;
  }

  list& operator=(const list& other) = delete;

  ~list()
  {
    clear();
    if (header_) {
      _aligned_free(header_);
    }
  }

  iterator begin() const noexcept
  {
    if (header_) {
      if (const auto entry = InterlockedPopEntrySList(header_)) {
        InterlockedPushEntrySList(header_, entry);
        return entry;
      }
    }
    return {};
  }

  constexpr iterator end() const noexcept
  {
    return {};
  }

  std::size_t size() const noexcept
  {
    if (header_) {
      return QueryDepthSList(header_);
    }
    return 0;
  }

  void clear() noexcept
  {
    if (header_) {
      for (auto entry = InterlockedFlushSList(header_); entry;) {
        const auto next = entry->Next;
        VirtualFree(static_cast<T*>(entry), 0, MEM_RELEASE);
        entry = next;
      }
    }
  }

  constexpr PSLIST_HEADER header() const noexcept
  {
    return header_;
  }

private:
  PSLIST_HEADER header_ = nullptr;
};

// clang-format off

template <class T>
concept SignatureScanCallback = requires(T&& callback, void* data) {
  { std::forward<T>(callback)(data) } -> std::convertible_to<bool>;
};

template <class T>
concept SignatureScanConstCallback = requires(T&& callback, const void* data) {
  { std::forward<T>(callback)(data) } -> std::convertible_to<bool>;
};

// clang-format on

class signature {
public:
  signature(const BYTE* data, SIZE_T size) noexcept : size_(size), data_(data, data + size) {}

  signature(const BYTE* data, const BYTE* mask, SIZE_T size) noexcept : size_(size), data_(size * 2)
  {
    std::memcpy(data_.data(), data, size);
    std::memcpy(data_.data() + size, mask, size);
  }

  signature(std::string_view signature) noexcept : size_((signature.size() + 1) / 3)
  {
    assert((signature.size() + 1) / 3 > 0);
    assert((signature.size() + 1) % 3 == 0);

    if (signature.empty()) {
      return;
    }
    if (signature.find('?') != std::string_view::npos) {
      data_.resize(size_ * 2);
      const auto mask = data_.data() + size_;
      for (SIZE_T i = 0; i < size_; i++) {
        mask[i] = mask_cast(signature[i * 3]) << 4 | mask_cast(signature[i * 3 + 1]);
      }
    } else {
      data_.resize(size_);
    }
    const auto data = data_.data();
    for (SIZE_T i = 0; i < size_; i++) {
      data[i] = data_cast(signature[i * 3]) << 4 | data_cast(signature[i * 3 + 1]);
      assert(i == 0 || signature[i * 3 - 1] == ' ');
    }
  }

  __forceinline void* scan(void* begin, void* end) const noexcept
  {
    const auto bytes_begin = reinterpret_cast<BYTE*>(begin);
    const auto bytes_end = reinterpret_cast<BYTE*>(end);
    return scan_impl(bytes_begin, bytes_end, data(), mask(), size());
  }

  __forceinline const void* scan(const void* begin, const void* end) const noexcept
  {
    const auto bytes_begin = reinterpret_cast<const BYTE*>(begin);
    const auto bytes_end = reinterpret_cast<const BYTE*>(end);
    return scan_impl(bytes_begin, bytes_end, data(), mask(), size());
  }

  __forceinline void scan(void* begin, void* end, SignatureScanCallback auto&& callback) const
  {
    const auto bytes_begin = reinterpret_cast<BYTE*>(begin);
    const auto bytes_end = reinterpret_cast<BYTE*>(end);
    scan_impl(bytes_begin, bytes_end, std::forward<decltype(callback)>(callback));
  }

  __forceinline void scan(const void* begin, const void* end, SignatureScanConstCallback auto&& callback) const
  {
    const auto bytes_begin = reinterpret_cast<const BYTE*>(begin);
    const auto bytes_end = reinterpret_cast<const BYTE*>(end);
    scan_impl(bytes_begin, bytes_end, std::forward<decltype(callback)>(callback));
  }

  constexpr BYTE* data() noexcept
  {
    return data_.data();
  }

  constexpr const BYTE* data() const noexcept
  {
    return data_.data();
  }

  constexpr BYTE* mask() noexcept
  {
    return data_.size() == size_ ? nullptr : data_.data() + size_;
  }

  constexpr const BYTE* mask() const noexcept
  {
    return data_.size() == size_ ? nullptr : data_.data() + size_;
  }

  constexpr SIZE_T size() const noexcept
  {
    return size_;
  }

private:
  template <class T, class Callback>
  void scan_impl(T* begin, T* end, Callback&& callback) const
  {
    const auto signature_data = data();
    const auto signature_mask = mask();
    const auto signature_size = size();
    for (auto address = begin; address != end; reinterpret_cast<UINT_PTR&>(address)++) {
      address = scan_impl(address, end, signature_data, signature_mask, signature_size);
      if (address == end) {
        break;
      }
      if (!callback(address)) {
        break;
      }
    }
  }

  template <class T>
  static T* scan_impl(T* begin, T* end, const BYTE* data, const BYTE* mask, SIZE_T size) noexcept
  {
    if (mask) {
      std::size_t mask_index = 0;
      const auto compare = [&](BYTE lhs, BYTE rhs) noexcept {
        if ((lhs & mask[mask_index++]) == rhs) {
          return true;
        }
        mask_index = 0;
        return false;
      };
      const auto searcher = std::default_searcher(data, data + size, compare);
      return std::search(begin, end, searcher);
    }
    const auto searcher = std::boyer_moore_horspool_searcher(data, data + size);
    return std::search(begin, end, searcher);
  }

  static constexpr BYTE data_cast(CHAR c) noexcept
  {
    if (c >= '0' && c <= '9') {
      return static_cast<BYTE>(c - '0');
    }
    if (c >= 'A' && c <= 'F') {
      return static_cast<BYTE>(c - 'A' + 0xA);
    }
    if (c >= 'a' && c <= 'f') {
      return static_cast<BYTE>(c - 'a' + 0xA);
    }
    assert(c == '?');
    return 0x0;
  }

  static constexpr BYTE mask_cast(CHAR c) noexcept
  {
    return c == '?' ? 0x0 : 0xF;
  }

  SIZE_T size_{ 0 };
  std::vector<BYTE> data_;
};

// clang-format off

template <class T>
concept DeviceScanCallback = requires(T&& callback, UINT_PTR address) {
  { std::forward<T>(callback)(address) } -> std::convertible_to<bool>;
};

// clang-format on

class device {
public:
  constexpr device() noexcept = default;

  constexpr device(device&& other) noexcept :
    handle_(std::exchange(other.handle_, INVALID_HANDLE_VALUE))
  {}

  device(const device& other) = delete;

  device& operator=(device&& other) noexcept
  {
    destroy();
    handle_ = std::exchange(other.handle_, INVALID_HANDLE_VALUE);
    return *this;
  }

  device& operator=(const device& other) = delete;

  ~device()
  {
    destroy();
  }

  result<void> create() noexcept
  {
    if (handle_ != INVALID_HANDLE_VALUE) {
      return std::unexpected(error(ERROR_ALREADY_INITIALIZED));
    }
    const DWORD access = GENERIC_READ | GENERIC_WRITE;
    const DWORD share_mode = OPEN_EXISTING;
    const DWORD attributes = FILE_ATTRIBUTE_NORMAL;
    handle_ = CreateFile("\\\\.\\Deus", access, 0, nullptr, share_mode, attributes, nullptr);
    if (handle_ == INVALID_HANDLE_VALUE) {
      return std::unexpected(error(static_cast<NTSTATUS>(GetLastError())));
    }
    auto v = version;
    if (const auto rv = control(code::version, &v, sizeof(v)); !rv) {
      CloseHandle(std::exchange(handle_, INVALID_HANDLE_VALUE));
      return std::unexpected(rv.error());
    }
    return {};
  }

  result<void> destroy() noexcept
  {
    if (handle_ == INVALID_HANDLE_VALUE) {
      return std::unexpected(error(STATUS_INVALID_HANDLE));
    }
    if (!CloseHandle(std::exchange(handle_, INVALID_HANDLE_VALUE))) {
      return std::unexpected(error(GetLastError()));
    }
    return {};
  }

  result<void> open(DWORD pid) noexcept
  {
    if (const auto rv = control(code::open, &pid, sizeof(pid)); !rv) {
      return std::unexpected(rv.error());
    }
    return {};
  }

  result<void> close() noexcept
  {
    if (const auto rv = control(code::close); !rv) {
      return std::unexpected(rv.error());
    }
    return {};
  }

  result<list<region>> query() noexcept
  {
    list<region> regions;
    if (const auto rv = control(code::query, regions.header(), sizeof(*regions.header())); !rv) {
      return std::unexpected(rv.error());
    }
    return regions;
  }

  result<UINT_PTR> scan(UINT_PTR begin, UINT_PTR end, const signature& signature) noexcept
  {
    const auto data = signature.data();
    const auto mask = signature.mask();
    const auto size = signature.size();
    const auto data_size = mask ? size * 2 : size;
    const auto scan_size = sizeof(deus::scan) + data_size;
    const auto scan = static_cast<deus::scan*>(_aligned_malloc(scan_size, alignof(deus::scan)));
    if (!scan) {
      return std::unexpected(error(STATUS_NO_MEMORY));
    }
    scan->begin = begin;
    scan->end = end;
    scan->address = end;
    scan->size = size;
    std::memcpy(scan + 1, data, data_size);
    const auto rv = control(code::scan, scan, scan_size);
    const auto address = rv ? scan->address : end;
    _aligned_free(scan);
    if (!rv) {
      return std::unexpected(rv.error());
    }
    return address;
  }

  result<void> scan(UINT_PTR begin, UINT_PTR end, const signature& signature, DeviceScanCallback auto&& callback)
  {
    for (auto address = begin; address != end; address++) {
      const auto rv = scan(address, end, signature);
      if (!rv) {
        return std::unexpected(rv.error());
      }
      if (*rv == end) {
        break;
      }
      if (!callback(*rv)) {
        break;
      }
      address = *rv;
    }
    return {};
  }

  result<SIZE_T> read(UINT_PTR src, void* dst, SIZE_T size) noexcept
  {
    copy copy{ src, reinterpret_cast<UINT_PTR>(dst), size, 0 };
    if (const auto rv = control(code::read, &copy, sizeof(copy)); !rv) {
      return std::unexpected(rv.error());
    }
    return copy.copied;
  }

  result<SIZE_T> write(const void* src, UINT_PTR dst, SIZE_T size) noexcept
  {
    copy copy{ reinterpret_cast<UINT_PTR>(src), dst, size, 0 };
    if (const auto rv = control(code::write, &copy, sizeof(copy)); !rv) {
      return std::unexpected(rv.error());
    }
    return copy.copied;
  }

  result<void> watch(std::span<copy> data) noexcept
  {
    if (const auto rv = control(code::watch, data.data(), sizeof(copy) * data.size()); !rv) {
      return std::unexpected(rv.error());
    }
    return {};
  }

  result<void> update() noexcept
  {
    if (const auto rv = control(code::update); !rv) {
      return std::unexpected(rv.error());
    }
    return {};
  }

  result<void> stop() noexcept
  {
    if (const auto rv = control(code::stop); !rv) {
      return std::unexpected(rv.error());
    }
    return {};
  }

  __forceinline result<DWORD> control(code code) noexcept
  {
    return control(static_cast<ULONG>(code), nullptr, 0, 0);
  }

  __forceinline result<DWORD> control(code code, PVOID data, ULONG size) noexcept
  {
    return control(static_cast<ULONG>(code), data, size, size);
  }

  __forceinline result<DWORD> control(code code, PVOID data, ULONG isize, ULONG osize) noexcept
  {
    return control(static_cast<ULONG>(code), data, isize, osize);
  }

private:
  __forceinline result<DWORD> control(ULONG code, PVOID data, ULONG isize, ULONG osize) noexcept
  {
    DWORD size = 0;
    if (!DeviceIoControl(handle_, code, data, isize, data, osize, &size, nullptr)) {
      return std::unexpected(error(GetLastError()));
    }
    return size;
  }

  HANDLE handle_{ INVALID_HANDLE_VALUE };
};

}  // namespace deus