#pragma once
#include "deus.h"
#include <ntstatus.h>
#include <winioctl.h>
#include <winternl.h>
#include <algorithm>
#include <expected>
#include <functional>
#include <iterator>
#include <span>
#include <string_view>
#include <system_error>
#include <vector>
#include <cassert>
#include <cstddef>

#ifdef DEUS_EXPORTS
#  define DEUS_API __declspec(dllexport)
#else
#  define DEUS_API __declspec(dllimport)
#endif

namespace deus {

DEUS_API std::error_category& error_category() noexcept;

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

class signature {
public:
  signature(const BYTE* data, SIZE_T size) noexcept : size_(size), data_(data, data + size) {}

  signature(std::string_view signature) noexcept : size_(signature.size() / 2)
  {
    assert(signature.size() % 2 == 0);
    if (signature.empty()) {
      return;
    }
    if (signature.find('?') != std::string_view::npos) {
      data_.resize(size_ * 2);
      const auto mask = data_.data() + size_;
      for (SIZE_T i = 0; i < size_; i++) {
        mask[i] = mask_cast(signature[i * 2]) << 4 | mask_cast(signature[i * 2 + 1]);
      }
    } else {
      data_.resize(size_);
    }
    const auto data = data_.data();
    for (SIZE_T i = 0; i < size_; i++) {
      data[i] = data_cast(signature[i * 2]) << 4 | data_cast(signature[i * 2 + 1]);
    }
  }

  __forceinline void* scan(void* data, SIZE_T size) const noexcept
  {
    const auto begin = static_cast<BYTE*>(data);
    return scan(begin, begin + size, this->data(), mask(), size_);
  }

  __forceinline const void* scan(const void* data, SIZE_T size) const noexcept
  {
    const auto begin = static_cast<const BYTE*>(data);
    return scan(begin, begin + size, this->data(), mask(), size_);
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
  template <class T>
  static T* scan(T* begin, T* end, const BYTE* data, const BYTE* mask, SIZE_T size) noexcept
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
      const auto it = std::search(begin, end, searcher);
      return it != end ? it : nullptr;
    }
    const auto searcher = std::boyer_moore_horspool_searcher(data, data + size);
    const auto it = std::search(begin, end, searcher);
    return it != end ? it : nullptr;
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

class DEUS_API device {
public:
  template <typename T>
  using result = std::expected<T, std::error_code>;

  constexpr device() noexcept = default;

  constexpr device(device&& other) noexcept :
    handle_(std::exchange(other.handle_, INVALID_HANDLE_VALUE))
  {}

  device(const device& other) = delete;
  device& operator=(device&& other) noexcept;
  device& operator=(const device& other) = delete;

  ~device();

  result<void> create() noexcept;
  result<void> destroy() noexcept;

  result<void> open(DWORD pid) noexcept
  {
    if (const auto rv = control(code::open, &pid, sizeof(pid)); !rv) {
      return error(rv.error());
    }
    return {};
  }

  result<void> close() noexcept
  {
    if (const auto rv = control(code::close); !rv) {
      return error(rv.error());
    }
    return {};
  }

  result<list<region>> query() noexcept
  {
    list<region> regions;
    if (const auto rv = control(code::query, regions.header(), sizeof(*regions.header())); !rv) {
      return error(rv.error());
    }
    return regions;
  }

  result<UINT_PTR> scan(UINT_PTR address, SIZE_T size, const signature& signature) noexcept
  {
    const auto signature_data = signature.data();
    const auto signature_mask = signature.mask();
    const auto signature_size = signature.size();
    const auto copy_size = signature_mask ? signature_size * 2 : signature_size;
    const auto data_size = sizeof(deus::scan) + copy_size;
    const auto data = static_cast<deus::scan*>(_aligned_malloc(data_size, alignof(deus::scan)));
    if (!data) {
      return error(STATUS_NO_MEMORY);
    }
    data->begin = address;
    data->end = address + size;
    data->pos = deus::npos;
    data->size = signature_size;
    std::memcpy(data + 1, signature_data, copy_size);
    UINT_PTR pos = deus::npos;
    const auto rv = control(code::scan, data, data_size);
    if (rv) {
      pos = data->pos;
    }
    _aligned_free(data);
    if (!rv) {
      return error(rv.error());
    }
    return pos;
  }

  result<SIZE_T> read(UINT_PTR src, UINT_PTR dst, SIZE_T size) noexcept
  {
    copy copy{ src, dst, size, 0 };
    if (const auto rv = control(code::read, &copy, sizeof(copy)); !rv) {
      return error(rv.error());
    }
    return copy.copied;
  }

  result<SIZE_T> write(UINT_PTR src, UINT_PTR dst, SIZE_T size) noexcept
  {
    copy copy{ src, dst, size, 0 };
    if (const auto rv = control(code::write, &copy, sizeof(copy)); !rv) {
      return error(rv.error());
    }
    return copy.copied;
  }

  result<void> watch(std::span<copy> data) noexcept
  {
    if (const auto rv = control(code::watch, data.data(), sizeof(copy) * data.size()); !rv) {
      return error(rv.error());
    }
    return {};
  }

  result<void> update() noexcept
  {
    if (const auto rv = control(code::update); !rv) {
      return error(rv.error());
    }
    return {};
  }

  result<void> stop() noexcept
  {
    if (const auto rv = control(code::stop); !rv) {
      return error(rv.error());
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
      return error(GetLastError());
    }
    return size;
  }

  static __forceinline std::unexpected<std::error_code> error(DWORD code) noexcept
  {
    return std::unexpected(std::error_code(static_cast<int>(code), error_category()));
  }

  static __forceinline std::unexpected<std::error_code> error(NTSTATUS status) noexcept
  {
    return std::unexpected(std::error_code(static_cast<int>(status), error_category()));
  }

  static __forceinline std::unexpected<std::error_code> error(std::error_code ec) noexcept
  {
    return std::unexpected(ec);
  }

  HANDLE handle_{ INVALID_HANDLE_VALUE };
};

}  // namespace deus