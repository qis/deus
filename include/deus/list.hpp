#pragma once
#include <windows.h>
#include <iterator>
#include <type_traits>
#include <utility>

namespace deus {

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

}  // namespace deus