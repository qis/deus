#pragma once
#ifndef _KERNEL_MODE
#include <windows.h>
#include <ntstatus.h>
#include <winioctl.h>
#include <winternl.h>
#else
#include <ntifs.h>
#endif

#define DEUS_DEVICE_NAME L"\\Device\\Deus"

namespace deus::io {

constexpr ULONG version = 0x00'02'0000;

// clang-format off

enum class code : ULONG {
  version = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER,  FILE_ANY_ACCESS),
  query   = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS),
  copy    = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER,  FILE_ANY_ACCESS),
};

// clang-format on

namespace memory {

constexpr UINT_PTR min = 0x00000000'00400000;
constexpr UINT_PTR max = 0x000F0000'00000000;

}  // namespace memory

/// Information about a range of committed pages in the virtual address space of a process.
/// No reported regions will have PAGE_NOACCESS or PAGE_GUARD protect flags set.
struct alignas(16) region : SLIST_ENTRY {
  /// A pointer to the base address of the region of pages.
  UINT_PTR address{ 0 };

  /// A pointer to the base address of a range of pages allocated by the application.
  /// The page pointed to by @ref size is contained within this allocation range.
  UINT_PTR allocation_base{ 0 };

  /// The memory protection option when the region was initially allocated.
  /// https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
  ULONG allocation_protect{ 0 };

  /// The size of the region beginning at @ref size in which all pages have identical attributes.
  SIZE_T size{ 0 };

  /// The state of the pages in the region.
  ULONG state{ 0 };

  /// The access protection of the pages in the region.
  /// https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
  ULONG protect{ 0 };

  /// The type of pages in the region. The following types are defined.
  /// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information
  ULONG type{ 0 };
};

struct alignas(16) query {
  HANDLE pid{ nullptr };
  UINT_PTR min{ memory::min };
  UINT_PTR max{ memory::max };
  PSLIST_HEADER regions{ nullptr };
};

struct alignas(16) copy {
  HANDLE from{ nullptr };
  SIZE_T count{ 1 };
  struct operation {
    UINT_PTR src{ 0 };
    UINT_PTR dst{ 0 };
    SIZE_T bytes{ 0 };
    SIZE_T copied{ 0 };
  } operations[1]{};
};

}  // namespace deus::io