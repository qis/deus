#pragma once
#ifdef DEUS_DRIVER
#  include <ntifs.h>
#  include <ntddk.h>
#else
#  include <windows.h>
#endif

#if defined(DEUS_DRIVER) && !defined(BYTE)
typedef unsigned char BYTE;
#endif

#if defined(DEUS_DRIVER) && !defined(DWORD)
typedef ULONG DWORD;
#else
static_assert(sizeof(DWORD) == sizeof(ULONG));
#endif

namespace deus {

// clang-format off
enum class code : ULONG {
  version = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_IN_DIRECT,  FILE_SPECIAL_ACCESS),
  open    = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_IN_DIRECT,  FILE_SPECIAL_ACCESS),
  close   = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER,    FILE_SPECIAL_ACCESS),
  query   = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_OUT_DIRECT, FILE_SPECIAL_ACCESS),
  scan    = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_OUT_DIRECT, FILE_SPECIAL_ACCESS),
  read    = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_OUT_DIRECT, FILE_SPECIAL_ACCESS),
  write   = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_OUT_DIRECT, FILE_SPECIAL_ACCESS),
  watch   = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_IN_DIRECT,  FILE_SPECIAL_ACCESS),
  update  = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_NEITHER,    FILE_SPECIAL_ACCESS),
  stop    = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x809, METHOD_NEITHER,    FILE_SPECIAL_ACCESS),
};
// clang-format on

inline constexpr DWORD version = 1;

namespace memory {

static constexpr UINT_PTR min = 0x00000000'00400000;
static constexpr UINT_PTR max = 0x000F0000'00000000;

}  // namespace memory

struct alignas(16) region : SLIST_ENTRY {
  UINT_PTR base_address{ 0 };
  UINT_PTR allocation_base{ 0 };
  ULONG allocation_protect{ 0 };
  SIZE_T region_size{ 0 };
  ULONG state{ 0 };
  ULONG protect{ 0 };
  ULONG type{ 0 };
};

struct alignas(16) scan {
  UINT_PTR begin{ 0 };
  UINT_PTR end{ 0 };
  UINT_PTR address{ 0 };
  SIZE_T size{ 0 };
};

struct alignas(32) copy {
  UINT_PTR src{ 0 };
  UINT_PTR dst{ 0 };
  SIZE_T size{ 0 };
  SIZE_T copied{ 0 };
};

}  // namespace deus