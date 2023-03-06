#include "deus.h"
#include <wchar.h>
#include <ntifs.h>
#include <algorithm>
#include <expected>
#include <functional>
#include <span>

#include <boost/algorithm/searching/boyer_moore_horspool.hpp>

extern "C" {

typedef enum _MEMORY_INFORMATION_CLASS_EX {
  MemoryBasicInformationEx = 0,
  MemoryWorkingSetInformation = 1,
  MemoryMappedFilenameInformation = 2,
  MemoryRegionInformation = 3,
  MemoryWorkingSetExInformation = 4,
} MEMORY_INFORMATION_CLASS_EX;

NTKERNELAPI NTSTATUS NTAPI MmCopyVirtualMemory(
  IN PEPROCESS FromProcess,
  IN PVOID FromAddress,
  IN PEPROCESS ToProcess,
  OUT PVOID ToAddress,
  IN SIZE_T BufferSize,
  IN KPROCESSOR_MODE PreviousMode,
  OUT PSIZE_T NumberOfBytesCopied);

}  // extern "C"

namespace deus {

class device {
public:
  using result = std::expected<ULONG_PTR, NTSTATUS>;

  device() noexcept = default;
  device(device&& other) = delete;
  device(const device& other) = delete;
  device& operator=(device&& other) = delete;
  device& operator=(const device& other) = delete;
  ~device() = default;

  NTSTATUS initialize(PDRIVER_OBJECT driver) noexcept
  {
    // Validate state.
    if (device_) {
      return STATUS_ALREADY_INITIALIZED;
    }

    // Initialize lock.
    InterlockedExchange64(&lock_, 0);

    // Initialize strings.
    RtlInitUnicodeString(&device_name_, L"\\Device\\Deus");
    RtlInitUnicodeString(&symbolic_link_name_, L"\\DosDevices\\Deus");

    // Create device.
    auto status =
      IoCreateDevice(driver, 0, &device_name_, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device_);
    if (!NT_SUCCESS(status)) {
      return status;
    }
    if (!device_) {
      return STATUS_UNEXPECTED_IO_ERROR;
    }
    device_->Flags &= ~DO_DEVICE_INITIALIZING;
    device_->Flags &= ~DO_BUFFERED_IO;
    device_->Flags |= DO_DIRECT_IO;

    // Create symbolic link.
    IoDeleteSymbolicLink(&symbolic_link_name_);
    status = IoCreateSymbolicLink(&symbolic_link_name_, &device_name_);
    if (!NT_SUCCESS(status)) {
      return status;
    }
    return STATUS_SUCCESS;
  }

  void reset() noexcept
  {
    // Release process handle.
    if (process_) {
      ObDereferenceObject(process_);
      process_ = nullptr;
    }

    // Delete symbolic link.
    IoDeleteSymbolicLink(&symbolic_link_name_);

    // Delete device.
    if (const auto device = std::exchange(device_, nullptr)) {
      IoDeleteDevice(device);
    }
  }

  NTSTATUS create() noexcept
  {
    // Validate state.
    if (!device_) {
      return STATUS_DEVICE_NOT_READY;
    }

    // Get application process ID.
    const auto application = reinterpret_cast<LONG64>(PsGetCurrentProcess());

    // Set lock.
    if (InterlockedCompareExchange64(&lock_, application, 0)) {
      return STATUS_DEVICE_BUSY;
    }

    // Get application process handles.
    application_ps_ = PsGetCurrentProcess();
    application_zw_ = ZwCurrentProcess();
    application_nt_ = NtCurrentProcess();
    return STATUS_SUCCESS;
  }

  void cleanup() noexcept
  {
    // Get application process ID.
    const auto application = reinterpret_cast<LONG64>(PsGetCurrentProcess());

    // Unset lock and release process handle.
    if (InterlockedCompareExchange64(&lock_, 0, application) && process_) {
      ObDereferenceObject(process_);
      process_ = nullptr;
    }
  }

  result control(PIRP irp) noexcept
  {
    // Validate state.
    if (!device_) {
      return std::unexpected(STATUS_DEVICE_NOT_READY);
    }

    // Get application data.
    PVOID buffer = nullptr;
    const auto stack = IoGetCurrentIrpStackLocation(irp);
    const auto isize = stack->Parameters.DeviceIoControl.InputBufferLength;
    const auto osize = stack->Parameters.DeviceIoControl.OutputBufferLength;
    if (isize || osize) {
      if (irp->MdlAddress) {
        buffer = MmGetSystemAddressForMdlSafe(irp->MdlAddress, NormalPagePriority);
      } else {
        buffer = stack->Parameters.DeviceIoControl.Type3InputBuffer;
      }
    }

    // Handle code.
    switch (static_cast<code>(stack->Parameters.DeviceIoControl.IoControlCode)) {
    case code::version:
      return version(buffer, osize);
    case code::open:
      return open(buffer, isize);
    case code::close:
      return close();
    case code::query:
      return query(buffer, osize);
    case code::scan:
      return scan(buffer, osize);
    case code::read:
      return copy(buffer, osize, true);
    case code::write:
      return copy(buffer, osize, false);
    case code::watch:
      return watch(buffer, isize);
    case code::update:
      return update();
    case code::stop:
      return stop();
    }
    return std::unexpected(STATUS_INVALID_PARAMETER);
  }

private:
  result version(PVOID buffer, ULONG osize) noexcept
  {
    if (!buffer) {
      return std::unexpected(STATUS_INVALID_USER_BUFFER);
    }
    if (osize != sizeof(deus::version)) {
      return std::unexpected(STATUS_INVALID_BUFFER_SIZE);
    }
    if (*reinterpret_cast<decltype(deus::version)*>(buffer) != deus::version) {
      return std::unexpected(STATUS_REMOTE_FILE_VERSION_MISMATCH);
    }
    return 0;
  }

  result open(PVOID buffer, ULONG isize) noexcept
  {
    // Validate parameters.
    if (!buffer) {
      return std::unexpected(STATUS_INVALID_USER_BUFFER);
    }
    if (isize != sizeof(DWORD)) {
      return std::unexpected(STATUS_INVALID_BUFFER_SIZE);
    }

    // Validate state.
    if (process_) {
      return std::unexpected(STATUS_ALREADY_INITIALIZED);
    }

    // Acquire process handle.
    const auto pid = reinterpret_cast<HANDLE>(*reinterpret_cast<DWORD*>(buffer));
    if (const auto status = PsLookupProcessByProcessId(pid, &process_); !NT_SUCCESS(status)) {
      return std::unexpected(status);
    }
    if (!process_) {
      return std::unexpected(STATUS_NOT_FOUND);
    }
    return 0;
  }

  result close() noexcept
  {
    // Stop watching.
    stop();

    // Release process handle.
    if (process_) {
      ObDereferenceObject(process_);
      process_ = nullptr;
    }
    return 0;
  }

  result query(PVOID buffer, ULONG osize) noexcept
  {
    // Validate parameters.
    if (!buffer) {
      return std::unexpected(STATUS_INVALID_USER_BUFFER);
    }
    if (osize != sizeof(SLIST_HEADER)) {
      return std::unexpected(STATUS_INVALID_BUFFER_SIZE);
    }

    // Validate state.
    const auto process = process_;
    const auto application = application_zw_;
    if (!process || !application) {
      return std::unexpected(STATUS_INVALID_DEVICE_STATE);
    }

    // Create regions list.
    SLIST_HEADER regions;
    InitializeSListHead(&regions);

    // Attach to process.
    KAPC_STATE state = {};
    KeStackAttachProcess(process, &state);
    const auto process_zw = ZwCurrentProcess();

    // Get regions information.
    MEMORY_BASIC_INFORMATION mbi = {};
    constexpr auto next = [](const MEMORY_BASIC_INFORMATION& mbi) noexcept {
      return reinterpret_cast<ULONG_PTR>(mbi.BaseAddress) + mbi.RegionSize;
    };

    NTSTATUS status = STATUS_SUCCESS;
    for (ULONG_PTR pos = memory::min; pos < memory::max; pos = next(mbi)) {
      // Query virtual memory.
      SIZE_T size = 0;
      constexpr auto info = static_cast<MEMORY_INFORMATION_CLASS>(MemoryBasicInformationEx);
      const auto address = reinterpret_cast<PVOID>(pos);
      status = ZwQueryVirtualMemory(process_zw, address, info, &mbi, sizeof(mbi), &size);
      if (!NT_SUCCESS(status)) {
        if (status == STATUS_INVALID_PARAMETER) {
          status = STATUS_SUCCESS;
        }
        break;
      }

      // Skip non-committed, non-accessible and guarded regions.
      if (!(mbi.State & MEM_COMMIT) || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) {
        continue;
      }

      // Create regions list entry.
      const auto data = MmAllocateNonCachedMemory(sizeof(region));
      if (!data) {
        status = STATUS_NO_MEMORY;
        break;
      }

      // Copy region information to regions list entry.
      new (data) region{
        nullptr,
        reinterpret_cast<UINT_PTR>(mbi.BaseAddress),
        reinterpret_cast<UINT_PTR>(mbi.AllocationBase),
        mbi.AllocationProtect,
        mbi.RegionSize,
        mbi.State,
        mbi.Protect,
        mbi.Type,
      };

      // Push regions list entry.
      InterlockedPushEntrySList(&regions, static_cast<region*>(data));
    }

    // Detach from process.
    KeUnstackDetachProcess(&state);

    // Move regions information to application memory.
    for (auto entry = InterlockedFlushSList(&regions); entry;) {
      if (NT_SUCCESS(status)) {
        PVOID data = nullptr;
        SIZE_T size = sizeof(region);
        constexpr ULONG type = MEM_RESERVE | MEM_COMMIT;
        constexpr ULONG protect = PAGE_READWRITE;
        status = ZwAllocateVirtualMemory(application, &data, 0, &size, type, protect);
        if (!NT_SUCCESS(status)) {
          continue;
        }
        if (!data || size < sizeof(region)) {
          status = STATUS_NO_MEMORY;
          continue;
        }
        new (data) region(*static_cast<region*>(entry));
        InterlockedPushEntrySList(reinterpret_cast<PSLIST_HEADER>(buffer), static_cast<region*>(data));
      }
      const auto next = entry->Next;
      MmFreeNonCachedMemory(static_cast<region*>(entry), sizeof(region));
      entry = next;
    }

    // Free allocated application memory on error.
    if (!NT_SUCCESS(status)) {
      for (auto entry = InterlockedFlushSList(reinterpret_cast<PSLIST_HEADER>(buffer)); entry;) {
        const auto next = entry->Next;
        PVOID data = entry;
        SIZE_T size = 0;
        ZwFreeVirtualMemory(application, &data, &size, MEM_RELEASE);
        entry = next;
      }
      return std::unexpected(status);
    }
    return osize;
  }

  result scan(PVOID buffer, ULONG osize) noexcept
  {
    // Validate parameters.
    if (!buffer) {
      return std::unexpected(STATUS_INVALID_USER_BUFFER);
    }
    if (osize <= sizeof(deus::scan)) {
      return std::unexpected(STATUS_INVALID_BUFFER_SIZE);
    }

    const auto scan = reinterpret_cast<deus::scan*>(buffer);
    const auto begin = reinterpret_cast<BYTE*>(scan->begin);
    const auto end = reinterpret_cast<BYTE*>(scan->end);
    const auto size = scan->size;
    const auto data = reinterpret_cast<BYTE*>(scan + 1);
    const auto mask = osize == sizeof(deus::scan) + size * 2 ? data + size : nullptr;

    if (!mask && osize != sizeof(deus::scan) + size) {
      return std::unexpected(STATUS_INVALID_BUFFER_SIZE);
    }

    // Validate state.
    const auto process = process_;
    const auto application = application_zw_;
    if (!process || !application) {
      return std::unexpected(STATUS_INVALID_DEVICE_STATE);
    }

    // Attach to process.
    KAPC_STATE state = {};
    KeStackAttachProcess(process, &state);
    const auto process_zw = ZwCurrentProcess();

    // Search for the signature.
    UINT_PTR pos = deus::npos;
    NTSTATUS status = STATUS_SUCCESS;

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
      if (const auto it = std::search(begin, end, searcher); it != end) {
        pos = reinterpret_cast<UINT_PTR>(it);
      }
    } else {
      //const auto searcher = std::boyer_moore_horspool_searcher(data, data + size);
      const auto searcher = boost::algorithm::boyer_moore_horspool(data, data + size);
      //const auto searcher = std::default_searcher(data, data + size);
      if (const auto it = std::search(begin, end, searcher); it != end) {
        pos = reinterpret_cast<UINT_PTR>(it);
      }
    }

    // Detach from process.
    KeUnstackDetachProcess(&state);

    // Verify result.
    if (!NT_SUCCESS(status)) {
      return std::unexpected(status);
    }
    scan->pos = pos;
    return osize;
  }

  result copy(PVOID buffer, ULONG osize, bool read) noexcept
  {
    // Validate parameters.
    if (!buffer) {
      return std::unexpected(STATUS_INVALID_USER_BUFFER);
    }
    if (osize != sizeof(deus::copy)) {
      return std::unexpected(STATUS_INVALID_BUFFER_SIZE);
    }

    // Validate data.
    const auto copy = reinterpret_cast<deus::copy*>(buffer);
    if (copy->src < memory::min || copy->dst < memory::min) {
      return std::unexpected(STATUS_INVALID_PARAMETER);
    }
    if (copy->src + copy->size > memory::max || copy->dst + copy->size > memory::max) {
      return std::unexpected(STATUS_INVALID_PARAMETER);
    }
    const auto src = reinterpret_cast<PVOID>(copy->src);
    const auto dst = reinterpret_cast<PVOID>(copy->dst);

    // Validate state.
    const auto process = process_;
    const auto application = application_ps_;
    if (!process || !application) {
      return std::unexpected(STATUS_INVALID_DEVICE_STATE);
    }

    // Copy memory.
    PEPROCESS sp = read ? process : application;
    PEPROCESS dp = read ? application : process;
    const auto status = MmCopyVirtualMemory(sp, src, dp, dst, copy->size, KernelMode, &copy->copied);
    if (!NT_SUCCESS(status)) {
      return std::unexpected(status);
    }
    return osize;
  }

  result watch(PVOID buffer, ULONG isize) noexcept
  {
    // Validate parameters.
    if (!buffer) {
      return std::unexpected(STATUS_INVALID_USER_BUFFER);
    }
    if (isize < sizeof(deus::copy) || isize % sizeof(deus::copy) != 0) {
      return std::unexpected(STATUS_INVALID_BUFFER_SIZE);
    }

    // Stop watching.
    stop();

    // Start watching.
    watch_copy_ = static_cast<deus::copy*>(MmAllocateNonCachedMemory(isize));
    if (!watch_copy_) {
      return std::unexpected(STATUS_NO_MEMORY);
    }
    std::memcpy(watch_copy_, buffer, isize);
    watch_size_ = isize / sizeof(deus::copy);
    return 0;
  }

  result update() noexcept
  {
    // Validate state.
    if (!watch_copy_) {
      return std::unexpected(STATUS_INVALID_DEVICE_STATE);
    }

    // Copy memory.
    for (auto& e : std::span(watch_copy_, watch_size_)) {
      if (const auto rv = copy(&e, sizeof(deus::copy), true); !rv) {
        return rv;
      }
    }
    return 0;
  }

  result stop() noexcept
  {
    // Validate state.
    if (!watch_copy_) {
      return std::unexpected(STATUS_INVALID_DEVICE_STATE);
    }

    // Stop watching.
    MmFreeNonCachedMemory(watch_copy_, sizeof(deus::copy) * watch_size_);
    watch_copy_ = nullptr;
    watch_size_ = 0;
    return 0;
  }

  UNICODE_STRING device_name_{};
  UNICODE_STRING symbolic_link_name_{};
  PDEVICE_OBJECT device_{ nullptr };
  LONG64 lock_{ 0 };

  PEPROCESS application_ps_{ nullptr };
  HANDLE application_zw_{ nullptr };
  HANDLE application_nt_{ nullptr };

  deus::copy* watch_copy_{ nullptr };
  size_t watch_size_{ 0 };

  PEPROCESS process_{ 0 };
};

static device driver;

}  // namespace deus

extern "C" DRIVER_DISPATCH DriverDispatch;
NTSTATUS DriverDispatch(PDEVICE_OBJECT device, PIRP irp)
{
  irp->IoStatus.Information = 0;
  irp->IoStatus.Status = STATUS_SUCCESS;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return STATUS_SUCCESS;
}

extern "C" DRIVER_DISPATCH DriverCreate;
NTSTATUS DriverCreate(PDEVICE_OBJECT device, PIRP irp)
{
  irp->IoStatus.Information = 0;
  irp->IoStatus.Status = deus::driver.create();
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return irp->IoStatus.Status;
}

extern "C" DRIVER_DISPATCH DriverCleanup;
NTSTATUS DriverCleanup(PDEVICE_OBJECT device, PIRP irp)
{
  deus::driver.cleanup();
  irp->IoStatus.Information = 0;
  irp->IoStatus.Status = STATUS_SUCCESS;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return STATUS_SUCCESS;
}

extern "C" DRIVER_DISPATCH DriverDeviceControl;
NTSTATUS DriverDeviceControl(PDEVICE_OBJECT device, PIRP irp)
{
  if (const auto result = deus::driver.control(irp)) {
    irp->IoStatus.Information = *result;
    irp->IoStatus.Status = STATUS_SUCCESS;
  } else {
    irp->IoStatus.Information = 0;
    irp->IoStatus.Status = result.error();
  }
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return irp->IoStatus.Status;
}

extern "C" DRIVER_UNLOAD DriverUnload;
VOID DriverUnload(PDRIVER_OBJECT driver)
{
  deus::driver.reset();
}

extern "C" DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
  // Register dispatch callbacks.
  for (unsigned int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
    driver->MajorFunction[i] = DriverDispatch;
  }
  driver->MajorFunction[IRP_MJ_CREATE] = DriverCreate;
  driver->MajorFunction[IRP_MJ_CLEANUP] = DriverCleanup;
  driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControl;

  // Register unload callback.
  driver->DriverUnload = DriverUnload;

  // Initialize driver.
  auto status = deus::driver.initialize(driver);
  if (!NT_SUCCESS(status)) {
    deus::driver.reset();
  }
  return status;
}