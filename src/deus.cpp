#include "deus.hpp"
#include <ntdll.hpp>

#define DEUS_STOP_ON_COPY_ERROR 0

#define DEUS_DRIVER_NAME L"\\Driver\\Deus"
#define DEUS_DRIVER_SHUTDOWN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_NEITHER, FILE_ANY_ACCESS)

#define DEUS_KEYBOARD_NAME L"\\Device\\DeusKeyboard"
#define DEUS_POINTER_NAME L"\\Device\\DeusPointer"

// reg query HKLM\HARDWARE\DeviceMap\KeyboardClass
#define DEUS_KEYBOARD_CLASS_NAME L"\\Device\\KeyboardClass0"

// reg query HKLM\HARDWARE\DeviceMap\PointerClass
#define DEUS_POINTER_CLASS_NAME L"\\Device\\PointerClass0"

static DRIVER_DISPATCH OnKeyboardRead;
static DRIVER_DISPATCH OnPointerRead;

namespace deus {
namespace {

template <class F>
class scope_exit {
public:
  explicit scope_exit(const F& f) noexcept : f_{ f } {}

  scope_exit(scope_exit&& other) = delete;
  scope_exit(const scope_exit& other) = delete;

  scope_exit& operator=(scope_exit&&) = delete;
  scope_exit& operator=(const scope_exit&) = delete;

  ~scope_exit() noexcept
  {
    f_();
  }

private:
  F f_;
};

PVOID FindDeviceNode(PDEVICE_OBJECT device)
{
  if (device->DeviceObjectExtension->DeviceNode) {
    return device->DeviceObjectExtension->DeviceNode;
  }
  if (device->DeviceObjectExtension->AttachedTo) {
    return FindDeviceNode(device->DeviceObjectExtension->AttachedTo);
  }
  return nullptr;
}

}  // namespace

class device {
public:
  device() = default;
  device(device&& other) = delete;
  device(const device& other) = delete;
  device& operator=(device&& other) = delete;
  device& operator=(const device& other) = delete;
  ~device() = default;

  NTSTATUS initialize(PDRIVER_OBJECT driver)
  {
    auto status = STATUS_SUCCESS;

    // Create control device.
    PDEVICE_OBJECT device{};
    UNICODE_STRING device_name{};
    RtlInitUnicodeString(&device_name, DEUS_DEVICE_NAME);
    status = IoCreateDevice(driver, 0, &device_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, TRUE, &device);
    if (!NT_SUCCESS(status)) {
      DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[DEUS] 0x%08X Could not create control device.\r\n", status);
      return status;
    }
    if (!device) {
      DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[DEUS] Could not create control device.\r\n");
      return STATUS_UNEXPECTED_IO_ERROR;
    }
    device->Flags |= DO_BUFFERED_IO;
    device->Flags |= DO_DIRECT_IO;
    const scope_exit control_cleanup([&]() {
      if (device) {
        IoDeleteDevice(device);
        device = nullptr;
      }
    });

    // Get or create keyboard device.
    PDEVICE_OBJECT keyboard{};
    UNICODE_STRING keyboard_name{};
    RtlInitUnicodeString(&keyboard_name, DEUS_KEYBOARD_NAME);
    status = IoCreateDevice(driver, 0, &keyboard_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &keyboard);
    if (!NT_SUCCESS(status)) {
      DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[DEUS] 0x%08X Could not create keyboard device.\r\n", status);
      return status;
    }
    if (!keyboard) {
      DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[DEUS] Could not create keyboard device.\r\n");
      return STATUS_UNEXPECTED_IO_ERROR;
    }
    keyboard->Flags |= DO_BUFFERED_IO;
    keyboard->Flags &= ~DO_DEVICE_INITIALIZING;
    const scope_exit keyboard_cleanup([&]() {
      if (keyboard) {
        IoDeleteDevice(keyboard);
        keyboard = nullptr;
      }
    });

    // Get or create pointer device.
    PDEVICE_OBJECT pointer{};
    UNICODE_STRING pointer_name{};
    RtlInitUnicodeString(&pointer_name, DEUS_POINTER_NAME);
    status = IoCreateDevice(driver, 0, &pointer_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pointer);
    if (!NT_SUCCESS(status)) {
      DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[DEUS] 0x%08X Could not create pointer device.\r\n", status);
      return status;
    }
    if (!pointer) {
      DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[DEUS] Could not create pointer device.\r\n");
      return STATUS_UNEXPECTED_IO_ERROR;
    }
    pointer->Flags |= DO_BUFFERED_IO;
    pointer->Flags &= ~DO_DEVICE_INITIALIZING;
    const scope_exit pointer_cleanup([&]() {
      if (pointer) {
        IoDeleteDevice(pointer);
        pointer = nullptr;
      }
    });

    // Get keyboard device chain.
    PDEVICE_OBJECT keyboard_target{};
    PFILE_OBJECT keyboard_target_file_object{};
    UNICODE_STRING keyboard_target_class_name{};
    RtlInitUnicodeString(&keyboard_target_class_name, DEUS_KEYBOARD_CLASS_NAME);
    status = IoGetDeviceObjectPointer(&keyboard_target_class_name, 0, &keyboard_target_file_object, &keyboard_target);
    if (!NT_SUCCESS(status)) {
      DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[DEUS] 0x%08X Could not get the keyboard device chain.\r\n", status);
      return status;
    }
    if (!keyboard_target) {
      DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[DEUS] Could not get the keyboard device chain.\r\n");
      return STATUS_UNEXPECTED_IO_ERROR;
    }
    const scope_exit keyboard_target_cleanup([&]() {
      if (keyboard_target) {
        ObDereferenceObject(keyboard_target);
        keyboard_target = nullptr;
      }
    });

    // Get pointer device chain.
    PDEVICE_OBJECT pointer_target{};
    PFILE_OBJECT pointer_target_file_object{};
    UNICODE_STRING pointer_target_class_name{};
    RtlInitUnicodeString(&pointer_target_class_name, DEUS_POINTER_CLASS_NAME);
    status = IoGetDeviceObjectPointer(&pointer_target_class_name, 0, &pointer_target_file_object, &pointer_target);
    if (!NT_SUCCESS(status)) {
      DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[DEUS] 0x%08X Could not get the pointer device chain.\r\n", status);
      return status;
    }
    if (!pointer_target) {
      DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[DEUS] Could not get the pointer device chain.\r\n");
      return STATUS_UNEXPECTED_IO_ERROR;
    }
    const scope_exit pointer_target_cleanup([&]() {
      if (pointer_target) {
        ObDereferenceObject(pointer_target);
        pointer_target = nullptr;
      }
    });

    // Add keyboard device to the keyboard device chain and hook it.
    if (const auto device_node = FindDeviceNode(keyboard_target)) {
      keyboard->DeviceObjectExtension->DeviceNode = device_node;
      keyboard_target->DriverObject->DriverExtension->AddDevice(keyboard_target->DriverObject, keyboard);
      keyboard_read_ = keyboard_target->DriverObject->MajorFunction[IRP_MJ_READ];
      keyboard_target->DriverObject->MajorFunction[IRP_MJ_READ] = OnKeyboardRead;
    }

    // Add pointer device to the pointer device chain and hook it.
    if (const auto device_node = FindDeviceNode(pointer_target)) {
      pointer->DeviceObjectExtension->DeviceNode = device_node;
      pointer_target->DriverObject->DriverExtension->AddDevice(pointer_target->DriverObject, pointer);
      pointer_read_ = pointer_target->DriverObject->MajorFunction[IRP_MJ_READ];
      pointer_target->DriverObject->MajorFunction[IRP_MJ_READ] = OnPointerRead;
    }

    // Assign pointer target device.
    pointer_target_ = pointer_target;
    pointer_target = nullptr;

    // Assign keyboard target device.
    keyboard_target_ = keyboard_target;
    keyboard_target = nullptr;

    // Assign pointer device.
    pointer_ = pointer;
    pointer = nullptr;

    // Assign keyboard device.
    keyboard_ = keyboard;
    keyboard = nullptr;

    // Assign control device.
    device_ = device;
    device = nullptr;

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[DEUS] Created driver version 0x%08X.\r\n", io::version);
    return status;
  }

  NTSTATUS shutdown()
  {
    // Release pointer target device.
    if (pointer_target_) {
      if (pointer_read_) {
        pointer_target_->DriverObject->MajorFunction[IRP_MJ_READ] = pointer_read_;
        pointer_read_ = nullptr;
      }
      ObDereferenceObject(pointer_target_);
      pointer_target_ = nullptr;
    }

    // Release keyboard target device.
    if (keyboard_target_) {
      if (keyboard_read_) {
        keyboard_target_->DriverObject->MajorFunction[IRP_MJ_READ] = keyboard_read_;
        keyboard_read_ = nullptr;
      }
      ObDereferenceObject(keyboard_target_);
      keyboard_target_ = nullptr;
    }

    // Delete pointer device.
    if (pointer_) {
      IoDeleteDevice(pointer_);
      pointer_ = nullptr;
    }

    // Delete keyboard device.
    if (keyboard_) {
      IoDeleteDevice(keyboard_);
      keyboard_ = nullptr;
    }

    // Release control device.
    if (device_) {
      ObDereferenceObject(device_);
      device_ = nullptr;
    }

    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_INFO_LEVEL, "[DEUS] Deleted driver version 0x%08X.\r\n", io::version);
    return STATUS_SUCCESS;
  }

  NTSTATUS query(HANDLE pid, UINT_PTR min, UINT_PTR max, PSLIST_HEADER regions)
  {
    // Validate parameters.
    if (!pid || min < io::memory::min || max > io::memory::max || !regions) {
      return STATUS_INVALID_PARAMETER;
    }

    // Get client process.
    const auto client = ZwCurrentProcess();

    // Open target process.
    HANDLE process = nullptr;
    OBJECT_ATTRIBUTES attributes{};
    CLIENT_ID cid{ pid, nullptr };
    InitializeObjectAttributes(&attributes, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);
    if (const auto status = ZwOpenProcess(&process, PROCESS_ALL_ACCESS, &attributes, &cid); !NT_SUCCESS(status)) {
      DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[DEUS] 0x%08X Could not open process.\r\n", status);
      return status;
    }
    const scope_exit process_cleanup([process]() {
      ZwClose(process);
    });

    // Scan virtual memory.
    NTSTATUS status = STATUS_SUCCESS;
    MEMORY_BASIC_INFORMATION mbi = {};
    for (auto pos = min; pos < max; pos = reinterpret_cast<ULONG_PTR>(mbi.BaseAddress) + mbi.RegionSize) {
      // Get next region.
      constexpr auto info = static_cast<MEMORY_INFORMATION_CLASS>(MemoryBasicInformationEx);
      status = ZwQueryVirtualMemory(process, reinterpret_cast<PVOID>(pos), info, &mbi, sizeof(mbi), nullptr);
      if (!NT_SUCCESS(status)) {
        if (status == STATUS_INVALID_PARAMETER) {
          status = STATUS_SUCCESS;
        }
        break;
      }

      // Allocate memory for regions list entry.
      PVOID data = nullptr;
      SIZE_T size = sizeof(io::region);
      constexpr ULONG type = MEM_RESERVE | MEM_COMMIT;
      constexpr ULONG protect = PAGE_READWRITE;
      status = ZwAllocateVirtualMemory(client, &data, 0, &size, type, protect);
      if (!NT_SUCCESS(status)) {
        break;
      }
      if (!data || size < sizeof(io::region)) {
        status = STATUS_NO_MEMORY;
        break;
      }

      // Create and push regions list entry.
      const auto region = static_cast<io::region*>(data);
      region->Next = nullptr;
      region->address = reinterpret_cast<UINT_PTR>(mbi.BaseAddress);
      region->allocation_base = reinterpret_cast<UINT_PTR>(mbi.AllocationBase);
      region->allocation_protect = mbi.AllocationProtect;
      region->size = mbi.RegionSize;
      region->state = mbi.State;
      region->protect = mbi.Protect;
      region->type = mbi.Type;
      InterlockedPushEntrySList(regions, region);
    }

    return STATUS_SUCCESS;
  }

  NTSTATUS copy(io::copy* copy)
  {
    // Get client process handle.
    const auto client = PsGetCurrentProcess();

    // Get target process handle.
    PEPROCESS target = nullptr;
    if (const auto status = PsLookupProcessByProcessId(copy->from, &target); !NT_SUCCESS(status)) {
      return status;
    }
    const scope_exit process_cleanup([target]() {
      ObDereferenceObject(target);
    });

    // Execute copy operations.
    const auto begin = copy->operations;
    const auto end = begin + copy->count;
    for (auto op = begin; op != end; ++op) {
      // Ignore uninitialized operations.
      if (!op->bytes) {
        continue;
      }

      // Prepare copy operation.
      op->copied = 0;
      const auto src = reinterpret_cast<PVOID>(op->src);
      const auto dst = reinterpret_cast<PVOID>(op->dst);

      // Execute copy operation.
      const auto status = MmCopyVirtualMemory(target, src, client, dst, op->bytes, KernelMode, &op->copied);

      // Sanitize result and report errors.
      if (!NT_SUCCESS(status) && status != STATUS_PARTIAL_COPY) {
        op->copied = 0;
#if DEUS_STOP_ON_COPY_ERROR
        DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[DEUS] 0x%08X Could not copy memory.\r\n", status);
        return status;
#endif
      }
    }
    return STATUS_SUCCESS;
  }

  NTSTATUS keyboard_read(PDEVICE_OBJECT device, PIRP irp)
  {
    return keyboard_read_(device, irp);
  }

  NTSTATUS pointer_read(PDEVICE_OBJECT device, PIRP irp)
  {
    return pointer_read_(device, irp);
  }

  constexpr PDEVICE_OBJECT control()
  {
    return device_;
  }

private:
  PDEVICE_OBJECT device_{ nullptr };

  PDEVICE_OBJECT keyboard_{ nullptr };
  PDEVICE_OBJECT keyboard_target_{ nullptr };
  PDRIVER_DISPATCH keyboard_read_{ nullptr };

  PDEVICE_OBJECT pointer_{ nullptr };
  PDEVICE_OBJECT pointer_target_{ nullptr };
  PDRIVER_DISPATCH pointer_read_{ nullptr };
};

}  // namespace deus

static deus::device g_device;

static NTSTATUS OnKeyboardRead(PDEVICE_OBJECT device, PIRP irp)
{
  return g_device.keyboard_read(device, irp);
}

static NTSTATUS OnPointerRead(PDEVICE_OBJECT device, PIRP irp)
{
  return g_device.pointer_read(device, irp);
}

static DRIVER_DISPATCH OnDispatch;
static NTSTATUS OnDispatch(PDEVICE_OBJECT device, PIRP irp)
{
  UNREFERENCED_PARAMETER(device);
  irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return STATUS_NOT_SUPPORTED;
}

static DRIVER_DISPATCH OnInternalDeviceControl;
static NTSTATUS OnInternalDeviceControl(PDEVICE_OBJECT device, PIRP irp)
{
  UNREFERENCED_PARAMETER(device);
  auto status = irp->IoStatus.Status;
  if (const auto stack = IoGetCurrentIrpStackLocation(irp)) {
    switch (stack->Parameters.DeviceIoControl.IoControlCode) {
    case DEUS_DRIVER_SHUTDOWN:
      status = g_device.shutdown();
      break;
    }
  }
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return status;
}

static DRIVER_DISPATCH OnDeviceControl;
static NTSTATUS OnDeviceControl(PDEVICE_OBJECT device, PIRP irp)
{
  UNREFERENCED_PARAMETER(device);
  auto status = STATUS_SUCCESS;
  if (const auto stack = IoGetCurrentIrpStackLocation(irp)) {
    switch (static_cast<deus::io::code>(stack->Parameters.DeviceIoControl.IoControlCode)) {
    case deus::io::code::version:
      irp->IoStatus.Information = deus::io::version;
      break;
    case deus::io::code::query:
      if (const auto query = static_cast<deus::io::query*>(irp->AssociatedIrp.SystemBuffer)) {
        if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(deus::io::query)) {
          status = g_device.query(query->pid, query->min, query->max, query->regions);
        } else {
          status = STATUS_BUFFER_TOO_SMALL;
        }
      } else {
        status = STATUS_INVALID_USER_BUFFER;
      }
      break;
    case deus::io::code::copy:
      if (const auto copy = static_cast<deus::io::copy*>(stack->Parameters.DeviceIoControl.Type3InputBuffer)) {
        if (stack->Parameters.DeviceIoControl.InputBufferLength == sizeof(deus::io::copy)) {
          status = g_device.copy(copy);
        } else {
          status = STATUS_INVALID_BUFFER_SIZE;
        }
      } else {
        status = STATUS_INVALID_PARAMETER;
      }
      break;
    default:
      status = STATUS_INVALID_PARAMETER;
      break;
    }
  } else {
    status = STATUS_INTERNAL_ERROR;
  }
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return status;
}

static DRIVER_DISPATCH OnCreate;
static NTSTATUS OnCreate(PDEVICE_OBJECT device, PIRP irp)
{
  UNREFERENCED_PARAMETER(device);
  const auto status = irp->IoStatus.Status;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return status;
}

static DRIVER_DISPATCH OnDestroy;
static NTSTATUS OnDestroy(PDEVICE_OBJECT device, PIRP irp)
{
  UNREFERENCED_PARAMETER(device);
  const auto status = irp->IoStatus.Status;
  IoCompleteRequest(irp, IO_NO_INCREMENT);
  return status;
}

static DRIVER_INITIALIZE DriverInitialize;
static NTSTATUS DriverInitialize(PDRIVER_OBJECT driver, PUNICODE_STRING path)
{
  UNREFERENCED_PARAMETER(path);
  auto status = STATUS_SUCCESS;

  // Inivialize driver device object.
  status = g_device.initialize(driver);
  if (!NT_SUCCESS(status)) {
    return status;
  }

  // Register control device dispatch callbacks.
  for (unsigned int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
    driver->MajorFunction[i] = OnDispatch;
  }
  driver->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = OnInternalDeviceControl;
  driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OnDeviceControl;
  driver->MajorFunction[IRP_MJ_CREATE] = OnCreate;
  driver->MajorFunction[IRP_MJ_CLOSE] = OnDestroy;
  driver->DriverUnload = nullptr;

  // Mark control device as initialized.
  g_device.control()->Flags &= ~DO_DEVICE_INITIALIZING;

  return status;
}

static VOID DriverShutdown(PUNICODE_STRING driver_name)
{
  auto status = STATUS_SUCCESS;

  // Initialize driver type name.
  UNICODE_STRING driver_type{};
  RtlInitUnicodeString(&driver_type, L"IoDriverObjectType");

  // Get driver type from name.
  const auto IoDriverObjectType = static_cast<POBJECT_TYPE*>(MmGetSystemRoutineAddress(&driver_type));
  if (!IoDriverObjectType) {
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[DEUS] Could not get driver object type.\r\n");
    return;
  }

  // Get driver from name and type.
  PDRIVER_OBJECT driver = nullptr;
  status = ObReferenceObjectByName(
    driver_name,
    OBJ_KERNEL_HANDLE,
    nullptr,
    0,
    *IoDriverObjectType,
    KernelMode,
    nullptr,
    reinterpret_cast<PVOID*>(&driver));
  if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
    return;
  }
  if (!NT_SUCCESS(status)) {
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[DEUS] 0x%08X Could not get driver object.\r\n", status);
    return;
  }
  if (!driver) {
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[DEUS] Could not get driver object.\r\n");
    return;
  }

  // Initialize device name.
  UNICODE_STRING device_name{};
  RtlInitUnicodeString(&device_name, DEUS_DEVICE_NAME);

  // Get device object from name.
  PDEVICE_OBJECT device{};
  PFILE_OBJECT device_file_object{};
  status = IoGetDeviceObjectPointer(&device_name, 0, &device_file_object, &device);
  if (!NT_SUCCESS(status)) {
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[DEUS] 0x%08X Could not get device object pointer.\r\n", status);
    return;
  }
  if (!device) {
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[DEUS] Could not get device object pointer.\r\n");
    return;
  }

  // Create shutdown request event.
  KEVENT event{};
  KeInitializeEvent(&event, SynchronizationEvent, FALSE);

  // Create shutdown request.
  IO_STATUS_BLOCK isb{};
  constexpr auto code = DEUS_DRIVER_SHUTDOWN;
  const auto irp = IoBuildDeviceIoControlRequest(code, device, nullptr, 0, nullptr, 0, TRUE, &event, &isb);
  if (!irp) {
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[DEUS] Could not build shutdown request.\r\n");
    return;
  }

  // Send shutdown request.
  status = IoCallDriver(device, irp);
  if (status == STATUS_PENDING) {
    KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, nullptr);
    status = isb.Status;
  }
  if (!NT_SUCCESS(status)) {
    DbgPrintEx(DPFLTR_DEFAULT_ID, DPFLTR_ERROR_LEVEL, "[DEUS] 0x%08X Could send shutdown request.\r\n", status);
    return;
  }

  // Delete device.
  IoDeleteDevice(device);

  // Delete driver.
  IoDeleteDriver(driver);
}

extern "C" DRIVER_INITIALIZE DriverEntry;
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT, PUNICODE_STRING)
{
  // Initialize driver name.
  UNICODE_STRING driver_name{};
  RtlInitUnicodeString(&driver_name, DEUS_DRIVER_NAME);

  // Shutdown driver.
  DriverShutdown(&driver_name);

  // Initialize driver.
  return IoCreateDriver(&driver_name, &DriverInitialize);
}