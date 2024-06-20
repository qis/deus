#pragma once
#include <ntifs.h>

extern "C" {

// clang-format off

typedef unsigned char BYTE;
typedef BYTE* PBYTE;

NTKERNELAPI NTSTATUS NTAPI IoCreateDriver(
  IN PUNICODE_STRING DriverName,
  IN PDRIVER_INITIALIZE InitializationFunction OPTIONAL);

NTKERNELAPI VOID NTAPI IoDeleteDriver(
  IN PDRIVER_OBJECT DriverObject);

NTKERNELAPI NTSTATUS NTAPI ObReferenceObjectByName(
  IN PUNICODE_STRING ObjectPath,
  IN ULONG Attributes,
  IN PACCESS_STATE PassedAccessState OPTIONAL,
  IN ACCESS_MASK DesiredAccess OPTIONAL,
  IN POBJECT_TYPE ObjectType,
  IN KPROCESSOR_MODE AccessMode,
  IN OUT PVOID ParseContext OPTIONAL,
  OUT PVOID* ObjectPtr);

NTKERNELAPI NTSTATUS NTAPI MmCopyVirtualMemory(
  IN PEPROCESS FromProcess,
  IN PVOID FromAddress,
  IN PEPROCESS ToProcess,
  OUT PVOID ToAddress,
  IN SIZE_T BufferSize,
  IN KPROCESSOR_MODE PreviousMode,
  OUT PSIZE_T NumberOfBytesCopied);

typedef enum _SYSTEM_INFORMATION_CLASS {
  SystemProcessInformation = 5,
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
  ULONG NextEntryOffset;
  ULONG NumberOfThreads;
  BYTE Reserved1[48];
  UNICODE_STRING ImageName;
  KPRIORITY BasePriority;
  HANDLE UniqueProcessId;
  PVOID Reserved2;
  ULONG HandleCount;
  ULONG SessionId;
  PVOID Reserved3;
  SIZE_T PeakVirtualSize;
  SIZE_T VirtualSize;
  ULONG Reserved4;
  SIZE_T PeakWorkingSetSize;
  SIZE_T WorkingSetSize;
  PVOID Reserved5;
  SIZE_T QuotaPagedPoolUsage;
  PVOID Reserved6;
  SIZE_T QuotaNonPagedPoolUsage;
  SIZE_T PagefileUsage;
  SIZE_T PeakPagefileUsage;
  SIZE_T PrivatePageCount;
  LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

NTKERNELAPI NTSTATUS NTAPI ZwQuerySystemInformation(
  IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
  IN OUT PVOID SystemInformation,
  IN ULONG SystemInformationLength,
  OUT PULONG ReturnLength OPTIONAL);

typedef enum _MEMORY_INFORMATION_CLASS_EX {
  MemoryBasicInformationEx = 0,
  MemoryWorkingSetInformation = 1,
  MemoryMappedFilenameInformation = 2,
  MemoryRegionInformation = 3,
  MemoryWorkingSetExInformation = 4,
} MEMORY_INFORMATION_CLASS_EX;

// clang-format on

}  // extern "C"