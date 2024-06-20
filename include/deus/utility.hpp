#pragma once
#include <deus/error.hpp>
#include <deus/result.hpp>
#include <winternl.h>
#include <string_view>
#include <vector>

namespace deus {

inline result<std::vector<HANDLE>> find_process(PUNICODE_STRING name, bool ignore_case = true) noexcept
{
  const auto ntdll = GetModuleHandleW(L"ntdll.dll");
  if (!ntdll) {
    return error(make_error_code(GetLastError()));
  }
  const auto RtlEqualUnicodeStringPtr = GetProcAddress(ntdll, "RtlEqualUnicodeString");
  if (!RtlEqualUnicodeStringPtr) {
    return error(make_error_code(GetLastError()));
  }

  using RtlEqualUnicodeStringProc = BOOLEAN(WINAPI*)(PCUNICODE_STRING, PCUNICODE_STRING, BOOLEAN);
  const auto RtlEqualUnicodeString = reinterpret_cast<RtlEqualUnicodeStringProc>(RtlEqualUnicodeStringPtr);

  ULONG size = 0;
  std::vector<BYTE> buffer;
  NTSTATUS status = STATUS_SUCCESS;
  do {
    buffer.resize(size);
    status = NtQuerySystemInformation(SystemProcessInformation, buffer.data(), size, &size);
  } while (status == STATUS_INFO_LENGTH_MISMATCH);
  if (!NT_SUCCESS(status)) {
    return error(make_error_code(status));
  }
  std::vector<HANDLE> pids;
  for (auto info = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(buffer.data()); info;) {
    if (RtlEqualUnicodeString(&info->ImageName, name, ignore_case ? TRUE : FALSE)) {
      pids.emplace_back(info->UniqueProcessId);
    }
    if (!info->NextEntryOffset) {
      break;
    }
    const auto next = reinterpret_cast<PBYTE>(info) + info->NextEntryOffset;
    info = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(next);
  }
  return pids;
}

inline result<std::vector<HANDLE>> find_process(std::wstring_view name, bool ignore_case = true) noexcept
{
  const auto size = static_cast<USHORT>(name.size() * sizeof(wchar_t));
  UNICODE_STRING uname{ size, size, const_cast<wchar_t*>(name.data()) };
  return find_process(&uname, ignore_case);
}

inline result<std::vector<HANDLE>> find_process(std::string_view name, bool ignore_case = true) noexcept
{
  const auto size = static_cast<int>(name.size());
  auto wsize = MultiByteToWideChar(CP_UTF8, 0, name.data(), size, nullptr, 0);
  if (!wsize) {
    return std::unexpected(make_error_code(GetLastError()));
  }
  std::wstring wname(static_cast<std::size_t>(wsize) + 1, L'\0');
  wsize = MultiByteToWideChar(CP_UTF8, 0, name.data(), size, wname.data(), wsize + 1);
  if (!wsize) {
    return std::unexpected(make_error_code(GetLastError()));
  }
  wname.resize(static_cast<std::size_t>(wsize));
  return find_process(wname, ignore_case);
}

}  // namespace deus