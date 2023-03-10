#include <deus.hpp>
#include <shellapi.h>
#include <filesystem>
#include <cstdlib>

EXTERN_C NTSTATUS NTAPI NtLoadDriver(PUNICODE_STRING key);
EXTERN_C NTSTATUS NTAPI NtUnloadDriver(PUNICODE_STRING key);
EXTERN_C NTSTATUS AdjustCiOptions(ULONG CiOptionsValue, PULONG OldCiOptionsValue);

namespace deus {

void request_privileges(PCSTR privileges)
{
  TOKEN_PRIVILEGES privilege = {};
  privilege.PrivilegeCount = 1;
  privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  if (!LookupPrivilegeValue(nullptr, "SeLoadDriverPrivilege", &privilege.Privileges[0].Luid)) {
    throw std::system_error(deus::error(GetLastError()), "LookupPrivilegeValue");
  }
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token)) {
    throw std::system_error(deus::error(GetLastError()), "OpenProcessToken");
  }
  using token_type = std::remove_pointer_t<decltype(token)>;
  std::unique_ptr<token_type, decltype(&CloseHandle)> token_ptr(token, CloseHandle);
  if (!AdjustTokenPrivileges(token, FALSE, &privilege, sizeof(privilege), nullptr, nullptr)) {
    throw std::system_error(deus::error(GetLastError()), "AdjustTokenPrivileges");
  }
}

void set(HKEY hkey, std::string name, DWORD value)
{
  const auto data = reinterpret_cast<const BYTE*>(&value);
  const auto size = static_cast<DWORD>(sizeof(value));
  if (const auto ev = RegSetValueExA(hkey, name.data(), 0, REG_DWORD, data, size)) {
    throw std::system_error(deus::error(ev), "RegSetValue: " + name);
  }
}

void set(HKEY hkey, std::string name, std::string value)
{
  const auto data = reinterpret_cast<const BYTE*>(value.data());
  const auto size = static_cast<DWORD>(value.size());
  if (const auto ev = RegSetValueEx(hkey, name.data(), 0, REG_EXPAND_SZ, data, size)) {
    throw std::system_error(deus::error(ev), "RegSetValue: " + name);
  }
}

void install(bool load)
{
  // Create driver source path.
  std::string src;
  DWORD size = 0;
  do {
    src.resize(src.size() + MAX_PATH);
    size = GetModuleFileName(nullptr, src.data(), static_cast<DWORD>(src.size()));
  } while (GetLastError() == ERROR_INSUFFICIENT_BUFFER);
  src.resize(size);
  src = (std::filesystem::canonical(src).parent_path() / "deus.sys").string();
  if (!std::filesystem::is_regular_file(src)) {
    throw std::runtime_error("Could not find deus.sys.");
  }

  // Create driver destination path.
  std::string dst;
  dst.resize(GetSystemDirectory(dst.data(), 0) + 1);
  dst.resize(GetSystemDirectory(dst.data(), static_cast<UINT>(dst.size())));
  if (dst.empty()) {
    throw std::runtime_error("Could not get system directory.");
  }
  dst = (std::filesystem::canonical(dst) / "drivers").string();
  if (!std::filesystem::is_directory(dst)) {
    throw std::runtime_error("Could not get system drivers directory.");
  }
  dst = (std::filesystem::canonical(dst) / "deus.sys").string();

  // Request privileges to load drivers.
  request_privileges("SeLoadDriverPrivilege");

  // Create driver registry key path.
  std::string sub = "System\\CurrentControlSet\\Services\\deus";
  std::wstring key = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\deus";

  UNICODE_STRING path = {};
  RtlInitUnicodeString(&path, key.data());

  // Unload driver.
  NtUnloadDriver(&path);

  // Create registry variables.
  const HKEY root = HKEY_LOCAL_MACHINE;
  constexpr REGSAM sa = KEY_ALL_ACCESS;

  // Delete registry key.
  HKEY hkey = nullptr;
  if (RegOpenKeyEx(root, sub.data(), 0, KEY_ALL_ACCESS, &hkey) == ERROR_SUCCESS) {
    RegCloseKey(hkey);
    if (const auto ev = RegDeleteKeyEx(root, sub.data(), KEY_WOW64_64KEY, 0)) {
      throw std::system_error(deus::error(ev), "RegDeleteKeyEx");
    }
  }

  // Delete file.
  if (GetFileAttributes(dst.data()) != INVALID_FILE_ATTRIBUTES) {
    if (!DeleteFile(dst.data())) {
      throw std::system_error(deus::error(GetLastError()), "DeleteFile: " + dst);
    }
  }

  // Return if only a driver unload was requested.
  if (!load) {
    return;
  }

  // Create file.
  if (!CopyFile(src.data(), dst.data(), TRUE)) {
    throw std::system_error(deus::error(GetLastError()), "CopyFile: " + src + " -> " + dst);
  }

  // Create registry key.
  DWORD disp = 0;
  if (const auto ev = RegCreateKeyEx(root, sub.data(), 0, nullptr, 0, sa, NULL, &hkey, &disp)) {
    throw std::system_error(deus::error(ev), "RegCreateKeyEx");
  }
  std::unique_ptr<std::remove_pointer_t<HKEY>, decltype(&RegCloseKey)> sub_ptr(hkey, RegCloseKey);
  set(hkey, "ErrorControl", 0);
  set(hkey, "ImagePath", "\\??\\" + dst);
  set(hkey, "Start", 3);
  set(hkey, "Type", 1);
  sub_ptr.reset();

  // Disable DSE.
  ULONG OldCiOptionsValue = 0;
  if (const auto ev = AdjustCiOptions(0, &OldCiOptionsValue)) {
    throw std::system_error(deus::error(ev), "AdjustCiOptions");
  }

  // Load driver.
  const auto status = NtLoadDriver(&path);

  // Enable DSE.
  AdjustCiOptions(0x6, &OldCiOptionsValue);

  // Report errors.
  if (!NT_SUCCESS(status)) {
    throw std::system_error(deus::error(status), "NtLoadDriver");
  }
}

}  // namespace deus

int WINAPI WinMain(_In_ HINSTANCE instance, _In_opt_ HINSTANCE, _In_ LPSTR cmd, _In_ int show)
{
  try {
    // Unload driver.
    if (cmd && std::string_view(cmd) == "unload") {
      deus::install(false);
      return EXIT_SUCCESS;
    }

    // Create device.
    deus::device device;
    if (const auto rv = device.create(); !rv) {
      const auto ev = rv.error().value();
      if (ev != ERROR_FILE_NOT_FOUND && ev != ERROR_REMOTE_FILE_VERSION_MISMATCH) {
        throw std::system_error(rv.error(), "create");
      }
    } else {
      return EXIT_SUCCESS;
    }

    // Load driver.
    deus::install(true);

    // Verify device.
    if (const auto rv = device.create(); !rv) {
      throw std::system_error(rv.error(), "verify");
    }
  }
  catch (const std::system_error& e) {
    const auto name = e.code().category().name();
    const auto text = std::format("Could not load driver.\r\n\r\n{} {}", name, e.what());
    MessageBox(nullptr, text.data(), "DEUS Load Error", MB_OK);
    return EXIT_FAILURE;
  }
  catch (const std::exception& e) {
    const auto text = std::format("Could not load driver.\r\n\r\n{}", e.what());
    MessageBox(nullptr, text.data(), "DEUS Load Error", MB_OK);
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}