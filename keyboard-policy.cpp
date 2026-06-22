// keyboard-policy.cpp
//
// Goal: Toggle Windows "Device Installation Restrictions" for keyboards via CLI.
//
// What this tool does (policy-based, not driver-based):
// - protect on  : Enable policy to block *new* keyboard-class device installs/updates.
// - protect off : Disable the policy toggles (leaves lists in place but inert).
// - allow/deny  : Maintain allow/deny lists by *device instance ID*.
// - nuke --yes  : Delete the entire registry policy key: ...\DeviceInstall\Restrictions
//                 (this removes *all* changes this tool made under Restrictions).
//
// Registry (policy-backed) path:
//   HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions
//
// Why "Retroactive=0" matters:
// - With Retroactive = 0, already-installed devices keep working.
// - That’s the main safety property that keeps your internal keyboard working.
//
// Layered evaluation:
// - Microsoft documents that Allow lists are intended to be used with
//   "Apply layered order of evaluation..." (we set AllowDenyLayered=1 when using allow/deny).
// - Also, by default, prevent policies take precedence unless layered evaluation is enabled.
//
// SAFETY NOTES:
// - Must run as Administrator (writes to HKLM\SOFTWARE\Policies).
// - This blocks installation/updates for certain devices; it does not "block keypresses" from
//   already-installed keyboards.
// - On Windows 11 Home, policy keys are often honored, but you should test on your machine.

#define UNICODE
#define _UNICODE

#include <windows.h>
#include <setupapi.h>
#include <devguid.h>     // GUID_DEVCLASS_KEYBOARD for list-present
#include <iostream>
#include <string>
#include <vector>
#include <cwchar>        // _wcsicmp

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "setupapi.lib")

// Base policy key this program manages.
static const wchar_t* kRestrictionsKey =
L"SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions";

// Parent key used for "nuke" (so we can delete Restrictions recursively).
static const wchar_t* kDeviceInstallKey =
L"SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall";

// Keyboard setup class GUID (string form).
// Microsoft lists Keyboard class GUID as 4d36e96b-e325-11ce-bfc1-08002be10318.
static const wchar_t* kKeyboardSetupClassGuid =
L"{4d36e96b-e325-11ce-bfc1-08002be10318}";

// ---- Error handling helpers -------------------------------------------------

// Track the last meaningful Win32 error code from registry APIs (LSTATUS).
// NOTE: Many registry APIs return an error code directly and do NOT set GetLastError().
static DWORD g_lastWin32 = ERROR_SUCCESS;

static std::wstring WinErrMsg(DWORD e) {
    wchar_t* buf = nullptr;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, e, 0, (LPWSTR)&buf, 0, nullptr);
    std::wstring s = buf ? buf : L"";
    if (buf) LocalFree(buf);
    return s;
}

// ---- Admin check ------------------------------------------------------------

static bool IsRunningAsAdmin() {
    // Standard "is member of Administrators" check.
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &adminGroup)) {
        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin == TRUE;
}

// ---- Registry open helpers --------------------------------------------------

// Always use 64-bit view so you write to the "real" policy location on 64-bit Windows.
static LSTATUS OpenOrCreateKey64(HKEY root, const std::wstring& subkey, REGSAM access, HKEY* out) {
    LSTATUS s = RegCreateKeyExW(root, subkey.c_str(), 0, nullptr, 0,
        access | KEY_WOW64_64KEY, nullptr, out, nullptr);
    g_lastWin32 = (DWORD)s;
    return s;
}

static LSTATUS OpenKey64(HKEY root, const std::wstring& subkey, REGSAM access, HKEY* out) {
    LSTATUS s = RegOpenKeyExW(root, subkey.c_str(), 0, access | KEY_WOW64_64KEY, out);
    g_lastWin32 = (DWORD)s;
    return s;
}

// ---- DWORD policy read/write ------------------------------------------------

static bool SetDWORD(const std::wstring& name, DWORD value) {
    HKEY h{};
    if (OpenOrCreateKey64(HKEY_LOCAL_MACHINE, kRestrictionsKey, KEY_SET_VALUE, &h) != ERROR_SUCCESS) return false;

    LSTATUS s = RegSetValueExW(h, name.c_str(), 0, REG_DWORD,
        reinterpret_cast<const BYTE*>(&value), sizeof(value));
    g_lastWin32 = (DWORD)s;
    RegCloseKey(h);
    return s == ERROR_SUCCESS;
}

static bool GetDWORD(const std::wstring& name, DWORD& outVal) {
    HKEY h{};
    if (OpenKey64(HKEY_LOCAL_MACHINE, kRestrictionsKey, KEY_QUERY_VALUE, &h) != ERROR_SUCCESS) return false;

    DWORD type = 0, data = 0, cb = sizeof(data);
    LSTATUS s = RegGetValueW(h, nullptr, name.c_str(), RRF_RT_REG_DWORD, &type, &data, &cb);
    g_lastWin32 = (DWORD)s;
    RegCloseKey(h);
    if (s != ERROR_SUCCESS) return false;

    outVal = data;
    return true;
}

// ---- List subkeys (REG_SZ values) ------------------------------------------
//
// Lists are stored as subkeys under Restrictions, with REG_SZ values named "1","2",...
// Example:
//   ...\Restrictions\DenyDeviceClasses\ "1"="{GUID}"

static bool EnsureListKey(const std::wstring& listName) {
    HKEY h{};
    std::wstring path = std::wstring(kRestrictionsKey) + L"\\" + listName;
    LSTATUS s = OpenOrCreateKey64(HKEY_LOCAL_MACHINE, path, KEY_SET_VALUE, &h);
    if (s == ERROR_SUCCESS) RegCloseKey(h);
    return s == ERROR_SUCCESS;
}

static std::vector<std::pair<std::wstring, std::wstring>> ReadList(const std::wstring& listName) {
    std::vector<std::pair<std::wstring, std::wstring>> out;

    HKEY h{};
    std::wstring path = std::wstring(kRestrictionsKey) + L"\\" + listName;
    if (OpenKey64(HKEY_LOCAL_MACHINE, path, KEY_QUERY_VALUE, &h) != ERROR_SUCCESS) return out;

    for (DWORD idx = 0;; idx++) {
        wchar_t name[256];
        DWORD nameLen = (DWORD)std::size(name);

        wchar_t data[4096];
        DWORD dataLen = sizeof(data);

        DWORD type = 0;
        LSTATUS s = RegEnumValueW(h, idx, name, &nameLen, nullptr, &type,
            reinterpret_cast<LPBYTE>(data), &dataLen);
        if (s == ERROR_NO_MORE_ITEMS) break;
        if (s != ERROR_SUCCESS) continue;

        if (type == REG_SZ) {
            out.push_back({ std::wstring(name, nameLen), std::wstring(data) });
        }
    }

    RegCloseKey(h);
    return out;
}

static bool AddToList(const std::wstring& listName, const std::wstring& entry) {
    if (!EnsureListKey(listName)) return false;

    // If already present (match by data), no-op.
    auto items = ReadList(listName);
    for (auto& it : items) {
        if (_wcsicmp(it.second.c_str(), entry.c_str()) == 0) return true;
    }

    // Find next free numeric value name.
    int next = 1;
    while (true) {
        std::wstring candidate = std::to_wstring(next);
        bool used = false;
        for (auto& it : items) {
            if (it.first == candidate) { used = true; break; }
        }
        if (!used) break;
        next++;
        if (next > 9999) { g_lastWin32 = ERROR_TOO_MANY_NAMES; return false; }
    }

    HKEY h{};
    std::wstring path = std::wstring(kRestrictionsKey) + L"\\" + listName;
    if (OpenKey64(HKEY_LOCAL_MACHINE, path, KEY_SET_VALUE, &h) != ERROR_SUCCESS) return false;

    std::wstring valueName = std::to_wstring(next);
    LSTATUS s = RegSetValueExW(h, valueName.c_str(), 0, REG_SZ,
        reinterpret_cast<const BYTE*>(entry.c_str()),
        (DWORD)((entry.size() + 1) * sizeof(wchar_t)));
    g_lastWin32 = (DWORD)s;
    RegCloseKey(h);
    return s == ERROR_SUCCESS;
}

static bool RemoveFromList(const std::wstring& listName, const std::wstring& entry) {
    HKEY h{};
    std::wstring path = std::wstring(kRestrictionsKey) + L"\\" + listName;
    if (OpenKey64(HKEY_LOCAL_MACHINE, path, KEY_SET_VALUE | KEY_QUERY_VALUE, &h) != ERROR_SUCCESS) return false;

    auto items = ReadList(listName);
    bool removedAny = false;

    for (auto& it : items) {
        if (_wcsicmp(it.second.c_str(), entry.c_str()) == 0) {
            LSTATUS s = RegDeleteValueW(h, it.first.c_str());
            g_lastWin32 = (DWORD)s;
            if (s == ERROR_SUCCESS) removedAny = true;
        }
    }

    RegCloseKey(h);
    return removedAny;
}

// ---- Device enumeration helper ---------------------------------------------
//
// Prints present keyboard device instance IDs (useful for allow/deny strings).
static int ListPresentKeyboards() {
    HDEVINFO info = SetupDiGetClassDevsW(&GUID_DEVCLASS_KEYBOARD, nullptr, nullptr, DIGCF_PRESENT);
    if (info == INVALID_HANDLE_VALUE) {
        std::wcerr << L"SetupDiGetClassDevs failed: " << WinErrMsg(GetLastError()) << L"\n";
        return 1;
    }

    for (DWORD idx = 0;; idx++) {
        SP_DEVINFO_DATA dev{};
        dev.cbSize = sizeof(dev);

        if (!SetupDiEnumDeviceInfo(info, idx, &dev)) {
            DWORD e = GetLastError();
            if (e == ERROR_NO_MORE_ITEMS) break;
            std::wcerr << L"SetupDiEnumDeviceInfo failed: " << WinErrMsg(e) << L"\n";
            break;
        }

        wchar_t idBuf[4096];
        if (SetupDiGetDeviceInstanceIdW(info, &dev, idBuf, (DWORD)std::size(idBuf), nullptr)) {
            std::wcout << idBuf << L"\n";
        }
    }

    SetupDiDestroyDeviceInfoList(info);
    return 0;
}

// ---- Policy operations ------------------------------------------------------

// Enable "block new keyboards" policy (not retroactive).
static bool ProtectOn() {
    // Layered evaluation: allows instance-ID allow rules to override broader prevent rules
    // when configured correctly (per Microsoft docs).
    if (!SetDWORD(L"AllowDenyLayered", 1)) return false;

    // Enable "prevent install of these device setup classes".
    if (!SetDWORD(L"DenyDeviceClasses", 1)) return false;

    // Safety: do NOT apply to already installed devices.
    if (!SetDWORD(L"DenyDeviceClassesRetroactive", 0)) return false;

    // Deny the keyboard setup class by GUID.
    if (!AddToList(L"DenyDeviceClasses", kKeyboardSetupClassGuid)) return false;

    return true;
}

// Disable policy toggles.
// Note: leaves lists in registry but inert (safe and reversible).
static bool ProtectOff() {
    SetDWORD(L"DenyDeviceClasses", 0);
    SetDWORD(L"DenyInstanceIDs", 0);
    SetDWORD(L"DenyDeviceIDs", 0);

    SetDWORD(L"AllowInstanceIDs", 0);
    SetDWORD(L"AllowDeviceIDs", 0);
    SetDWORD(L"AllowDeviceClasses", 0);

    SetDWORD(L"AllowDenyLayered", 0);

    // Keep retroactive flags at 0 (safety).
    SetDWORD(L"DenyDeviceClassesRetroactive", 0);
    SetDWORD(L"DenyDeviceIDsRetroactive", 0);
    SetDWORD(L"DenyInstanceIDsRetroactive", 0);

    return true;
}

static bool AllowAdd(const std::wstring& instanceId) {
    if (!SetDWORD(L"AllowDenyLayered", 1)) return false;
    if (!SetDWORD(L"AllowInstanceIDs", 1)) return false;
    return AddToList(L"AllowInstanceIDs", instanceId);
}

static bool AllowRemove(const std::wstring& instanceId) {
    return RemoveFromList(L"AllowInstanceIDs", instanceId);
}

static bool DenyAdd(const std::wstring& instanceId) {
    if (!SetDWORD(L"AllowDenyLayered", 1)) return false;
    if (!SetDWORD(L"DenyInstanceIDs", 1)) return false;
    return AddToList(L"DenyInstanceIDs", instanceId);
}

static bool DenyRemove(const std::wstring& instanceId) {
    return RemoveFromList(L"DenyInstanceIDs", instanceId);
}

// Delete the entire Restrictions policy subtree.
// This is the "panic button" rollback.
// Uses RegDeleteTreeW to recursively delete subkeys + values.
static bool NukeRestrictions() {
    HKEY hParent{};
    if (OpenKey64(HKEY_LOCAL_MACHINE, kDeviceInstallKey, KEY_WRITE, &hParent) != ERROR_SUCCESS) {
        // If DeviceInstall doesn't exist, nothing to nuke.
        if (g_lastWin32 == ERROR_FILE_NOT_FOUND) return true;
        return false;
    }

    // Delete "Restrictions" under ...\DeviceInstall
    LSTATUS s = RegDeleteTreeW(hParent, L"Restrictions");
    g_lastWin32 = (DWORD)s;
    RegCloseKey(hParent);

    // If not found, consider it already "nuked".
    if (s == ERROR_FILE_NOT_FOUND) return true;

    return s == ERROR_SUCCESS;
}

// ---- UI / CLI ---------------------------------------------------------------

static void PrintStatus() {
    auto show = [&](const wchar_t* n) {
        DWORD v{};
        bool ok = GetDWORD(n, v);
        std::wcout << n << L" = " << (ok ? std::to_wstring(v) : L"(missing)") << L"\n";
        };

    show(L"AllowDenyLayered");
    show(L"DenyDeviceClasses");
    show(L"DenyDeviceClassesRetroactive");
    show(L"AllowInstanceIDs");
    show(L"DenyInstanceIDs");

    auto dc = ReadList(L"DenyDeviceClasses");
    if (!dc.empty()) {
        std::wcout << L"\nDenyDeviceClasses list:\n";
        for (auto& it : dc) std::wcout << L"  [" << it.first << L"] " << it.second << L"\n";
    }

    auto al = ReadList(L"AllowInstanceIDs");
    if (!al.empty()) {
        std::wcout << L"\nAllowInstanceIDs list:\n";
        for (auto& it : al) std::wcout << L"  [" << it.first << L"] " << it.second << L"\n";
    }

    auto dl = ReadList(L"DenyInstanceIDs");
    if (!dl.empty()) {
        std::wcout << L"\nDenyInstanceIDs list:\n";
        for (auto& it : dl) std::wcout << L"  [" << it.first << L"] " << it.second << L"\n";
    }
}

static void Usage() {
    std::wcout <<
        L"Usage:\n"
        L"  keyboard-policy status\n"
        L"  keyboard-policy protect on|off\n"
        L"  keyboard-policy allow add \"<INSTANCE_ID>\"\n"
        L"  keyboard-policy allow remove \"<INSTANCE_ID>\"\n"
        L"  keyboard-policy allow list\n"
        L"  keyboard-policy deny add \"<INSTANCE_ID>\"\n"
        L"  keyboard-policy deny remove \"<INSTANCE_ID>\"\n"
        L"  keyboard-policy deny list\n"
        L"  keyboard-policy list-present\n"
        L"  keyboard-policy nuke --yes\n\n"
        L"Notes:\n"
        L" - Run as Administrator.\n"
        L" - protect on blocks NEW keyboard installs (not retroactive) and should keep internal keyboard working.\n"
        L" - 'nuke --yes' removes the entire policy key ...\\DeviceInstall\\Restrictions.\n";
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) { Usage(); return 0; }

    std::wstring cmd = argv[1];

    // list-present does not require admin; everything else normally does.
    if (cmd != L"list-present" && !IsRunningAsAdmin()) {
        std::wcerr << L"Error: Please run as Administrator.\n";
        return 5;
    }

    if (cmd == L"list-present") return ListPresentKeyboards();
    if (cmd == L"status") { PrintStatus(); return 0; }

    if (cmd == L"protect" && argc >= 3) {
        std::wstring arg = argv[2];
        if (arg == L"on") {
            if (!ProtectOn()) {
                std::wcerr << L"Failed to enable protection: " << WinErrMsg(g_lastWin32) << L"\n";
                return 2;
            }
            std::wcout << L"Protection ON (blocks new keyboard installs). Restart recommended.\n";
            return 0;
        }
        if (arg == L"off") {
            ProtectOff();
            std::wcout << L"Protection OFF. Restart recommended.\n";
            return 0;
        }
    }

    if (cmd == L"nuke") {
        // Hard safety gate: require explicit --yes.
        if (argc < 3 || std::wstring(argv[2]) != L"--yes") {
            std::wcerr << L"Refusing to nuke without explicit confirmation.\n"
                << L"Run: keyboard-policy nuke --yes\n";
            return 6;
        }
        if (!NukeRestrictions()) {
            std::wcerr << L"Failed to nuke Restrictions: " << WinErrMsg(g_lastWin32) << L"\n";
            return 7;
        }
        std::wcout << L"Nuked ...\\DeviceInstall\\Restrictions. Restart recommended.\n";
        return 0;
    }

    if ((cmd == L"allow" || cmd == L"deny") && argc >= 3) {
        std::wstring sub = argv[2];

        if (sub == L"list") {
            auto listName = (cmd == L"allow") ? L"AllowInstanceIDs" : L"DenyInstanceIDs";
            auto items = ReadList(listName);
            for (auto& it : items) std::wcout << it.second << L"\n";
            return 0;
        }

        if ((sub == L"add" || sub == L"remove") && argc >= 4) {
            std::wstring instanceId = argv[3];
            bool ok = false;

            if (cmd == L"allow") ok = (sub == L"add") ? AllowAdd(instanceId) : AllowRemove(instanceId);
            if (cmd == L"deny")  ok = (sub == L"add") ? DenyAdd(instanceId) : DenyRemove(instanceId);

            if (!ok) {
                std::wcerr << L"Operation failed: " << WinErrMsg(g_lastWin32) << L"\n";
                return 3;
            }
            std::wcout << L"OK\n";
            return 0;
        }
    }

    Usage();
    return 1;
}
