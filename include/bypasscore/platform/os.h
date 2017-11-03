#pragma once

#include <string>
#include <cstdint>

#ifdef _WIN32
#include <windows.h>
#endif

namespace bypasscore {
namespace platform {

enum class OsType {
    Unknown,
    Windows,
    Linux,
    MacOS
};

struct OsVersion {
    uint32_t major = 0;
    uint32_t minor = 0;
    uint32_t build = 0;
    std::string name;
};

/**
 * @brief Detect the current operating system.
 */
inline OsType detect_os() {
#if defined(_WIN32)
    return OsType::Windows;
#elif defined(__linux__)
    return OsType::Linux;
#elif defined(__APPLE__)
    return OsType::MacOS;
#else
    return OsType::Unknown;
#endif
}

/**
 * @brief Retrieve the OS version. On Windows, uses RtlGetVersion
 *        to avoid the GetVersionEx deprecation/compatibility shim.
 */
inline OsVersion get_os_version() {
    OsVersion ver;
#ifdef _WIN32
    // Use RtlGetVersion to bypass compatibility shims
    using RtlGetVersionFn = NTSTATUS(WINAPI*)(PRTL_OSVERSIONINFOW);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        auto fn = reinterpret_cast<RtlGetVersionFn>(
            GetProcAddress(ntdll, "RtlGetVersion"));
        if (fn) {
            RTL_OSVERSIONINFOW osvi = {};
            osvi.dwOSVersionInfoSize = sizeof(osvi);
            if (fn(&osvi) == 0) { // STATUS_SUCCESS
                ver.major = osvi.dwMajorVersion;
                ver.minor = osvi.dwMinorVersion;
                ver.build = osvi.dwBuildNumber;

                if (ver.major == 10 && ver.build >= 22000)
                    ver.name = "Windows 11";
                else if (ver.major == 10)
                    ver.name = "Windows 10";
                else if (ver.major == 6 && ver.minor == 3)
                    ver.name = "Windows 8.1";
                else if (ver.major == 6 && ver.minor == 2)
                    ver.name = "Windows 8";
                else if (ver.major == 6 && ver.minor == 1)
                    ver.name = "Windows 7";
                else
                    ver.name = "Windows (unknown)";
            }
        }
    }
#endif
    return ver;
}

/**
 * @brief Check if the current process is running as administrator/root.
 */
inline bool is_elevated() {
#ifdef _WIN32
    BOOL is_admin = FALSE;
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    PSID admin_group = nullptr;
    if (AllocateAndInitializeSid(&authority, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &admin_group)) {
        CheckTokenMembership(nullptr, admin_group, &is_admin);
        FreeSid(admin_group);
    }
    return is_admin != FALSE;
#else
    return getuid() == 0;
#endif
}

} // namespace platform
} // namespace bypasscore
