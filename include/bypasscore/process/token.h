#pragma once

#include "../util/result.h"
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace bypasscore {
namespace process {

class TokenManager {
public:
#ifdef _WIN32
    static Result<bool> enable_privilege(const std::string& privilege) {
        HANDLE token;
        if (!OpenProcessToken(GetCurrentProcess(),
                              TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
            return make_error("OpenProcessToken failed", GetLastError());

        TOKEN_PRIVILEGES tp = {};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        std::wstring wide(privilege.begin(), privilege.end());
        if (!LookupPrivilegeValueW(nullptr, wide.c_str(), &tp.Privileges[0].Luid)) {
            CloseHandle(token);
            return make_error("LookupPrivilegeValue failed", GetLastError());
        }

        BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, 0, nullptr, nullptr);
        DWORD err = GetLastError();
        CloseHandle(token);

        if (!ok || err == ERROR_NOT_ALL_ASSIGNED)
            return make_error("AdjustTokenPrivileges failed", err);
        return true;
    }

    static Result<bool> enable_debug_privilege() {
        return enable_privilege("SeDebugPrivilege");
    }

    static std::vector<std::string> list_privileges() {
        std::vector<std::string> result;
        HANDLE token;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
            return result;

        DWORD size = 0;
        GetTokenInformation(token, TokenPrivileges, nullptr, 0, &size);
        std::vector<uint8_t> buf(size);
        if (GetTokenInformation(token, TokenPrivileges, buf.data(), size, &size)) {
            auto* tp = reinterpret_cast<TOKEN_PRIVILEGES*>(buf.data());
            for (DWORD i = 0; i < tp->PrivilegeCount; ++i) {
                wchar_t name[256];
                DWORD name_size = 256;
                if (LookupPrivilegeNameW(nullptr, &tp->Privileges[i].Luid,
                                         name, &name_size)) {
                    char narrow[256];
                    WideCharToMultiByte(CP_UTF8, 0, name, -1,
                                        narrow, 256, nullptr, nullptr);
                    result.emplace_back(narrow);
                }
            }
        }
        CloseHandle(token);
        return result;
    }
#endif
};

} // namespace process
} // namespace bypasscore
