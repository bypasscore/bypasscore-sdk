#pragma once

#include "../util/result.h"
#include <cstdint>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#endif

namespace bypasscore {
namespace process {

struct ThreadInfo {
    uint32_t tid = 0;
    uint32_t owner_pid = 0;
    int32_t  priority = 0;
};

/**
 * @brief Thread enumeration and manipulation.
 */
class Thread {
public:
    static std::vector<ThreadInfo> enumerate(uint32_t pid) {
        std::vector<ThreadInfo> result;
#ifdef _WIN32
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) return result;
        THREADENTRY32 te = {}; te.dwSize = sizeof(te);
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID == pid) {
                    ThreadInfo info;
                    info.tid = te.th32ThreadID;
                    info.owner_pid = te.th32OwnerProcessID;
                    info.priority = te.tpBasePri;
                    result.push_back(info);
                }
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
#endif
        return result;
    }

    static Result<bool> suspend(uint32_t tid) {
#ifdef _WIN32
        HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
        if (!h) return make_error("OpenThread failed", GetLastError());
        SuspendThread(h);
        CloseHandle(h);
        return true;
#else
        return make_error("Not implemented");
#endif
    }

    static Result<bool> resume(uint32_t tid) {
#ifdef _WIN32
        HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
        if (!h) return make_error("OpenThread failed", GetLastError());
        ResumeThread(h);
        CloseHandle(h);
        return true;
#else
        return make_error("Not implemented");
#endif
    }

    static Result<bool> suspend_all(uint32_t pid, uint32_t except_tid = 0) {
        auto threads = enumerate(pid);
        for (const auto& t : threads) {
            if (t.tid != except_tid) {
                auto r = suspend(t.tid);
                if (!r) return r;
            }
        }
        return true;
    }

    static Result<bool> resume_all(uint32_t pid) {
        auto threads = enumerate(pid);
        for (const auto& t : threads) {
            auto r = resume(t.tid);
            if (!r) return r;
        }
        return true;
    }
};

} // namespace process
} // namespace bypasscore
