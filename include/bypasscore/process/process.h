#pragma once

#include "../util/result.h"
#include <cstdint>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#endif

namespace bypasscore {
namespace process {

struct ProcessInfo {
    uint32_t    pid = 0;
    uint32_t    parent_pid = 0;
    std::string name;
    std::string path;
};

struct ModuleInfo {
    uintptr_t   base = 0;
    size_t      size = 0;
    std::string name;
    std::string path;
};

class Process {
public:
    Process() = default;
    ~Process() { close(); }
    Process(const Process&) = delete;
    Process& operator=(const Process&) = delete;

    static Result<Process> open(uint32_t pid, uint32_t access = 0) {
        Process p;
#ifdef _WIN32
        DWORD desired = access ? access :
            (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
             PROCESS_QUERY_INFORMATION);
        p.handle_ = OpenProcess(desired, FALSE, pid);
        if (!p.handle_) return make_error("OpenProcess failed", GetLastError());
        p.pid_ = pid;
#endif
        return p;
    }

    static Result<Process> open_by_name(const std::string& name) {
        auto procs = enumerate();
        for (const auto& pi : procs) {
            if (pi.name == name) return open(pi.pid);
        }
        return make_error("Process not found: " + name);
    }

    static std::vector<ProcessInfo> enumerate() {
        std::vector<ProcessInfo> result;
#ifdef _WIN32
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return result;
        PROCESSENTRY32W pe = {}; pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                ProcessInfo info;
                info.pid = pe.th32ProcessID;
                info.parent_pid = pe.th32ParentProcessID;
                char narrow[MAX_PATH];
                WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1,
                                    narrow, MAX_PATH, nullptr, nullptr);
                info.name = narrow;
                result.push_back(info);
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
#endif
        return result;
    }

    Result<std::vector<uint8_t>> read(uintptr_t address, size_t size) const {
        std::vector<uint8_t> buf(size);
#ifdef _WIN32
        SIZE_T read_bytes = 0;
        if (!ReadProcessMemory(handle_, reinterpret_cast<LPCVOID>(address),
                               buf.data(), size, &read_bytes))
            return make_error("ReadProcessMemory failed", GetLastError());
        buf.resize(read_bytes);
#endif
        return buf;
    }

    Result<bool> write(uintptr_t address, const void* data, size_t size) {
#ifdef _WIN32
        SIZE_T written = 0;
        if (!WriteProcessMemory(handle_, reinterpret_cast<LPVOID>(address),
                                data, size, &written))
            return make_error("WriteProcessMemory failed", GetLastError());
        return true;
#else
        return make_error("Not implemented");
#endif
    }

    std::vector<ModuleInfo> modules() const {
        std::vector<ModuleInfo> result;
#ifdef _WIN32
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid_);
        if (snap == INVALID_HANDLE_VALUE) return result;
        MODULEENTRY32W me = {}; me.dwSize = sizeof(me);
        if (Module32FirstW(snap, &me)) {
            do {
                ModuleInfo info;
                info.base = reinterpret_cast<uintptr_t>(me.modBaseAddr);
                info.size = me.modBaseSize;
                char narrow[MAX_PATH];
                WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1,
                                    narrow, MAX_PATH, nullptr, nullptr);
                info.name = narrow;
                WideCharToMultiByte(CP_UTF8, 0, me.szExePath, -1,
                                    narrow, MAX_PATH, nullptr, nullptr);
                info.path = narrow;
                result.push_back(info);
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
#endif
        return result;
    }

    void close() {
#ifdef _WIN32
        if (handle_) { CloseHandle(handle_); handle_ = nullptr; }
#endif
    }

    uint32_t pid() const { return pid_; }
    void* handle() const { return handle_; }

private:
    void*    handle_ = nullptr;
    uint32_t pid_    = 0;
};

} // namespace process
} // namespace bypasscore
