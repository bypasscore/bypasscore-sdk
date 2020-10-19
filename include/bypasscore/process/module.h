#pragma once

#include "process.h"
#include "../binary/pe.h"
#include "../util/result.h"
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

namespace bypasscore {
namespace process {

/**
 * @brief Higher-level module abstraction with PE parsing.
 */
class Module {
public:
    Module() = default;

    static Result<Module> from_handle(void* hModule) {
        Module m;
#ifdef _WIN32
        m.base_ = reinterpret_cast<uintptr_t>(hModule);
        auto* dos = static_cast<const uint8_t*>(hModule);
        // Read PE headers
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(hModule, &mbi, sizeof(mbi)))
            m.size_ = mbi.RegionSize;
        char path[MAX_PATH];
        if (GetModuleFileNameA(static_cast<HMODULE>(hModule), path, MAX_PATH))
            m.path_ = path;
#endif
        return m;
    }

    static Result<Module> find(const std::string& name) {
#ifdef _WIN32
        HMODULE hMod = GetModuleHandleA(name.c_str());
        if (!hMod) return make_error("Module not found: " + name);
        return from_handle(hMod);
#else
        return make_error("Not implemented");
#endif
    }

    uintptr_t base() const { return base_; }
    size_t size() const { return size_; }
    const std::string& path() const { return path_; }

    void* find_export(const std::string& name) const {
#ifdef _WIN32
        return reinterpret_cast<void*>(
            GetProcAddress(reinterpret_cast<HMODULE>(base_), name.c_str()));
#else
        return nullptr;
#endif
    }

private:
    uintptr_t   base_ = 0;
    size_t      size_ = 0;
    std::string path_;
};

} // namespace process
} // namespace bypasscore
