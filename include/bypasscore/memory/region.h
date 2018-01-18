#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

namespace bypasscore {
namespace memory {

/**
 * @brief Flags describing memory region protection and state.
 */
enum class RegionAccess : uint32_t {
    None        = 0,
    Read        = 1 << 0,
    Write       = 1 << 1,
    Execute     = 1 << 2,
    Guard       = 1 << 3,
    NoCache     = 1 << 4,
    ReadWrite   = Read | Write,
    ReadExecute = Read | Execute,
    All         = Read | Write | Execute
};

inline RegionAccess operator|(RegionAccess a, RegionAccess b) {
    return static_cast<RegionAccess>(
        static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}
inline RegionAccess operator&(RegionAccess a, RegionAccess b) {
    return static_cast<RegionAccess>(
        static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}
inline bool has_flag(RegionAccess val, RegionAccess flag) {
    return (static_cast<uint32_t>(val) & static_cast<uint32_t>(flag)) != 0;
}

enum class RegionState : uint32_t {
    Free,
    Reserved,
    Committed
};

/**
 * @brief Represents a contiguous memory region with its protection attributes.
 */
struct MemoryRegion {
    uintptr_t   base   = 0;
    size_t      size   = 0;
    RegionAccess access = RegionAccess::None;
    RegionState  state  = RegionState::Free;
    std::string  module_name;  // Module owning this region, if known

    uintptr_t end() const { return base + size; }
    bool contains(uintptr_t addr) const {
        return addr >= base && addr < end();
    }
    bool is_readable() const { return has_flag(access, RegionAccess::Read); }
    bool is_writable() const { return has_flag(access, RegionAccess::Write); }
    bool is_executable() const { return has_flag(access, RegionAccess::Execute); }
};

#ifdef _WIN32
/**
 * @brief Convert Windows PAGE_* constants to RegionAccess flags.
 */
inline RegionAccess from_win32_protect(DWORD protect) {
    RegionAccess acc = RegionAccess::None;
    switch (protect & 0xFF) {
        case PAGE_READONLY:          acc = RegionAccess::Read; break;
        case PAGE_READWRITE:         acc = RegionAccess::ReadWrite; break;
        case PAGE_WRITECOPY:         acc = RegionAccess::ReadWrite; break;
        case PAGE_EXECUTE:           acc = RegionAccess::Execute; break;
        case PAGE_EXECUTE_READ:      acc = RegionAccess::ReadExecute; break;
        case PAGE_EXECUTE_READWRITE: acc = RegionAccess::All; break;
        case PAGE_EXECUTE_WRITECOPY: acc = RegionAccess::All; break;
        default: break;
    }
    if (protect & PAGE_GUARD)   acc = acc | RegionAccess::Guard;
    if (protect & PAGE_NOCACHE) acc = acc | RegionAccess::NoCache;
    return acc;
}

/**
 * @brief Convert RegionAccess flags to Windows PAGE_* constant.
 */
inline DWORD to_win32_protect(RegionAccess acc) {
    bool r = has_flag(acc, RegionAccess::Read);
    bool w = has_flag(acc, RegionAccess::Write);
    bool x = has_flag(acc, RegionAccess::Execute);

    DWORD prot = PAGE_NOACCESS;
    if (x && w)      prot = PAGE_EXECUTE_READWRITE;
    else if (x && r) prot = PAGE_EXECUTE_READ;
    else if (x)      prot = PAGE_EXECUTE;
    else if (w)      prot = PAGE_READWRITE;
    else if (r)      prot = PAGE_READONLY;

    if (has_flag(acc, RegionAccess::Guard))   prot |= PAGE_GUARD;
    if (has_flag(acc, RegionAccess::NoCache)) prot |= PAGE_NOCACHE;
    return prot;
}
#endif

/**
 * @brief Enumerate all memory regions for a given process.
 *
 * @param process_handle Handle to the target process (use GetCurrentProcess()
 *        for the calling process, or a handle with PROCESS_QUERY_INFORMATION).
 * @return Vector of MemoryRegion describing each contiguous region.
 */
inline std::vector<MemoryRegion> enumerate_regions(void* process_handle = nullptr) {
    std::vector<MemoryRegion> regions;
#ifdef _WIN32
    if (!process_handle)
        process_handle = GetCurrentProcess();

    MEMORY_BASIC_INFORMATION mbi = {};
    uintptr_t addr = 0;
    while (VirtualQueryEx(process_handle, reinterpret_cast<LPCVOID>(addr),
                          &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT) {
            MemoryRegion region;
            region.base   = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            region.size   = mbi.RegionSize;
            region.access = from_win32_protect(mbi.Protect);
            region.state  = RegionState::Committed;
            regions.push_back(region);
        }
        addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (addr == 0) break; // Overflow guard
    }
#endif
    return regions;
}

} // namespace memory
} // namespace bypasscore
