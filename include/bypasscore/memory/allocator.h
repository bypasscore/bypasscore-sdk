#pragma once

#include "region.h"
#include "../util/result.h"
#include <cstdint>
#include <cstddef>
#include <vector>
#include <mutex>

#ifdef _WIN32
#include <windows.h>
#endif

namespace bypasscore {
namespace memory {

/**
 * @brief Code cave finder -- locates unused executable memory regions
 *        near a target address for trampoline allocation.
 */
class CaveFinder {
public:
    struct Cave {
        uintptr_t address = 0;
        size_t    size    = 0;
    };

    /**
     * @brief Find code caves (runs of CC/00/90 bytes) near a target address.
     */
    static std::vector<Cave> find_near(uintptr_t target, size_t min_size = 32,
                                        size_t search_range = 0x7FFFFF00) {
        std::vector<Cave> caves;
#ifdef _WIN32
        uintptr_t start = (target > search_range) ? target - search_range : 0;
        uintptr_t end   = target + search_range;

        MEMORY_BASIC_INFORMATION mbi;
        for (uintptr_t addr = start; addr < end; ) {
            if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0)
                break;

            uintptr_t region_end = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;

            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                PAGE_EXECUTE_READWRITE))) {
                // Scan for padding bytes
                auto* p = static_cast<const uint8_t*>(mbi.BaseAddress);
                size_t run = 0;
                uintptr_t run_start = 0;

                for (size_t i = 0; i < mbi.RegionSize; ++i) {
                    if (p[i] == 0xCC || p[i] == 0x00 || p[i] == 0x90) {
                        if (run == 0)
                            run_start = reinterpret_cast<uintptr_t>(p) + i;
                        ++run;
                    } else {
                        if (run >= min_size) {
                            caves.push_back({run_start, run});
                        }
                        run = 0;
                    }
                }
                if (run >= min_size) {
                    caves.push_back({run_start, run});
                }
            }
            addr = region_end;
            if (addr == 0) break;
        }
#endif
        return caves;
    }
};

/**
 * @brief Trampoline allocator -- allocates executable memory near a target.
 */
class TrampolineAllocator {
public:
    static TrampolineAllocator& instance() {
        static TrampolineAllocator alloc;
        return alloc;
    }

    void* allocate(uintptr_t near_addr, size_t size) {
        std::lock_guard<std::mutex> lock(mutex_);
#ifdef _WIN32
        // Try to allocate within +/- 2GB of the target
        uintptr_t start = (near_addr > 0x7FFFFF00) ? near_addr - 0x7FFFFF00 : 0;
        uintptr_t end   = near_addr + 0x7FFFFF00;

        // Round start up to allocation granularity
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        uintptr_t gran = si.dwAllocationGranularity;
        start = (start + gran - 1) & ~(gran - 1);

        MEMORY_BASIC_INFORMATION mbi;
        for (uintptr_t addr = start; addr < end; ) {
            if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0)
                break;

            if (mbi.State == MEM_FREE && mbi.RegionSize >= size) {
                void* p = VirtualAlloc(reinterpret_cast<LPVOID>(addr), size,
                                       MEM_COMMIT | MEM_RESERVE,
                                       PAGE_EXECUTE_READWRITE);
                if (p) {
                    allocations_.push_back({reinterpret_cast<uintptr_t>(p), size});
                    return p;
                }
            }
            addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            if (addr == 0) break;
        }

        // Fallback: allocate anywhere
        void* p = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
        if (p) allocations_.push_back({reinterpret_cast<uintptr_t>(p), size});
        return p;
#else
        return nullptr;
#endif
    }

    void deallocate(void* ptr) {
        std::lock_guard<std::mutex> lock(mutex_);
#ifdef _WIN32
        VirtualFree(ptr, 0, MEM_RELEASE);
#endif
        auto it = std::remove_if(allocations_.begin(), allocations_.end(),
            [ptr](const Allocation& a) {
                return a.address == reinterpret_cast<uintptr_t>(ptr);
            });
        allocations_.erase(it, allocations_.end());
    }

private:
    struct Allocation {
        uintptr_t address;
        size_t size;
    };

    std::mutex mutex_;
    std::vector<Allocation> allocations_;
};

} // namespace memory
} // namespace bypasscore
