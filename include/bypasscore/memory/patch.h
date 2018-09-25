#pragma once

#include "protection.h"
#include "../util/result.h"
#include "../util/logger.h"
#include <cstdint>
#include <cstring>
#include <vector>
#include <unordered_map>
#include <mutex>

namespace bypasscore {
namespace memory {

/**
 * @brief A single memory patch with rollback capability.
 *
 * Stores original bytes before patching, allowing reliable
 * restoration of the original memory content.
 */
struct PatchEntry {
    uintptr_t            address   = 0;
    std::vector<uint8_t> original;
    std::vector<uint8_t> patched;
    bool                 applied   = false;
};

/**
 * @brief Memory patch manager with transactional rollback support.
 *
 * Allows applying multiple patches atomically — if any patch in a
 * transaction fails, all previously applied patches in that transaction
 * are rolled back.
 */
class PatchManager {
public:
    using PatchId = uint32_t;

    /**
     * @brief Create a patch (does not apply it yet).
     *
     * @param address  Target address to patch.
     * @param bytes    New bytes to write.
     * @return Patch ID for later apply/restore operations.
     */
    Result<PatchId> create(uintptr_t address, const std::vector<uint8_t>& bytes) {
        std::lock_guard<std::mutex> lock(mutex_);

        PatchEntry entry;
        entry.address = address;
        entry.patched = bytes;
        entry.original.resize(bytes.size());

        // Read original bytes
        std::memcpy(entry.original.data(),
                    reinterpret_cast<const void*>(address), bytes.size());

        PatchId id = next_id_++;
        patches_[id] = std::move(entry);
        return id;
    }

    /**
     * @brief Apply a previously created patch.
     */
    Result<bool> apply(PatchId id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = patches_.find(id);
        if (it == patches_.end())
            return make_error("Patch not found");

        auto& entry = it->second;
        if (entry.applied)
            return make_error("Patch already applied");

        return apply_entry(entry);
    }

    /**
     * @brief Restore the original bytes for a patch.
     */
    Result<bool> restore(PatchId id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = patches_.find(id);
        if (it == patches_.end())
            return make_error("Patch not found");

        auto& entry = it->second;
        if (!entry.applied)
            return make_error("Patch not applied");

        return restore_entry(entry);
    }

    /**
     * @brief Apply a list of patches atomically.
     *
     * If any patch fails, all previously applied patches in this
     * batch are rolled back.
     */
    Result<bool> apply_batch(const std::vector<PatchId>& ids) {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<PatchId> applied_ids;

        for (auto id : ids) {
            auto it = patches_.find(id);
            if (it == patches_.end()) {
                rollback_locked(applied_ids);
                return make_error("Patch not found: " + std::to_string(id));
            }
            auto result = apply_entry(it->second);
            if (!result) {
                rollback_locked(applied_ids);
                return make_error("Failed to apply patch " + std::to_string(id));
            }
            applied_ids.push_back(id);
        }
        return true;
    }

    /**
     * @brief Restore all applied patches.
     */
    void restore_all() {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& [id, entry] : patches_) {
            if (entry.applied) {
                restore_entry(entry);
            }
        }
    }

    /**
     * @brief Remove a patch from the manager (restores first if applied).
     */
    void remove(PatchId id) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = patches_.find(id);
        if (it != patches_.end()) {
            if (it->second.applied)
                restore_entry(it->second);
            patches_.erase(it);
        }
    }

    /**
     * @brief Quick one-shot patch: write bytes with automatic protection change.
     */
    static Result<std::vector<uint8_t>> write_bytes(uintptr_t address,
                                                     const uint8_t* bytes,
                                                     size_t count) {
        void* addr = reinterpret_cast<void*>(address);
        std::vector<uint8_t> original(count);
        std::memcpy(original.data(), addr, count);

        ProtectionGuard guard(addr, count, RegionAccess::ReadWrite);
        if (!guard)
            return make_error("Failed to change protection");

        std::memcpy(addr, bytes, count);
        return original;
    }

    /**
     * @brief Fill a memory region with a single byte value.
     */
    static Result<bool> fill(uintptr_t address, uint8_t value, size_t count) {
        void* addr = reinterpret_cast<void*>(address);
        ProtectionGuard guard(addr, count, RegionAccess::ReadWrite);
        if (!guard)
            return make_error("Failed to change protection");

        std::memset(addr, value, count);
        return true;
    }

    /**
     * @brief NOP-fill a region (x86/x64: 0x90).
     */
    static Result<bool> nop(uintptr_t address, size_t count) {
        return fill(address, 0x90, count);
    }

private:
    Result<bool> apply_entry(PatchEntry& entry) {
        void* addr = reinterpret_cast<void*>(entry.address);
        ProtectionGuard guard(addr, entry.patched.size(), RegionAccess::ReadWrite);
        if (!guard)
            return make_error("Failed to change memory protection");

        // Re-read original in case memory changed since creation
        std::memcpy(entry.original.data(), addr, entry.original.size());
        std::memcpy(addr, entry.patched.data(), entry.patched.size());
        entry.applied = true;
        return true;
    }

    Result<bool> restore_entry(PatchEntry& entry) {
        void* addr = reinterpret_cast<void*>(entry.address);
        ProtectionGuard guard(addr, entry.original.size(), RegionAccess::ReadWrite);
        if (!guard)
            return make_error("Failed to change memory protection");

        std::memcpy(addr, entry.original.data(), entry.original.size());
        entry.applied = false;
        return true;
    }

    void rollback_locked(const std::vector<PatchId>& ids) {
        for (auto it = ids.rbegin(); it != ids.rend(); ++it) {
            auto pit = patches_.find(*it);
            if (pit != patches_.end() && pit->second.applied) {
                restore_entry(pit->second);
            }
        }
    }

    std::mutex mutex_;
    std::unordered_map<PatchId, PatchEntry> patches_;
    PatchId next_id_ = 1;
};

} // namespace memory
} // namespace bypasscore
