#pragma once

#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace bypasscore {
namespace hook {

class HookEngine {
public:
    using HookId = uint32_t;

    static HookEngine& instance() {
        static HookEngine engine;
        return engine;
    }

    HookId register_hook(void* target, void* detour, void** original);
    bool enable(HookId id);
    bool disable(HookId id);
    bool enable_all();
    bool disable_all();
    void remove(HookId id);
    void remove_all();
    bool is_enabled(HookId id) const;

private:
    HookEngine() = default;
    ~HookEngine() { remove_all(); }

    struct HookEntry {
        void*    target   = nullptr;
        void*    detour   = nullptr;
        void**   original = nullptr;
        bool     enabled  = false;
        uint8_t* trampoline = nullptr;
        size_t   stolen_bytes = 0;
        std::vector<uint8_t> original_bytes;
    };

    mutable std::mutex mutex_;
    std::unordered_map<HookId, HookEntry> hooks_;
    HookId next_id_ = 1;
};

} // namespace hook
} // namespace bypasscore
