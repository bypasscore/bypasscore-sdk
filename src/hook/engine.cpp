#include "bypasscore/hook/engine.h"
#include "bypasscore/hook/trampoline.h"
#include "bypasscore/memory/protection.h"
#include "bypasscore/util/logger.h"
#include <cstring>

namespace bypasscore {
namespace hook {

HookEngine::HookId HookEngine::register_hook(void* target, void* detour, void** original) {
    std::lock_guard<std::mutex> lock(mutex_);
    HookEntry entry;
    entry.target = target; entry.detour = detour; entry.original = original;
    HookId id = next_id_++;
    hooks_[id] = entry;
    return id;
}

bool HookEngine::enable(HookId id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = hooks_.find(id);
    if (it == hooks_.end()) return false;
    auto& e = it->second;
    if (e.enabled) return true;
#if defined(_M_X64) || defined(__x86_64__)
    constexpr bool is_64 = true;
#else
    constexpr bool is_64 = false;
#endif
    auto result = Trampoline::create(e.target, is_64);
    if (!result) return false;
    auto info = *result;
    e.trampoline = info.trampoline_addr;
    e.stolen_bytes = info.stolen_bytes;
    e.original_bytes = info.original;
    if (e.original) *e.original = info.trampoline_addr;
    auto jmp = Trampoline::install_jump(e.target, e.detour, e.stolen_bytes, is_64);
    if (!jmp) { Trampoline::destroy(info); return false; }
    e.enabled = true;
    return true;
}

bool HookEngine::disable(HookId id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = hooks_.find(id);
    if (it == hooks_.end()) return false;
    auto& e = it->second;
    if (!e.enabled) return true;
    auto* dst = static_cast<uint8_t*>(e.target);
    memory::ProtectionGuard guard(dst, e.stolen_bytes, memory::RegionAccess::ReadWrite);
    if (!guard) return false;
    std::memcpy(dst, e.original_bytes.data(), e.stolen_bytes);
    Trampoline::Info info; info.trampoline_addr = e.trampoline;
    Trampoline::destroy(info);
    e.trampoline = nullptr; e.enabled = false;
    return true;
}

bool HookEngine::enable_all() {
    std::vector<HookId> ids;
    { std::lock_guard<std::mutex> lock(mutex_);
      for (auto& [id, _] : hooks_) ids.push_back(id); }
    bool ok = true;
    for (auto id : ids) ok &= enable(id);
    return ok;
}

bool HookEngine::disable_all() {
    std::vector<HookId> ids;
    { std::lock_guard<std::mutex> lock(mutex_);
      for (auto& [id, _] : hooks_) ids.push_back(id); }
    bool ok = true;
    for (auto id : ids) ok &= disable(id);
    return ok;
}

void HookEngine::remove(HookId id) { disable(id); std::lock_guard<std::mutex> lock(mutex_); hooks_.erase(id); }
void HookEngine::remove_all() { disable_all(); std::lock_guard<std::mutex> lock(mutex_); hooks_.clear(); }

bool HookEngine::is_enabled(HookId id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = hooks_.find(id);
    return it != hooks_.end() && it->second.enabled;
}

} // namespace hook
} // namespace bypasscore
