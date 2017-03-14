#include "bypasscore/bypasscore.h"
#include <atomic>

namespace bypasscore {

static std::atomic<bool> g_initialized{false};

bool initialize() {
    bool expected = false;
    if (g_initialized.compare_exchange_strong(expected, true)) {
        return true;
    }
    return false;
}

void shutdown() {
    g_initialized.store(false);
}

bool is_initialized() {
    return g_initialized.load();
}

} // namespace bypasscore
