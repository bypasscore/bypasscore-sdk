#pragma once

#include <cstdint>
#include <string>

namespace bypasscore {
namespace platform {

enum class Architecture {
    Unknown,
    X86,
    X64,
    ARM64
};

/**
 * @brief Detect the compile-time target architecture.
 */
constexpr Architecture target_arch() {
#if defined(_M_X64) || defined(__x86_64__)
    return Architecture::X64;
#elif defined(_M_IX86) || defined(__i386__)
    return Architecture::X86;
#elif defined(_M_ARM64) || defined(__aarch64__)
    return Architecture::ARM64;
#else
    return Architecture::Unknown;
#endif
}

/**
 * @brief Returns a human-readable name for the architecture.
 */
inline const char* arch_name(Architecture arch) {
    switch (arch) {
        case Architecture::X86:   return "x86";
        case Architecture::X64:   return "x86-64";
        case Architecture::ARM64: return "ARM64";
        default:                  return "unknown";
    }
}

/**
 * @brief Returns the pointer size in bytes for the given architecture.
 */
constexpr size_t pointer_size(Architecture arch) {
    switch (arch) {
        case Architecture::X86:   return 4;
        case Architecture::X64:   return 8;
        case Architecture::ARM64: return 8;
        default:                  return sizeof(void*);
    }
}

/**
 * @brief Returns true if running on a 64-bit architecture.
 */
constexpr bool is_64bit() {
    return target_arch() == Architecture::X64 ||
           target_arch() == Architecture::ARM64;
}

} // namespace platform
} // namespace bypasscore
