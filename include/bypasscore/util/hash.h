#pragma once

#include <cstdint>
#include <cstddef>
#include <string>

namespace bypasscore {

/**
 * @brief Compile-time FNV-1a string hashing.
 *
 * Useful for obfuscating string comparisons at compile time:
 *   if (hash(name) == "CreateFileW"_hash) { ... }
 */
namespace detail {
    constexpr uint32_t fnv1a_32_val  = 0x811c9dc5;
    constexpr uint32_t fnv1a_32_prime = 0x01000193;
    constexpr uint64_t fnv1a_64_val  = 0xcbf29ce484222325ULL;
    constexpr uint64_t fnv1a_64_prime = 0x100000001b3ULL;
}

constexpr uint32_t hash32(const char* str, size_t len) {
    uint32_t h = detail::fnv1a_32_val;
    for (size_t i = 0; i < len; ++i)
        h = (h ^ static_cast<uint32_t>(str[i])) * detail::fnv1a_32_prime;
    return h;
}

constexpr uint32_t hash32(const char* str) {
    uint32_t h = detail::fnv1a_32_val;
    while (*str)
        h = (h ^ static_cast<uint32_t>(*str++)) * detail::fnv1a_32_prime;
    return h;
}

constexpr uint64_t hash64(const char* str) {
    uint64_t h = detail::fnv1a_64_val;
    while (*str)
        h = (h ^ static_cast<uint64_t>(*str++)) * detail::fnv1a_64_prime;
    return h;
}

inline uint32_t hash32_runtime(const std::string& str) {
    return hash32(str.c_str(), str.size());
}

/**
 * @brief User-defined literal for compile-time hashing.
 */
constexpr uint32_t operator""_hash(const char* str, size_t len) {
    return hash32(str, len);
}

constexpr uint64_t operator""_hash64(const char* str, size_t len) {
    uint64_t h = detail::fnv1a_64_val;
    for (size_t i = 0; i < len; ++i)
        h = (h ^ static_cast<uint64_t>(str[i])) * detail::fnv1a_64_prime;
    return h;
}

} // namespace bypasscore
