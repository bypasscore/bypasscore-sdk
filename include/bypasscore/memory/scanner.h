#pragma once

#include "region.h"
#include "../util/result.h"
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <optional>
#include <sstream>

namespace bypasscore {
namespace memory {

/**
 * @brief A byte pattern element that supports wildcard matching.
 */
struct PatternByte {
    uint8_t value    = 0;
    bool    wildcard = false;
};

/**
 * @brief Parse an IDA-style AOB pattern string.
 *
 * Supported formats:
 *   "48 8B 05 ?? ?? ?? ?? 48 85 C0"   (IDA style, ?? = wildcard)
 *   "48 8B 05 ? ? ? ? 48 85 C0"       (single ? = wildcard)
 *   "\x48\x8B\x05"                  (C-style hex escape, no wildcards)
 *
 * @param pattern The pattern string to parse.
 * @return Vector of PatternByte on success.
 */
inline Result<std::vector<PatternByte>> parse_pattern(const std::string& pattern) {
    std::vector<PatternByte> result;

    if (pattern.empty())
        return make_error("Empty pattern");

    // Handle C-style hex escapes: \x48\x8B\x05
    if (pattern.size() >= 4 && pattern[0] == '\' && pattern[1] == 'x') {
        for (size_t i = 0; i < pattern.size();) {
            if (pattern[i] == '\' && i + 3 < pattern.size() && pattern[i + 1] == 'x') {
                char hex[3] = { pattern[i + 2], pattern[i + 3], 0 };
                PatternByte pb;
                pb.value = static_cast<uint8_t>(strtoul(hex, nullptr, 16));
                pb.wildcard = false;
                result.push_back(pb);
                i += 4;
            } else {
                ++i;
            }
        }
        if (result.empty())
            return make_error("Failed to parse C-style pattern");
        return result;
    }

    // IDA-style space-separated hex with ?? wildcards
    std::istringstream iss(pattern);
    std::string token;
    while (iss >> token) {
        PatternByte pb;
        if (token == "?" || token == "??") {
            pb.wildcard = true;
        } else {
            char* end = nullptr;
            unsigned long val = strtoul(token.c_str(), &end, 16);
            if (end == token.c_str() || val > 0xFF)
                return make_error("Invalid pattern byte: " + token);
            pb.value = static_cast<uint8_t>(val);
            pb.wildcard = false;
        }
        result.push_back(pb);
    }

    if (result.empty())
        return make_error("Pattern produced no bytes");

    return result;
}

/**
 * @brief Scan a memory buffer for the first occurrence of a byte pattern.
 *
 * @param data       Pointer to the buffer to scan.
 * @param data_size  Size of the buffer in bytes.
 * @param pattern    The parsed pattern to search for.
 * @return Offset into `data` of the first match, or std::nullopt.
 */
inline std::optional<size_t> scan_buffer(const uint8_t* data, size_t data_size,
                                         const std::vector<PatternByte>& pattern) {
    if (!data || data_size == 0 || pattern.empty())
        return std::nullopt;

    if (pattern.size() > data_size)
        return std::nullopt;

    const size_t scan_end = data_size - pattern.size();

    for (size_t i = 0; i <= scan_end; ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (!pattern[j].wildcard && data[i + j] != pattern[j].value) {
                match = false;
                break;
            }
        }
        if (match) return i;
    }

    return std::nullopt;
}

/**
 * @brief Scan a memory buffer for ALL occurrences of a byte pattern.
 */
inline std::vector<size_t> scan_buffer_all(const uint8_t* data, size_t data_size,
                                           const std::vector<PatternByte>& pattern) {
    std::vector<size_t> results;
    if (!data || data_size == 0 || pattern.empty() || pattern.size() > data_size)
        return results;

    const size_t scan_end = data_size - pattern.size();

    for (size_t i = 0; i <= scan_end; ++i) {
        bool match = true;
        for (size_t j = 0; j < pattern.size(); ++j) {
            if (!pattern[j].wildcard && data[i + j] != pattern[j].value) {
                match = false;
                break;
            }
        }
        if (match) results.push_back(i);
    }

    return results;
}

/**
 * @brief High-level scanner: parse an AOB string and scan a buffer.
 */
inline Result<std::optional<uintptr_t>> find_pattern(const uint8_t* data,
                                                     size_t data_size,
                                                     const std::string& aob) {
    auto parsed = parse_pattern(aob);
    if (!parsed)
        return make_error("Failed to parse pattern: " + parsed.error().message);

    auto offset = scan_buffer(data, data_size, *parsed);
    if (!offset)
        return std::optional<uintptr_t>(std::nullopt);

    return std::optional<uintptr_t>(static_cast<uintptr_t>(*offset));
}

/**
 * @brief Scan the entire virtual memory of a process for a pattern.
 *
 * @param process_handle  Process handle with PROCESS_VM_READ access.
 * @param aob             IDA-style pattern string.
 * @return Address of the first match, or empty optional.
 */
inline std::optional<uintptr_t> scan_process(void* process_handle,
                                             const std::string& aob) {
    auto parsed = parse_pattern(aob);
    if (!parsed) return std::nullopt;

    auto regions = enumerate_regions(process_handle);
    for (const auto& region : regions) {
        if (!region.is_readable()) continue;
        if (has_flag(region.access, RegionAccess::Guard)) continue;

        std::vector<uint8_t> buffer(region.size);
#ifdef _WIN32
        SIZE_T bytes_read = 0;
        if (!ReadProcessMemory(process_handle,
                               reinterpret_cast<LPCVOID>(region.base),
                               buffer.data(), region.size, &bytes_read)) {
            continue;
        }
        auto offset = scan_buffer(buffer.data(),
                                  static_cast<size_t>(bytes_read), *parsed);
        if (offset)
            return region.base + *offset;
#endif
    }
    return std::nullopt;
}

} // namespace memory
} // namespace bypasscore
