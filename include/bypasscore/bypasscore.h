#pragma once

/**
 * @file bypasscore.h
 * @brief Main SDK header — includes the entire BypassCore SDK.
 *
 * BypassCore SDK provides low-level primitives for hooking, memory
 * manipulation, process introspection, and binary analysis across
 * Windows platforms (x86, x64, and ARM64).
 *
 * Copyright (c) 2017 BypassCore Labs
 * Licensed under the MIT License.
 */

#include "version.h"

namespace bypasscore {

/// Initialize the SDK. Must be called before any other SDK function.
bool initialize();

/// Shut down the SDK and release all resources.
void shutdown();

/// Returns true if the SDK has been initialized.
bool is_initialized();

} // namespace bypasscore
