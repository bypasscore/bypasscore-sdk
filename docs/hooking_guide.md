# BypassCore Hooking Guide

This guide covers the hooking primitives provided by the BypassCore SDK.

## Overview

BypassCore provides four hooking mechanisms, each suited to different scenarios:

| Method | Use Case | Scope | Overhead |
|--------|----------|-------|----------|
| **Inline Detour** | General-purpose function hooking | All callers | Low |
| **IAT Hook** | Intercepting imported API calls | Per-module | Very low |
| **VMT Hook** | Hooking C++ virtual methods | Per-object | Very low |
| **Syscall Hook** | Intercepting NT syscalls | Global | Low |

## 1. Inline Detour Hooking

The `DetourHook` class replaces the first bytes of a target function with a
JMP instruction that redirects execution to your detour function. A trampoline
preserves the original instructions so the original function can still be called.

### Architecture Details

**x86 (32-bit):**
- Overwrites **5 bytes** with `E9 rel32` (relative JMP)
- Trampoline contains stolen bytes + `E9 rel32` jump-back

**x64 (64-bit):**
- Overwrites **14 bytes** with `FF 25 00000000` + 8-byte absolute address
- Falls back to 5-byte `E9 rel32` if the detour is within +/-2GB range
- For short functions (<14 bytes), automatically attempts the 5-byte variant

### Usage

```cpp
#include "bypasscore/hook/detour.h"

using Fn_t = int(*)(int, int);
Fn_t original = nullptr;

int my_hook(int a, int b) {
    // Pre-processing
    int result = original(a, b);  // Call original via trampoline
    // Post-processing
    return result;
}

bypasscore::hook::DetourHook hook;
hook.install(target_function, my_hook, &original);
// ... later ...
hook.remove();
```

## 2. IAT Hooking

The `IatHook` class patches a function pointer in a module's Import Address
Table. This only intercepts calls made through the IAT (not direct calls or
calls from other modules).

### Usage

```cpp
#include "bypasscore/hook/iat_hook.h"

bypasscore::hook::IatHook hook;
void* orig = nullptr;
hook.install(GetModuleHandle(NULL), "user32.dll", "MessageBoxA",
             my_detour, &orig);
```

## 3. VMT Hooking

The `VmtHook` class replaces entries in a C++ object's vtable. It uses
the **table-swap** technique: a shadow copy of the vtable is created and
the object's vtable pointer is redirected to the shadow.

### Usage

```cpp
#include "bypasscore/hook/vmt_hook.h"

bypasscore::hook::VmtHook hook;
hook.initialize(object_ptr);
void* original = *hook.hook(3, my_virtual_override);  // Index 3
```

## 4. Syscall Hooking

The `SyscallHook` class patches ntdll syscall stubs to redirect execution.
On Windows x64, ntdll stubs follow a recognizable pattern:

```asm
mov r10, rcx        ; 4C 8B D1
mov eax, <number>   ; B8 xx xx 00 00
syscall             ; 0F 05
ret                 ; C3
```

### Usage

```cpp
#include "bypasscore/hook/syscall_hook.h"

bypasscore::hook::SyscallHook shook;
void* orig = nullptr;
shook.hook("NtQuerySystemInformation", my_handler, &orig);
```

## Thread Safety

All hooking operations should be performed with other threads suspended to
prevent crashes from partially-written instructions. Use the thread
suspension utilities:

```cpp
#include "bypasscore/process/thread.h"
bypasscore::process::Thread::suspend_all(GetCurrentProcessId(),
                                          GetCurrentThreadId());
// ... install hooks ...
bypasscore::process::Thread::resume_all(GetCurrentProcessId());
```
