# BypassCore SDK

**Cross-platform hooking engine, memory introspection framework, and security research primitives.**

[![CI](https://github.com/bypasscore/bypasscore-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/bypasscore/bypasscore-sdk/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)]()
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)]()

---

## What is BypassCore SDK?

BypassCore SDK is the foundational library powering the entire BypassCore toolchain. It provides battle-tested, low-level primitives for:

- **Function hooking** (inline detours, IAT patching, VMT swapping, syscall interception)
- **Memory introspection** (region enumeration, pattern scanning, page protection manipulation)
- **Process interaction** (read/write memory, module enumeration, thread control, privilege management)
- **Binary analysis** (PE parsing, instruction length disassembly, relocation processing)

Designed for security researchers, reverse engineers, and tool developers who need reliable, well-documented building blocks.

## Architecture

```
+-------------------------------------------------------------------+
|                        BypassCore SDK                              |
|-------------------------------------------------------------------|
|  Hook Engine          | Memory Engine       | Binary Engine       |
|  - Inline Detour      | - Region Enum       | - PE Parser         |
|  - IAT Hook           | - AOB Scanner       | - Disassembler      |
|  - VMT Hook           | - Memory Patch      | - Reloc Processing  |
|  - Syscall Hook       | - Page Protection   | - Import/Export     |
|  - Trampoline Gen     | - Code Cave Finder  |                     |
|-------------------------------------------------------------------|
|  Process Layer        | Platform Layer      | Utilities           |
|  - Process Enum       | - OS Detection      | - Result<T,E>       |
|  - Module Mgmt        | - Arch Detection    | - Logger            |
|  - Thread Control     | - NT API Resolver   | - Scope Guard       |
|  - Token/Privilege    |                     | - FNV-1a Hash       |
+-------------------------------------------------------------------+
```

## Platform Support

| Platform | Architecture | Status |
|----------|-------------|--------|
| Windows 11/10 | x64 | Fully supported |
| Windows 11/10 | x86 | Fully supported |
| Windows 11 | ARM64 | Trampoline support |
| Windows 8.1/7 | x86/x64 | Supported (limited testing) |
| Linux | x64 | Partial (memory scanning, PE parsing) |

## Quick Start

### Building

```bash
git clone https://github.com/bypasscore/bypasscore-sdk.git
cd bypasscore-sdk
cmake -B build -DBYPASSCORE_BUILD_TESTS=ON -DBYPASSCORE_BUILD_EXAMPLES=ON
cmake --build build --config Release
```

### Basic Usage

#### Hook a Function

```cpp
#include "bypasscore/hook/detour.h"

using MessageBoxA_t = int(WINAPI*)(HWND, LPCSTR, LPCSTR, UINT);
MessageBoxA_t orig = nullptr;

int WINAPI hooked(HWND h, LPCSTR text, LPCSTR cap, UINT type) {
    printf("Intercepted: %s\n", text);
    return orig(h, "[Hooked]", cap, type);
}

bypasscore::hook::DetourHook hook;
hook.install(GetProcAddress(GetModuleHandleA("user32"), "MessageBoxA"),
             hooked, &orig);
```

#### Scan for a Pattern

```cpp
#include "bypasscore/memory/scanner.h"

auto result = bypasscore::memory::find_pattern(
    data, size, "48 8B 05 ?? ?? ?? ?? 48 85 C0");
if (result && *result)
    printf("Found at offset: 0x%zX\n", **result);
```

#### Parse a PE File

```cpp
#include "bypasscore/binary/pe.h"

auto pe = bypasscore::binary::PeImage::parse(data, size);
if (pe) {
    printf("Image base: 0x%llX\n", pe->image_base());
    for (const auto& sec : pe->sections())
        printf("  %s: 0x%X (%zu bytes)\n",
               sec.name.c_str(), sec.virtual_address, sec.virtual_size);
}
```

## Module Overview

### Hook Engine (`include/bypasscore/hook/`)

| Component | Description |
|-----------|-------------|
| `detour.h` | Inline detour hooking with automatic trampoline generation |
| `iat_hook.h` | Import Address Table patching for per-module interception |
| `vmt_hook.h` | Virtual Method Table swapping for C++ object hooks |
| `syscall_hook.h` | NT syscall stub patching for kernel-boundary interception |
| `trampoline.h` | Low-level trampoline code generation (x86, x64, ARM64) |
| `engine.h` | Central hook lifecycle management |

### Memory Engine (`include/bypasscore/memory/`)

| Component | Description |
|-----------|-------------|
| `region.h` | Memory region enumeration and abstraction |
| `scanner.h` | AOB pattern scanning with SIMD acceleration (SSE2) |
| `patch.h` | Transactional memory patching with rollback |
| `protection.h` | RAII page protection manipulation |
| `allocator.h` | Code cave finder and near-address trampoline allocator |

### Binary Analysis (`include/bypasscore/binary/`)

| Component | Description |
|-----------|-------------|
| `pe.h` | Complete PE32/PE32+ parser (headers, sections, imports, exports) |
| `disasm.h` | Lightweight x86/x64 instruction length disassembler |
| `reloc.h` | Base relocation table parsing and application |

### Process Layer (`include/bypasscore/process/`)

| Component | Description |
|-----------|-------------|
| `process.h` | Process enumeration, memory read/write, module listing |
| `module.h` | Module abstraction with PE integration |
| `thread.h` | Thread enumeration, suspend/resume |
| `token.h` | Token privilege management (SeDebugPrivilege, etc.) |

### Platform (`include/bypasscore/platform/`)

| Component | Description |
|-----------|-------------|
| `os.h` | OS detection via RtlGetVersion (bypasses compatibility shims) |
| `arch.h` | Compile-time architecture detection |
| `ntapi.h` | Dynamically resolved undocumented NT API declarations |

## Performance

Pattern scanning benchmarks (1GB buffer, 16-byte pattern):

| Method | Throughput |
|--------|-----------|
| Scalar scan | ~2.1 GB/s |
| SSE2 SIMD scan | ~8.4 GB/s |

Hooking overhead per call:

| Hook Type | Overhead |
|-----------|----------|
| Inline Detour | ~2-5 ns |
| IAT Hook | ~1 ns (pointer indirection) |
| VMT Hook | ~1 ns (pointer indirection) |

## Python Bindings

```bash
cd bindings/python
pip install pybind11
python setup.py build_ext --inplace
```

```python
import pybypasscore as bc

bc.initialize()
print(bc.get_os_version())
print(bc.fnv1a_32("CreateFileW"))

offset = bc.scan_buffer(data, "48 8B 05 ?? ?? ?? ??")
procs = bc.enumerate_processes()
```

## Tools

- **`bc_dump`** - PE header dump utility
- **`bc_scan`** - Standalone file pattern scanner

## Research References

This SDK draws from extensive research in the security community:

- [Microsoft PE/COFF Specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Intel x86/x64 Software Developer Manuals](https://www.intel.com/sdm)
- [ARM Architecture Reference Manual](https://developer.arm.com/documentation/)
- [Windows Internals (Russinovich et al.)](https://learn.microsoft.com/en-us/sysinternals/)
- [Detours: Binary Interception of Win32 Functions (Hunt & Brubacher, 1999)](https://www.microsoft.com/en-us/research/project/detours/)

## Responsible Use

This SDK is intended for **authorized security research, education, and legitimate software development only**. By using this software, you agree to:

- Only test on systems you own or have written authorization to test
- Comply with all applicable laws and regulations in your jurisdiction
- Not use this software for malicious purposes, piracy, or unauthorized access
- Report any vulnerabilities you discover responsibly

See [SECURITY.md](SECURITY.md) for our security policy and vulnerability reporting process.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contact

Building on BypassCore SDK? Need commercial licensing, custom modules, or integration support?

- **Email:** [contact@bypasscore.com](mailto:contact@bypasscore.com)
- **Telegram:** [@bypasscore](https://t.me/bypasscore)
- **Web:** [bypasscore.com](https://bypasscore.com)

Copyright (c) 2017-2026 BypassCore Labs
