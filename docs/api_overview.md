# BypassCore SDK API Overview

## Core API

### Initialization

```cpp
#include "bypasscore/bypasscore.h"

bool bypasscore::initialize();    // Must be called before using SDK
void bypasscore::shutdown();      // Release all resources
bool bypasscore::is_initialized();
```

## Hook API

### DetourHook

```cpp
#include "bypasscore/hook/detour.h"

class DetourHook {
    template<typename T>
    Result<bool> install(void* target, void* detour, T* original);
    Result<bool> remove();
    bool is_installed() const;
};
```

### IatHook

```cpp
#include "bypasscore/hook/iat_hook.h"

class IatHook {
    Result<bool> install(void* module_base, const char* dll,
                         const char* func, void* detour, void** original);
    Result<bool> remove();
};
```

### VmtHook

```cpp
#include "bypasscore/hook/vmt_hook.h"

class VmtHook {
    Result<bool> initialize(void* object);
    Result<void*> hook(size_t index, void* detour);
    Result<bool> unhook(size_t index);
    void unhook_all();
    void* get_original(size_t index) const;
};
```

### SyscallHook

```cpp
#include "bypasscore/hook/syscall_hook.h"

class SyscallHook {
    static Result<uint32_t> get_syscall_number(void* ntdll_func);
    Result<bool> hook(const char* function_name, void* detour, void** original);
    Result<bool> restore(const char* function_name);
    void restore_all();
};
```

## Memory API

### Pattern Scanner

```cpp
#include "bypasscore/memory/scanner.h"

Result<std::vector<PatternByte>> parse_pattern(const std::string& pattern);
std::optional<size_t> scan_buffer(const uint8_t* data, size_t size,
                                   const std::vector<PatternByte>& pattern);
std::vector<size_t> scan_buffer_all(...);
std::optional<uintptr_t> scan_process(void* handle, const std::string& aob);
```

### PatchManager

```cpp
#include "bypasscore/memory/patch.h"

class PatchManager {
    Result<PatchId> create(uintptr_t address, const std::vector<uint8_t>& bytes);
    Result<bool> apply(PatchId id);
    Result<bool> restore(PatchId id);
    Result<bool> apply_batch(const std::vector<PatchId>& ids);
    void restore_all();

    static Result<std::vector<uint8_t>> write_bytes(uintptr_t addr, ...);
    static Result<bool> nop(uintptr_t address, size_t count);
};
```

### ProtectionGuard

```cpp
#include "bypasscore/memory/protection.h"

class ProtectionGuard {
    ProtectionGuard(void* address, size_t size, RegionAccess new_access);
    explicit operator bool() const;
    bool restore();
};
```

## Binary API

### PeImage

```cpp
#include "bypasscore/binary/pe.h"

class PeImage {
    static Result<PeImage> parse(const uint8_t* data, size_t size);
    bool is_64bit() const;
    MachineType machine() const;
    uint64_t image_base() const;
    const std::vector<Section>& sections() const;
    std::vector<ImportEntry> parse_imports() const;
    std::vector<ExportEntry> parse_exports() const;
    std::optional<uint32_t> rva_to_offset(uint32_t rva) const;
};
```

### LengthDisasm

```cpp
#include "bypasscore/binary/disasm.h"

class LengthDisasm {
    explicit LengthDisasm(Mode mode = Mode::X64);
    size_t length(const uint8_t* code) const;
    size_t calc_overwrite_size(const uint8_t* code, size_t min_bytes) const;
};

size_t insn_length(const void* address, bool is_64bit = true);
```

## Process API

```cpp
#include "bypasscore/process/process.h"

class Process {
    static Result<Process> open(uint32_t pid);
    static Result<Process> open_by_name(const std::string& name);
    static std::vector<ProcessInfo> enumerate();
    Result<std::vector<uint8_t>> read(uintptr_t address, size_t size) const;
    Result<bool> write(uintptr_t address, const void* data, size_t size);
    std::vector<ModuleInfo> modules() const;
};
```

## Utility API

### Result<T, E>

```cpp
#include "bypasscore/util/result.h"

template<typename T, typename E = Error>
class Result {
    bool has_value() const;
    bool has_error() const;
    T& value();
    E& error();
    T value_or(T default_val) const;
    template<typename Fn> auto map(Fn&& fn) const;
};
```

### Hashing

```cpp
#include "bypasscore/util/hash.h"

constexpr uint32_t hash32(const char* str);
constexpr uint64_t hash64(const char* str);
constexpr uint32_t operator""_hash(const char* str, size_t len);
```
