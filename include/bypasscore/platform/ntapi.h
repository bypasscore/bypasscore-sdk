#pragma once

#ifdef _WIN32

#include <windows.h>
#include <cstdint>

namespace bypasscore {
namespace platform {

// Undocumented NT API declarations for low-level system interaction.
// These are resolved dynamically from ntdll.dll at runtime.

using NTSTATUS = LONG;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

enum SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemProcessInformation = 5,
    SystemModuleInformation = 11,
    SystemHandleInformation = 16,
    SystemKernelDebuggerInformation = 35
};

enum MEMORY_INFORMATION_CLASS_NT {
    MemoryBasicInformationNt = 0,
    MemoryWorkingSetInformation = 1,
    MemoryMappedFilenameInformation = 2
};

struct UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
};

struct OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    UNICODE_STRING* ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
};

struct CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
};

struct SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryBase;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
};

// Function pointer types for dynamically resolved NT APIs
using NtQuerySystemInformation_t = NTSTATUS(NTAPI*)(
    SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

using NtQueryVirtualMemory_t = NTSTATUS(NTAPI*)(
    HANDLE, PVOID, MEMORY_INFORMATION_CLASS_NT, PVOID, SIZE_T, PSIZE_T);

using NtReadVirtualMemory_t = NTSTATUS(NTAPI*)(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

using NtWriteVirtualMemory_t = NTSTATUS(NTAPI*)(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

using NtAllocateVirtualMemory_t = NTSTATUS(NTAPI*)(
    HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

using NtProtectVirtualMemory_t = NTSTATUS(NTAPI*)(
    HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

using NtOpenProcess_t = NTSTATUS(NTAPI*)(
    PHANDLE, ACCESS_MASK, OBJECT_ATTRIBUTES*, CLIENT_ID*);

/**
 * @brief Resolve NT API functions from ntdll.dll.
 */
class NtApi {
public:
    static NtApi& instance() {
        static NtApi api;
        return api;
    }

    NtQuerySystemInformation_t NtQuerySystemInformation = nullptr;
    NtQueryVirtualMemory_t     NtQueryVirtualMemory     = nullptr;
    NtReadVirtualMemory_t      NtReadVirtualMemory      = nullptr;
    NtWriteVirtualMemory_t     NtWriteVirtualMemory     = nullptr;
    NtAllocateVirtualMemory_t  NtAllocateVirtualMemory  = nullptr;
    NtProtectVirtualMemory_t   NtProtectVirtualMemory   = nullptr;
    NtOpenProcess_t            NtOpenProcess             = nullptr;

    bool is_loaded() const { return loaded_; }

private:
    NtApi() {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return;

        NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformation_t>(
            GetProcAddress(ntdll, "NtQuerySystemInformation"));
        NtQueryVirtualMemory = reinterpret_cast<NtQueryVirtualMemory_t>(
            GetProcAddress(ntdll, "NtQueryVirtualMemory"));
        NtReadVirtualMemory = reinterpret_cast<NtReadVirtualMemory_t>(
            GetProcAddress(ntdll, "NtReadVirtualMemory"));
        NtWriteVirtualMemory = reinterpret_cast<NtWriteVirtualMemory_t>(
            GetProcAddress(ntdll, "NtWriteVirtualMemory"));
        NtAllocateVirtualMemory = reinterpret_cast<NtAllocateVirtualMemory_t>(
            GetProcAddress(ntdll, "NtAllocateVirtualMemory"));
        NtProtectVirtualMemory = reinterpret_cast<NtProtectVirtualMemory_t>(
            GetProcAddress(ntdll, "NtProtectVirtualMemory"));
        NtOpenProcess = reinterpret_cast<NtOpenProcess_t>(
            GetProcAddress(ntdll, "NtOpenProcess"));

        loaded_ = true;
    }

    bool loaded_ = false;
};

} // namespace platform
} // namespace bypasscore

#endif // _WIN32
