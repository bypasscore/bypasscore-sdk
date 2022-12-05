/**
 * @file hook_messagebox.cpp
 * @brief Example: Hook MessageBoxA to modify the message text.
 *
 * Demonstrates DetourHook usage with a simple Win32 API hook.
 */

#include "bypasscore/bypasscore.h"
#include "bypasscore/hook/detour.h"
#include <cstdio>

#ifdef _WIN32
#include <windows.h>

using MessageBoxA_t = int(WINAPI*)(HWND, LPCSTR, LPCSTR, UINT);
static MessageBoxA_t orig_MessageBoxA = nullptr;

int WINAPI hk_MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    printf("[BypassCore] MessageBoxA intercepted!\n");
    printf("  Original text: %s\n", lpText);
    printf("  Caption: %s\n", lpCaption);

    // Modify the message and forward to the original
    return orig_MessageBoxA(hWnd, "[Hooked by BypassCore] Hello!", lpCaption, uType);
}

int main() {
    printf("BypassCore SDK - Hook MessageBoxA Example\n");
    printf("==========================================\n\n");

    bypasscore::initialize();

    bypasscore::hook::DetourHook hook;
    auto result = hook.install(
        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA")),
        reinterpret_cast<void*>(hk_MessageBoxA),
        &orig_MessageBoxA);

    if (!result) {
        printf("Failed to install hook!\n");
        return 1;
    }

    printf("Hook installed successfully.\n");
    printf("Calling MessageBoxA...\n\n");

    MessageBoxA(nullptr, "Original message", "Test", MB_OK);

    printf("\nRemoving hook...\n");
    hook.remove();

    printf("Calling MessageBoxA again (should be original)...\n");
    MessageBoxA(nullptr, "This should be unmodified", "Test", MB_OK);

    bypasscore::shutdown();
    return 0;
}
#else
int main() {
    printf("This example requires Windows.\n");
    return 0;
}
#endif
