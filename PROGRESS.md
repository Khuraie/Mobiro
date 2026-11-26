# Mobiro Progress Log

> Live engineering record for **Mobiro** — a clean-room, Bring-Your-Own-Files (BYOF) ARM64 Android native runtime container for *Sekiro: Shadows Die Twice*.

---

## Log Entries

### Increment 3 — M1-b: Guest Executor, SEH `.pdata` Unwind Registry, Win32 Heap/Events & Box64 Build Script (2026-11-27)
- **Status:** Implemented & verified (local MSVC 2022 + GitHub Actions Linux GCC & Android ARM64 NDK)
- **Changes:**
  - Implemented `GuestHeap`, `EventTable`, `Win64SystemInfo`, and `SehUnwindRegistry` (`app/src/main/cpp/cpu_mem/win32_proc_sync.hpp`), adding `GetProcessHeap`, `HeapAlloc`, `HeapReAlloc`, `HeapFree`, `HeapSize`, `CreateEventW`/`A`, `SetEvent`, `ResetEvent`, `WaitForSingleObject`, unified `CloseHandle`, `GetLastError`/`SetLastError`, `GetSystemInfo`, and `RtlLookupFunctionEntry`.
  - Implemented `GuestExecutor` (`app/src/main/cpp/cpu_mem/guest_executor.hpp`) setting up Win64 16-byte stack alignment + `GS`/TEB binding, with both the embedded Box64 integration hook (`MOBIRO_HAVE_BOX64`) and a built-in x86_64 smoke-test dispatcher for CI end-to-end verification of `GS:[0x30]` reads and indirect IAT `CALL [RIP+disp32]` trampolines.
  - Added transparent Android NDK `arm64-v8a` cross-build script for upstream Box64 (`scripts/build_box64_android.sh`).
  - Wired `.pdata` SEH registration into `runtime_main.cpp` and added `test_x86_64_guest_execution_and_seh` in `tests/test_core.cpp` executing real x86_64 machine code from a loaded PE32+ image through IAT-patched `GetProcessHeap` + `HeapAlloc`.

---

### Increment 2 — M1 Core: PE64 Loader, Win64 TEB/PEB & Win32 VFS File/Sync Shims (2026-11-27)
- **Commit:** `156caa9` (CI Run `45855341708` — Linux GCC tests 11s, Android ARM64 APK 1m15s)
- **Status:** Implemented & verified (local MSVC 2022 + GitHub Actions Linux GCC & Android ARM64 NDK)
- **Changes:**
  - Upgraded `GuestArena` (`app/src/main/cpp/cpu_mem/guest_arena.hpp`) with portable `MemProt` flags and real OS virtual memory backing on both Android (`mmap`/`mprotect`/`madvise`) and Windows hosts (`VirtualAlloc`/`VirtualProtect`/`VirtualFree`).
  - Implemented `PeLoader` (`app/src/main/cpp/cpu_mem/pe_loader.hpp`): maps Win64 PE32+ headers & sections into `GuestArena`, applies `IMAGE_REL_BASED_DIR64` / `IMAGE_REL_BASED_HIGHLOW` base relocations, patches IAT entries with Box64 `NativeBridgeStub` trampolines, records `.pdata` (SEH) and TLS directories, and reports unresolved imports.
  - Implemented `Win64Teb` / `Win64Peb` (`app/src/main/cpp/cpu_mem/win64_teb.hpp`) with static-asserted x64 ABI offsets (`GS:[0x30]`, `GS:[0x60]`, `GS:[0x1480]` TLS slots).
  - Implemented VFS-backed Win32 file I/O & sync primitives (`app/src/main/cpp/cpu_mem/win32_file_sync.hpp` + `win32_shim.cpp`): `CreateFileW`/`CreateFileA`, `ReadFile` (including `OVERLAPPED` 64-bit random-access offsets for `.bdt` archives), `SetFilePointerEx`, `GetFileSizeEx`, `CloseHandle`, `SRWLock`, 10 MHz `QueryPerformanceCounter`/`QueryPerformanceFrequency`, `TlsAlloc`/`TlsSetValue`/`TlsGetValue`, `GetCurrentThreadId`/`GetCurrentProcessId`, `GetModuleHandleW`, and `VirtualProtect`.
  - Wired `PeLoader` + `Win64ThreadEnv` into `runtime_main.cpp` startup sequence.
  - Expanded `tests/test_core.cpp` to verify forced DIR64 PE64 relocation, IAT stub patching, TEB/PEB + TLS thunks, QPC timing, and UTF-16LE `CreateFileW` + `OVERLAPPED` `ReadFile` against VFS.

---

### Increment 1 — M0 Foundation & CI Green (2026-11-26)
- **Commits:** `1d2fbb3`, `6a35d4e`, `da876b7`
- **Status:** Complete & CI Green (Run `45854144576`)
- **Changes:**
  - Scaffolded clean Android Gradle + Kotlin `GameActivity` container (`com.mobiro.runtime`, SDK 35, NDK `27.2.12479018`, flexible 16KB page support, `ThermalMonitor`, SAF BYOF picker).
  - Built clean-room PE32+ & `Data0`–`Data5` `.bhd`/`.bdt` (`BDF4`) validator and case-insensitive `VfsMapper` (zero copyrighted assets or decryption keys).
  - Built initial `GuestArena`, `Box64Bridge` native thunk table, `Turnip` ICD `dlopen` loader with fallback, dynamic UMA `dxvk.conf` generator, lock-free seqlock `InputRouter`, and dynamic big.LITTLE + ADPF `ThreadBalancer`.
  - Added open-source `fetch_third_party.{sh,ps1}` scripts (Box64, DXVK, Mesa Turnip) and GitHub Actions CI (`C++20 Core Unit Tests` + `Android ARM64 NDK Build`).
- **Verification:**
  - Local MSVC 2022 + CMake: `mobiro_core_tests` `1/1 Passed`.
  - GitHub Actions CI: Linux GCC C++20 tests passed (18s); Android ARM64 Debug APK assembled cleanly (2m6s).

---

## Upcoming Increments
- **Increment 4 (M2):** Cross-compile native AArch64 `DXVK` + `Mesa Turnip` (`libvulkan_freedreno.so`) from source, add `dxvk_interop.cpp` (`ANativeWindow` → `VK_KHR_android_surface` + `SwappyVk`), and wire `D3D11CreateDevice`/`CreateDXGIFactory1` thunks.
- **Increment 5 (M3):** Win32 `CreateThread` + `ThreadBalancer` auto-classification, writable save-game VFS overlay, `WaitOnAddress` futex sync, and `XAudio2` → `AAudio` bridge.
- **Increment 6 (M4):** In-swapchain Vulkan touch HUD overlay and GPL pipeline pre-warming.
