# Mobiro Progress Log

> Live engineering record for **Mobiro** — a clean-room, Bring-Your-Own-Files (BYOF) ARM64 Android native runtime container for *Sekiro: Shadows Die Twice*.

---

## Log Entries

### Increment 7 — M5: `IXAudio2` COM Voice Vtables, Vulkan Touch HUD Vertex Packer & CI Artifact / Upstream Build Workflows (2026-11-27)
- **Status:** Implemented & verified (local MSVC 2022 + GitHub Actions Linux GCC & Android ARM64 NDK)
- **Changes:**
  - Implemented Win64 binary-compatible `IXAudio2` / `IXAudio2Voice` / `IXAudio2SourceVoice` COM vtables (`app/src/main/cpp/audio/xaudio2_com.hpp`) supporting `CreateMasteringVoice`, `CreateSourceVoice` (PCM16 and IEEE float32, mono upmix & stereo, per-voice volume gain), `SubmitSourceBuffer` feeding `AAudioXAudioBridge`, `Start`/`Stop`, `GetState`, and `IUnknown` refcounting; wired `thunk_XAudio2Create` in `win32_shim.cpp` to return real COM objects.
  - Implemented `TouchOverlayVk` (`app/src/main/cpp/gfx/touch_overlay_vk.hpp`) converting `TouchController` screen-space quads into tightly packed Vulkan NDC triangle vertices (24B/vertex) with automatic hide/show switching between physical controllers and touchscreen in `runtime_main.cpp`.
  - Updated `.github/workflows/ci.yml` (`actions/checkout@v5`) to publish `mobiro-arm64-debug-apk` (`app-debug.apk`) as a downloadable artifact on every CI run.
  - Added dispatchable `.github/workflows/build-third-party.yml` to cross-compile upstream open-source Box64, Mesa Turnip (`libvulkan_freedreno.so`), and native AArch64 DXVK (`libdxvk_{d3d11,dxgi}.so`) for `arm64-v8a` on demand.
  - Added `test_xaudio2_com_and_touch_overlay_vk` in `tests/test_core.cpp`, forced `#undef NDEBUG` so Release CI builds execute every `assert(...)`, and fixed a worker-thread VA leak (`Win64ThreadEnv::init_worker_thread` no longer allocates a redundant 16 MB process heap per `CreateThread`).

---

### Increment 6 — M4: Persistent Save Storage, Multi-Touch XInput Controller + HUD Quads & Pipeline Cache Pre-Warmer (2026-11-27)
- **Commit:** `cb8d8cc` (CI Run `45858840945` — Linux GCC tests 17s, Android ARM64 APK 1m17s)
- **Status:** Implemented & verified (local MSVC 2022 + GitHub Actions Linux GCC & Android ARM64 NDK)
- **Changes:**
  - Separated persistent `filesDir/saves_overlay` from `cacheDir` across `MainActivity.kt` and `runtime_main.cpp` so Android's cache eviction never deletes Sekiro save games.
  - Implemented `TouchController` (`app/src/main/cpp/input/touch_controller.hpp`): zero-debounce landscape Sekiro combat layout (`L1` Deflect, `R1` Attack, `B` Dodge/Mikiri, `A` Jump, `L2`/`R2`, `R3` Lock-On), left-half floating movement thumbstick, right-half relative camera look, and flat screen-space `HudQuad` geometry generation for single-draw in-swapchain Vulkan rendering.
  - Wired `AINPUT_SOURCE_TOUCHSCREEN` multi-touch pointer events and `ANativeWindow` viewport dimensions into `runtime_main.cpp`.
  - Implemented `PipelineCacheWarmer` (`app/src/main/cpp/gfx/pipeline_cache_warmer.hpp`) running on Efficiency cores to prune stale build cache directories and pre-read active DXVK/Turnip cache files into the OS page cache at startup.
  - Added `test_touch_controller_and_cache_warmer` in `tests/test_core.cpp`.

---

### Increment 5 — M3: Writable Save-Game VFS Overlay, `CreateThread` + `WaitOnAddress` & `XAudio2` → `AAudio` Bridge (2026-11-27)
- **Commit:** `81568e6` (CI Run `45858200668` — Linux GCC tests 15s, Android ARM64 APK 1m22s)
- **Status:** Implemented & verified (local MSVC 2022 + GitHub Actions Linux GCC & Android ARM64 NDK)
- **Changes:**
  - Added copy-on-write writable save-game overlay (`set_write_overlay` / `resolve_for_write` with path-traversal guard) to `VfsMapper` and `WriteFile`/`FlushFileBuffers`/`GENERIC_WRITE` routing in `FileHandleTable` so save files never mutate the user's read-only BYOF PC directory.
  - Implemented `GuestThreadTable` (`CreateThread` with per-thread `Win64Teb` + automatic `ThreadBalancer` worker core binding + `WaitForSingleObject` join) and `AddressWaitTable` (`WaitOnAddress` / `WakeByAddressSingle` / `WakeByAddressAll`) in `app/src/main/cpp/cpu_mem/win32_thread_wait.hpp`.
  - Implemented `AAudioXAudioBridge` (`app/src/main/cpp/audio/aaudio_xaudio_bridge.hpp`) with a lock-free SPSC stereo float32 PCM ring buffer feeding Android's `AAUDIO_PERFORMANCE_MODE_LOW_LATENCY` stream, linked `libaaudio` in `CMakeLists.txt`, and wired `xaudio2_7.dll`/`xaudio2_9.dll!XAudio2Create`.
  - Added `test_vfs_write_overlay_threads_wait_and_audio` in `tests/test_core.cpp` verifying save overlay isolation, path traversal rejection, `CreateThread` + `WaitOnAddress` cross-thread sync, and `XAudio2` PCM ring buffer drain/underrun zero-fill.

---

### Increment 4 — M2: Native AArch64 DXVK & Mesa Turnip Interop, `ANativeWindow` Lifecycle & MS-x64 D3D11 Marshaling (2026-11-27)
- **Commit:** `b71e9d9` (CI Run `45857162080` — Linux GCC tests 15s, Android ARM64 APK 1m12s)
- **Status:** Implemented & verified (local MSVC 2022 + GitHub Actions Linux GCC & Android ARM64 NDK)
- **Changes:**
  - Implemented `DxvkInterop` (`app/src/main/cpp/gfx/dxvk_interop.hpp`) for dynamic `dlopen` loading of source-built native AArch64 `libdxvk_d3d11.so` + `libdxvk_dxgi.so`, `ANativeWindow` surface generation tracking, and `30/60 FPS` frame interval pacing.
  - Replaced placeholder graphics thunks in `win32_shim.cpp` with full 10-arg `D3D11CreateDevice`, 12-arg `D3D11CreateDeviceAndSwapChain`, and `CreateDXGIFactory1`/`2` MS-x64 register + stack marshaling into native AArch64 DXVK.
  - Wired `APP_CMD_INIT_WINDOW` / `APP_CMD_TERM_WINDOW` and thermal FPS step-down into `runtime_main.cpp`.
  - Added transparent Android NDK Meson cross-build scripts: `scripts/build_turnip_android.sh` (Mesa Freedreno Turnip `libvulkan_freedreno.so`) and `scripts/build_dxvk_android.sh` (native AArch64 `libdxvk_d3d11.so` + `libdxvk_dxgi.so`).
  - Added `test_dxvk_interop_and_ms_x64_marshaling` in `tests/test_core.cpp` verifying 10-arg MS-x64 D3D11CreateDevice marshaling, DXGI factory creation, and thermal frame pacing intervals.

---

### Increment 3 — M1-b: Guest Executor, SEH `.pdata` Unwind Registry, Win32 Heap/Events & Box64 Build Script (2026-11-27)
- **Commit:** `c939700` (CI Run `45856320605` — Linux GCC tests 11s, Android ARM64 APK 1m27s)
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
- **Increment 8 (M6 — On-Device Validation & Upstream Binary Packaging):** Run the dispatchable `build-third-party.yml` workflow to verify upstream `box64`/`Turnip`/`DXVK` cross-builds, attach the Vulkan SPIR-V HUD draw pass to `libdxvk_dxgi.so` swapchain presentation, and validate real-device boot on Adreno 7xx/8xx hardware.
