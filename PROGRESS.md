# Mobiro Progress Log

> Live engineering record for **Mobiro** — a clean-room, Bring-Your-Own-Files (BYOF) ARM64 Android native runtime container for *Sekiro: Shadows Die Twice*.

---

## Log Entries

### Increment 12 — M10: Android `ANativeWindow` DXVK WSI Backend (`VK_KHR_android_surface`), Embedded Box64 PIC Static Core & XMM3 Float COM Forwarding (2026-11-27)
- **Status:** Implemented & verified (local MSVC 2022 + GitHub Actions Linux GCC/`spirv-val` + Android ARM64 NDK + upstream DXVK/Box64 full-stack rebuild)
- **Changes:**
  - Implemented `AndroidWsiDriver` (`patches/dxvk/wsi_platform_android.{h,cpp}`) and idempotent injector `scripts/patch_dxvk_android_wsi.py` wired into `scripts/build_dxvk_android.sh`, enabling native AArch64 DXVK (`libdxvk_dxgi.so` / `libdxvk_d3d11.so`) to create real `VK_KHR_android_surface` Vulkan surfaces directly against the live `ANativeWindow*` exported via `mobiro_get_android_native_window()` in `runtime_main.cpp`.
  - Upgraded `scripts/build_box64_android.sh` to build position-independent (`-DCMAKE_POSITION_INDEPENDENT_CODE=ON`) Box64 objects and archive all non-`main.c.o` core + ARM64 Dynarec objects into `libbox64_core.a`; added pure-C11 `app/src/main/cpp/cpu_mem/box64_c_shim.c` so `libsekiro_runtime.so` links and invokes Box64's `DynaRun` cleanly without exposing C-only internal Box64 headers to C++20.
  - Added Win64 `XMM0–3` scalar float support in `box64_bridge.hpp` and wired `ID3D11DeviceContext::ClearDepthStencilView` (slot 53) float forwarding + automatic `D3D11ComBridge` proxy wrapping (`D3D11CreateDevice`, `D3D11CreateDeviceAndSwapChain`, `CreateDXGIFactory1`) + `DxvkInterop::pace_present()` 30/60 FPS `Present` hook + `DllMain`/TLS callback execution on `LoadLibraryW` and startup.
  - Added `test_m10_xmm_com_auto_wrap_and_dllmain_tls` in `tests/test_core.cpp` (11/11 test suites passing).

---

### Increment 11 — M9: Native AArch64 DXVK Green (All 3 Upstream Layers Verified) & Bundled Full-Stack APK Workflow (2026-11-27)
- **Status:** Implemented & verified on GitHub Actions NDK `27.2.12479018`
- **Changes:**
  - Initialized DXVK's official Khronos/subproject submodules (`SPIRV-Headers`, `Vulkan-Headers`, `libdisplay-info`, `dxbc-spirv`) in `scripts/fetch_third_party.{sh,ps1}` and isolated `pkg-config = 'false'` in `scripts/build_dxvk_android.sh` (commit `286269f`).
  - Verified **native AArch64 DXVK (`libdxvk_d3d11.so` + `libdxvk_dxgi.so`) compiled cleanly and uploaded artifacts** in 2m49s on GitHub Actions (Run `45864612958`) — completing from-source `arm64-v8a` cross-build verification for all three upstream open-source pillars (**Box64** + **Mesa Turnip** + **Native AArch64 DXVK**).
  - Upgraded `.github/workflows/build-third-party.yml` to default `build_dxvk: true` and added `assemble_bundled_apk: true`, assembling and uploading a complete sideloadable `mobiro-arm64-bundled-debug-apk` packaging `libsekiro_runtime.so`, `libvulkan_freedreno.so`, `libdxvk_d3d11.so`, and `libdxvk_dxgi.so`.

---

### Increment 10 — M8: Mesa Turnip `arm64-v8a` Green, Generated Win64→ARM64 D3D11/DXGI COM Bridge, Extended Win32/DirectInput8 Shims, Vulkan HUD Draw Pass & `spirv-val` CI (2026-11-27)
- **Commit:** `eaa92c2` (CI Run `45864147018` — Linux GCC tests + Khronos `spirv-val` 37s, Android ARM64 APK 1m24s)
- **Status:** Implemented & verified (local MSVC 2022 + GitHub Actions Linux GCC + `spirv-val` + Android ARM64 NDK)
- **Changes:**
  - Verified upstream **Mesa Turnip ICD (`libvulkan_freedreno.so`) `arm64-v8a` cross-build passed and uploaded artifact** on GitHub Actions NDK `27.2.12479018` (Run `45863055424`), meaning both Box64 and Mesa Turnip now build cleanly from upstream source.
  - Added Python COM metadata generator (`scripts/gen_d3d11_thunks.py` → `app/src/main/cpp/gfx/d3d11_com_thunks_gen.hpp`, 6 DXGI/D3D11 interfaces, 204 vtable slots) and `D3D11ComBridge` (`app/src/main/cpp/gfx/d3d11_com_bridge.hpp`) providing `NativeBridgeStub`-backed Win64 → ARM64 COM proxy vtables with `IDXGISwapChain::Present` hook interception and automatic proxy cleanup on `Release() == 0`.
  - Updated `scripts/build_dxvk_android.sh` to current upstream DXVK Meson options (`-Dnative_*=disabled`) and `CMakeLists.txt` to auto-link `third_party/prebuilt/arm64-v8a/box64/lib/libbox64*.a` when present.
  - Added `GuestExecutor::call_guest_fn` & `run_tls_callbacks` (`IMAGE_TLS_DIRECTORY64` callbacks), `win32_ext_shims.hpp` (`GlobalMemoryStatusEx`, `DirectInput8Create` COM stub), and 25+ extended Win32 shims (`GetFileAttributesW/A`, `CreateDirectoryW`, `GetModuleFileNameW/A`, `MultiByteToWideChar`/`WideCharToMultiByte`, `EncodePointer`/`DecodePointer`, `Fls*`, `advapi32` registry stubs).
  - Added dynamic Vulkan draw-command recording (`TouchOverlayVk::record_draw_commands`), `--dump-spirv` export in `tests/test_core.cpp`, and real Khronos `spirv-val --target-env vulkan1.0` validation in `.github/workflows/ci.yml`.

---

### Increment 9 — M7: Dynamic Guest DLL Loader (`LoadLibrary`/`GetProcAddress`), Headless `user32`/`shell32`/`ole32`/`winmm`/`bcrypt` & Upstream Box64 Green + Turnip Fix (2026-11-27)
- **Commit:** `1ea1843` (CI Run `45862992744` — Linux GCC tests 30s, Android ARM64 APK + artifact upload 1m32s; Turnip Run `45863055424` PASS)
- **Status:** Implemented & verified (local MSVC 2022 + GitHub Actions Linux GCC & Android ARM64 NDK)
- **Changes:**
  - Verified upstream **Box64 `arm64-v8a` ARM64 Dynarec cross-compilation passed** on GitHub Actions NDK 27.2.12479018 (Run `45862062389`), and fixed Mesa Turnip's host `zstd.h` leak in `scripts/build_turnip_android.sh` (`-Dzstd=disabled -Dxmlconfig=disabled -Dlibunwind=disabled`).
  - Added PE64 Export Directory (`DataDirectory[0]`) parsing to `PeLoader` and implemented `ModuleRegistry` (`app/src/main/cpp/cpu_mem/win32_module_mgr.hpp`) backing `LoadLibraryW`/`A`/`ExW`, `GetModuleHandleW`/`A`, `GetProcAddress` (both guest DLL exports by name/ordinal and native-thunked Win32 DLLs), and `FreeLibrary`.
  - Implemented `HeadlessWindowState` (`app/src/main/cpp/cpu_mem/win32_ui_misc.hpp`) and wired headless `user32.dll` (`RegisterClassEx`, `CreateWindowEx`, `GetClientRect`/`GetWindowRect`, `GetSystemMetrics`, `PeekMessage`, `PostQuitMessage`), `shell32.dll` (`SHGetKnownFolderPath`/`SHGetFolderPathW` routing `%APPDATA%` saves into VFS overlay), `ole32.dll` (`CoInitializeEx`/`CoTaskMemAlloc`/`CoTaskMemFree`), `winmm.dll` (`timeGetTime`/`timeBeginPeriod`), and `bcrypt.dll` (`BCryptGenRandom`).
  - Added `test_module_loader_and_headless_win32_ui` in `tests/test_core.cpp` verifying live synthetic guest DLL export loading, native-thunked `GetProcAddress`, headless `user32` message pump, `SHGetKnownFolderPath`, and `BCryptGenRandom`.

---

### Increment 8 — M6: XAudio2.7 COM Vtable + Linear Resampler, MSVC CRT Startup Shims, Embedded SPIR-V HUD Shaders & Upstream Cross-Build Fix (2026-11-27)
- **Commit:** `837568b` (CI Run `45862004494` — Linux GCC tests 35s, Android ARM64 APK + artifact upload 1m20s)
- **Status:** Implemented & verified (local MSVC 2022 + GitHub Actions Linux GCC & Android ARM64 NDK)
- **Changes:**
  - Added legacy `IXAudio2_7Vtbl` (`GetDeviceCount`, `GetDeviceDetails`, `Initialize`, `CreateMasteringVoice` 7-arg signature) alongside `IXAudio2Vtbl` (XAudio2.9) and a stereo linear sample-rate resampler (`src_rate -> 48 kHz`) in `app/src/main/cpp/audio/xaudio2_com.hpp`, wiring `xaudio2_7.dll` and `xaudio2_9.dll` to their exact COM ABIs in `win32_shim.cpp`.
  - Implemented recursive `CriticalSectionTable` (`InitializeCriticalSection*`, `EnterCriticalSection`, `TryEnterCriticalSection`, `LeaveCriticalSection`, `DeleteCriticalSection`) and core MSVC CRT startup Win32 thunks (`GetSystemTimeAsFileTime`, `GetTickCount64`, `Sleep`, `SwitchToThread`, `GetCommandLineW`/`A`, `GetStartupInfoW`, `IsProcessorFeaturePresent`) across `win32_file_sync.hpp`, `box64_bridge.hpp`, and `win32_shim.cpp`.
  - Embedded pre-assembled Vulkan 1.0 SPIR-V vertex & fragment shader modules (`kHudVertSpv`, `kHudFragSpv`) + `spirv::validate_module` structural verifier in `app/src/main/cpp/gfx/touch_overlay_vk.hpp`.
  - Fixed `ANDROID_NDK_HOME` propagation (`$GITHUB_ENV`) in `.github/workflows/build-third-party.yml` discovered during live upstream Box64/Turnip cross-build testing (Run `45861214515`).
  - Expanded `tests/test_core.cpp` to verify XAudio2.7 COM dispatch, 24 kHz → 48 kHz linear resampling, recursive critical sections, CRT startup shims, and SPIR-V shader validation.

---

### Increment 7 — M5: `IXAudio2` COM Voice Vtables, Vulkan Touch HUD Vertex Packer & CI Artifact / Upstream Build Workflows (2026-11-27)
- **Commit:** `e9cd99b` (CI Run `45860781333` — Linux GCC tests 28s, Android ARM64 APK + artifact upload 1m12s)
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
- **Increment 13 (M11 — Steam/FMOD/Game-Specific Import Coverage & Live Adreno 7xx/8xx Boot):** Add clean-room BYOF-compliant Steam stub / missing Win32 CRT & `ntdll` imports discovered against real user-supplied `Sekiro.exe`, attach the `TouchOverlayVk` Vulkan draw pass to the swapchain command buffer, and validate first live Adreno 7xx/8xx handset boot.
