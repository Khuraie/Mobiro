# Mobiro

> **Project Goal:** Build a clean-room, open-source, Bring-Your-Own-Files (BYOF) native ARM64 Android runtime container to run the PC version of *Sekiro: Shadows Die Twice* directly on modern Android devices (Snapdragon/Adreno + Mesa Turnip) — bypassing heavy desktop Windows/X11 emulation layers in favor of in-process CPU dynarec, native ARM64 DXVK thunking, and low-latency Vulkan presentation.

---

## Core Design Principles

1. **Strict BYOF Compliance:** Mobiro contains **zero** copyrighted game assets, proprietary binaries, or decryption keys. Users supply their own legally owned local PC install directory; Mobiro validates structure only (`PE32+` headers, `d3d11.dll` imports, and `Data0`–`Data5` `.bhd`/`.bdt` `BDF4` container magic).
2. **No Opaque Pre-Compiled Blobs:** All translation layers map directly to upstream open-source projects built from source via `scripts/fetch_third_party.*`:
   - **CPU Translation:** Embedded [Box64](https://github.com/ptitSeb/box64) AArch64 Dynarec (`strongmem=1`) with direct MS-x64 → AAPCS64 IAT native thunks.
   - **Graphics (DX11 → Vulkan):** Native AArch64 [DXVK](https://github.com/doitsujin/dxvk) with `VK_EXT_graphics_pipeline_library` stepped compilation and dynamic mobile UMA memory budgeting.
   - **Vulkan Driver:** Direct `dlopen` [Mesa Turnip](https://gitlab.freedesktop.org/mesa/mesa) (`libvulkan_freedreno.so`) bypassing outdated OEM Adreno Vulkan drivers, with automatic fallback to system `libvulkan.so`.
3. **Mobile-First Latency & Pacing:**
   - Lock-free seqlock `InputRouter` translating Android `GameActivity` touch/HID input directly into `XInputGetState` (`d3d11.maxFrameLatency = 1`).
   - Dynamic heterogeneous CPU topology discovery + Android ADPF (`APerformanceHintManager`) separating Main Sim/Physics (Prime core), Render/DXVK CS (Performance cores), and shader compilation/I/O (Efficiency cores).

---

## Architecture Layout

```text
app/src/main/
├── java/com/mobiro/runtime/
│   ├── MainActivity.kt              # GameActivity + SAF BYOF directory binding + trim/thermal hooks
│   └── ThermalMonitor.kt            # Android PowerManager thermal headroom monitor
├── assets/config/dxvk.base.conf     # Base Sekiro + Turnip DXVK profile
└── cpp/
    ├── runtime_main.cpp             # android_main, JNI config/validation, input loop
    ├── validator/                   # PE32+ parser, Data0-5 BDF4 probe, case-insensitive VFS
    ├── cpu_mem/                     # mmap low-47-bit guest arena, Box64 IAT thunk bridge, Win32 shim
    ├── gfx/                         # Turnip ICD dlopen loader, dynamic UMA dxvk.conf generator
    ├── input/                       # Lock-free XInput router (deadzone + cubic curve)
    └── sched/                       # Dynamic big.LITTLE topology + ADPF thread balancer
tests/test_core.cpp                  # Portable C++20 core unit tests
scripts/fetch_third_party.{sh,ps1}   # Transparent upstream open-source fetcher
```

---

## Building & Testing

### 1. Run Portable C++20 Core Tests (Host)
```bash
cmake -S app/src/main/cpp -B build-host -DMOBIRO_BUILD_HOST_TESTS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build-host --parallel
ctest --test-dir build-host --output-on-failure
```

### 2. Fetch Open-Source Submodules (Box64, DXVK, Mesa Turnip)
```bash
./scripts/fetch_third_party.sh        # Linux / macOS
# or
./scripts/fetch_third_party.ps1       # Windows PowerShell
```

### 3. Build Android ARM64 NDK Container
Requires Android SDK 35, NDK `27.2.12479018`, CMake `3.22.1`, and JDK 17:
```bash
gradle :app:assembleDebug
```

### 4. Built-In Clean-Room 60 FPS Self-Test & Trace Toggle (Android)
The CI-assembled bundled APK embeds a clean-room Win64 D3D11 + XAudio2 + XInput 60 FPS payload (`tools/mobiro_selftest.c`, zero game assets):
```bash
# Run 120-frame 60 FPS D3D11/DXVK/TouchHUD self-test without staging 12.5 GB of BYOF files
adb shell am start -n com.mobiro.runtime/.MainActivity --ez selftest true

# Optional: enable verbose Box64 + Win32 API trace logs (off by default for zero-overhead 60 FPS)
adb shell am start -n com.mobiro.runtime/.MainActivity --ez selftest true --ez trace true
```

---

## Roadmap & Progress

See [PROGRESS.md](PROGRESS.md) for the live engineering log of every verified increment.

- [x] **M0 — Clean-Room Container Foundation:** Android `GameActivity` NDK shell, PE32+ & `Data0`–`Data5` `BDF4` BYOF validator, case-insensitive VFS, low-47-bit `mmap` guest arena, IAT thunk bridge, Turnip ICD loader, dynamic `dxvk.conf` UMA generator, lock-free XInput router, ADPF thread balancer, CI + unit tests.
- [x] **M1-a — PE64 Loader, Relocations, TEB/PEB & Win32 VFS/Sync Core:** Section mapper, `DIR64`/`HIGHLOW` relocator, IAT native stub patcher, canonical Win64 `TEB`/`PEB` (`GS:[0x30]`/`GS:[0x60]`), VFS-backed `CreateFileW`/`ReadFile` (`OVERLAPPED`), `SRWLock`, QPC, and TLS thunks.
- [x] **M1-b — Guest Executor, SEH `.pdata` Registry, Win32 Heap/Events & Box64 Build Pipeline:** Implemented `GuestExecutor` (`GS`/TEB + Win64 stack setup + x86_64 IAT dispatch verification), `.pdata` `RtlLookupFunctionEntry` binary search, `GuestHeap` (`HeapAlloc`/`ReAlloc`/`Free`), `EventTable` (`WaitForSingleObject`), and `scripts/build_box64_android.sh`.
- [x] **M2 — Native AArch64 DXVK + Turnip Interop & Build Pipeline:** Implemented `DxvkInterop` (`ANativeWindow` lifecycle + `30/60 FPS` pacing + `dlopen` native DXVK loader), full MS-x64 10/12-arg `D3D11CreateDevice`/`D3D11CreateDeviceAndSwapChain`/`CreateDXGIFactory1` marshaling, and Meson cross-build scripts (`scripts/build_turnip_android.sh`, `scripts/build_dxvk_android.sh`).
- [x] **M3 — Win32 Save Overlay, `CreateThread`/`WaitOnAddress` & `AAudio` Bridge:** Copy-on-write save-game VFS overlay (`WriteFile`/`FlushFileBuffers`), `CreateThread` with per-thread TEB + `ThreadBalancer` binding, `WaitOnAddress`/`WakeByAddress`, and `XAudio2Create` → lock-free `AAudio` stereo PCM bridge.
- [x] **M4 — Multi-Touch XInput Controller, HUD Quads & Pipeline Cache Pre-Warmer:** Zero-debounce Sekiro combat multi-touch controller (`TouchController`), in-swapchain `HudQuad` geometry generator, persistent `filesDir/saves_overlay` separation, and Efficiency-core `PipelineCacheWarmer` with stale cache pruning.
- [x] **M5 — `IXAudio2` COM Voices, Vulkan Touch HUD Packing & Upstream CI Packaging:** Win64 `IXAudio2`/`IXAudio2SourceVoice` COM vtables (PCM16 + float32 -> `AAudio`), `TouchOverlayVk` NDC triangle packer with controller auto-hide, CI `app-debug.apk` artifact upload, and dispatchable `.github/workflows/build-third-party.yml` for upstream `box64`/Turnip/DXVK `arm64-v8a` builds.
- [x] **M6 — XAudio2.7 + Resampler, MSVC CRT Shims & Embedded SPIR-V HUD Shaders:** Dedicated XAudio2.7 vs XAudio2.9 COM vtables, linear audio resampler, recursive `CRITICAL_SECTION` + CRT startup Win32 thunks (`GetSystemTimeAsFileTime`, `GetTickCount64`, `Sleep`, `GetStartupInfoW`, `GetCommandLineW/A`, `IsProcessorFeaturePresent`), embedded Vulkan 1.0 SPIR-V HUD shaders, and `build-third-party.yml` NDK env fix.
- [x] **M7 — Dynamic Guest DLL Loader, Headless `user32`/`shell32`/`ole32`/`winmm`/`bcrypt` & Upstream Box64 Green:** PE64 Export Directory parsing, `LoadLibrary`/`GetProcAddress` for guest & native-thunked DLLs, headless `user32` HWND/message pump synced with `ANativeWindow`, `%APPDATA%` `SHGetKnownFolderPath` save routing, `BCryptGenRandom`, verified upstream Box64 `arm64-v8a` cross-build, and fixed Mesa Turnip cross-build (`-Dzstd=disabled`).
- [x] **M8 — Mesa Turnip `arm64-v8a` Green, D3D11/DXGI COM Bridge, Extended Win32/DirectInput8 & `spirv-val` CI:** Verified from-source Mesa Turnip (`libvulkan_freedreno.so`) alongside Box64 `arm64-v8a`, generated 204-slot Win64 → ARM64 DXGI/D3D11 COM proxy bridge (`scripts/gen_d3d11_thunks.py`, `D3D11ComBridge`), added `DirectInput8Create` + TLS callback runner + 25+ Win32/FS/UTF-16/Registry shims, wired `TouchOverlayVk::record_draw_commands`, and added Khronos `spirv-val --target-env vulkan1.0` validation to CI.
- [x] **M9 — Native AArch64 DXVK Green (All 3 Upstream Layers Verified) & Bundled APK Pipeline:** Verified from-source `arm64-v8a` cross-builds for **Box64** (Run `45862062389`), **Mesa Turnip** `libvulkan_freedreno.so` (Run `45863055424`), and **Native AArch64 DXVK** `libdxvk_{d3d11,dxgi}.so` (Run `45864612958`), and added `assemble_bundled_apk` packaging to `.github/workflows/build-third-party.yml`.
- [x] **M10 — Android `ANativeWindow` DXVK WSI Backend, Embedded Box64 PIC Static Core & XMM Float COM Forwarding:** Added `VK_KHR_android_surface` `AndroidWsiDriver` for native AArch64 DXVK (`patches/dxvk/wsi_platform_android.*`, `scripts/patch_dxvk_android_wsi.py`), packaged position-independent `libbox64_core.a` + C11 `box64_c_shim.c` (`DynaRun`), wired `XMM3` scalar float forwarding (`ClearDepthStencilView`) + automatic COM proxy wrapping + `Present` frame pacing + `DllMain`/TLS callback execution.
- [x] **M11 — Box64 `onebridge_t` Live Native-Thunk Dispatch, Prime-Core Guest Launch & `ntdll`/CRT Sync Expansion:** Aligned `NativeBridgeStub` to exact 32-byte Box64 `onebridge_t` (`0xCC 'S' 'C'`) + clean `0xCC 'S' 'C' 0ULL` exit stub for zero-patch ARM64 Dynarec IAT/COM dispatch, wired Prime-core `guest_thread` launch in `android_main`, and added `ConditionVariable` (`SRW`/`CS`), semaphores, `WaitForMultipleObjects`, `ntdll` `Rtl*` sync, and 30+ MSVC CRT & VFS-safe file shims.
- [x] **M12 — Dependent BYOF DLL Auto-Load, Unresolved-Import Trap Telemetry, Default `CreateThread` Execution & Diagnostics:** Auto-loads statically imported BYOF guest DLLs (`oo2core_6_win64.dll`, `bink2w64.dll`, etc.) in `PeLoader`, patches unresolved IAT slots with safe `onebridge_t` logging traps instead of raw RVAs, wires default `GuestExecutor` execution into `CreateThread`, adds `TouchOverlayVk` pipeline/device-proc specs, and surfaces runtime diagnostics via `MainActivity.nativeGetDiagnosticsSummary`.
- [x] **M13 — Full D3D11/DXGI COM Out-Param Auto-Wrapping, Pointer-Array Unwrapping & Display/Mutex/Find Shims:** Expanded generated COM metadata to 8 interfaces (237 slots), wired automatic Win64 proxy wrapping on `QueryInterface`/`EnumAdapters*`/`CreateSwapChain`/`GetBuffer`/`Create*`/`GetImmediateContext` + zero-heap stack array unwrapping for `OMSetRenderTargets`/`IASetVertexBuffers`/`*SetShaderResources`/`*SetConstantBuffers`, and added `CreateMutex`/`GetMonitorInfoW`/`EnumDisplaySettingsW`/`FindFirstFileW` thunks.
- [x] **M14 — Locked 60 FPS Zero-Drop Optimization Pass:** Replaced `D3D11ComBridge` per-arg mutex/hash lookup with a lock-free 65,536-slot `ComProxyObject` slab, upgraded `DxvkInterop::pace_present()` to hybrid sleep + sub-ms spin with live ADPF closed-loop work reporting & thermal hysteresis, exported tuned Box64 ARM64 Dynarec & Turnip single-file cache defaults (`pthread_once` context init), and registered native ARM64 NEON-backed CRT/`ntdll` memory & string thunks (`memcpy`/`memmove`/`memset`/`memcmp`/`strlen`/`wcslen`/`Rtl*Memory`).
- [x] **M15 — O(1) Segregated Heap, 64-Shard Sync Tables, Parallel Archive I/O & HUD C ABI:** Upgraded `GuestHeap` to O(1) 20-bucket power-of-2 segregated freelists, sharded `SrwLockTable`/`CriticalSectionTable`/`ConditionVariableTable` across 64 cache-line-aligned `shared_mutex` shards (and `alignas(64)` `AddressWaitTable`), switched `FileHandleTable` to per-file I/O locking for parallel `.bdt` streaming, and exported thread-safe `mobiro_touch_overlay_*` C ABI hooks for DXVK's Vulkan present pass.
- [x] **M16 — Box64 `LoadEnvVariables()` Activation, DXVK In-Swapchain Touch HUD Patch & CRT/SList/InitOnce Shims:** Called upstream `LoadEnvVariables()` before `NewBox64Context(0)` in `box64_c_shim.c` so `BOX64_DYNAREC_*` settings are live, injected `patches/dxvk/mobiro_touch_hud.{h,cpp}` directly into DXVK's `DxvkSwapchainBlitter` dynamic rendering pass (zero extra GMEM passes), and added `InitOnce*`, `Interlocked*SList`, `GetLocalTime`, `GetFileInformationByHandle`, `VirtualQuery`, and `XInputGetCapabilities` shims.
- [x] **M17 — XAudio2 `onebridge_t` COM Bridge, Zero-Alloc Audio Ring, PE Forwarded Exports/`DllMain` & Touch Completeness:** Wrapped XAudio2.7/2.9 & voice vtables in lock-free Box64 `onebridge_t` COM proxies (`XMM1` float forwarding + `WAVE_FORMAT_EXTENSIBLE`/5.1 downmix + zero-alloc scratch buffers + bulk `memcpy` ring), added PE64 forwarded export resolution + topological dependent-DLL `DllMain` init, and added Healing Gourd (`D-Pad Up`)/Item Cycle/Crouch (`L3`) + touch camera look decay.
- [x] **M18 — 100% Retail PE64 Import Coverage, `Data1..Data5` Validator Fix, FMODEx/Bink2 `waveOut*` → `AAudio` Bridge & DirectInput8 `onebridge_t` Proxy:** Fixed retail `Data1..Data5` encrypted/DCX BYOF validation, implemented real WinMM `waveOut*` → `AAudio` streaming for FMODEx/Bink2, wrapped `IDirectInput8` in Box64 `onebridge_t`, added `dxgi!CreateDXGIFactory` + `xinput1_3!#2/#3` + full `kernel32`/`user32`/`gdi32`/`ole32`/`advapi32`/`ws2_32` retail import coverage (`534/534` retail `sekiro.exe` imports resolved), and added `--verify-byof` dry-run loader validation.
- [x] **M19 — Win64 Implicit Static TLS (`GS:[0x58]`) Isolation & One-Command ADB Staging:** Implemented `StaticTlsRegistry` + isolated per-thread `.tls` template copies behind `GS:[0x58]` (preventing NULL-deref & `TlsAlloc` collisions across `sekiro.exe`, `fmod_event64.dll`, and `fmodex64.dll`), patched PE `*AddressOfIndex`, and added `scripts/stage_byof_adb.ps1` for one-command PC → Snapdragon deployment.
- [x] **M20 — Full-Stack Bundled APK Verified Green (`52.9 MB`) & Android 15 MuMu Smoke Test:** Verified from-source `arm64-v8a` compilation & linking of Box64 (`LoadEnvVariables()`), Mesa Turnip, and Native DXVK (`AndroidWsiDriver` + `MobiroTouchHud`) in Run `45885793713`, fixed Android 15 `extractNativeLibs="false"` bare-soname `dlopen` + missing SAF picker crash, and verified live install/launch on Android 15 MuMu Player.
- [x] **M21 — Live Snapdragon 8 Gen 2 (Honor Magic5 Pro) ARM64 Dynarec Bring-Up & 1,507-Call Real Win32 Trace:** Fixed embedded Box64 ARM64 Dynarec initialization & dynamic `memprot` sync (`GuestArena` + all `NativeBridgeStub` slabs), added GuestHeap-backed `msvcrt`/`ucrtbase`, `FileMappingStore`, `ntdll` `Nt*`/`Zw*`/`Rtl*`, and `VfsMapper::strip_prefix` fixes; verified all 6 retail BYOF DLL `DllMain`s + 1,507 real `sekiro.exe` Win32 calls live on Adreno 740.
- [x] **M22 — Zero-Overhead 60 FPS Trace Gating, Turnip Android 16 `clns-*` Stub Fix & Clean-Room Self-Test:** Gated Box64/Win32 tracing behind opt-in `mobiro_trace.enable`, eliminated private `libhardware.so`/`libsync.so`/`libbacktrace.so` `DT_NEEDED` entries from Mesa Turnip (`scripts/patch_turnip_android_stubs.py` + `llvm-readelf -d` CI gate), and added `tools/mobiro_selftest.c` + `--verify-pe` CI validation.
- [x] **M23 — D3D11 Hot-Loop Fast Path, Turnip VNDK Bridge & Built-In APK Self-Test Mode:** Added 1–4 arg fast path & `SO`/`HS`/`DS` array unwrapping in `D3D11ComBridge`, bridged `AHardwareBuffer_getNativeHandle` via static `dlsym` (`--dyn-syms` CI gate), and bundled `mobiro_selftest.exe` inside the APK (`--ez selftest true`, `--ez trace true`).
- [x] **M24 — `SetResourceMinLOD` (`XMM2`), Live `avgMs`/`maxMs` Frame Telemetry & Clean Guest-Exit UX:** Added `XMM2` float forwarding for `ID3D11DeviceContext::SetResourceMinLOD` (slot 55), exact `avgMs`/`maxMs` pacing telemetry in `DxvkInterop` + `nativeGetDiagnosticsSummary()`, zero-warning `tools/mobiro_selftest.c`, and clean guest-exit Toast/Logcat reporting in `MainActivity.kt`.
- [x] **M25 — Lock-Free `Present` Hook, Full XAudio2 + D3D11 Dynamic Buffer Self-Test & `-SelfTest` ADB Runner:** Switched live `IDXGISwapChain::Present` hook to `std::atomic<PresentHookRawFn>`, expanded `tools/mobiro_selftest.c` with full XAudio2.7 voice submission + per-frame dynamic D3D11 CB updates, and added `-SelfTest`/`-Trace` to `scripts/stage_byof_adb.ps1`.
- [x] **M26 — Live Snapdragon 8 Gen 2 Full-Stack 60 FPS Bring-Up (Box64 ARM64 Dynarec + Mesa Turnip 26.99.99 + Native DXVK 3.2+ + `TurnipWsiShim`):** Implemented clean-room public-NDK `TurnipWsiShim` (`VK_KHR_android_surface`/`VK_KHR_swapchain`), fixed Android `RTLD_LOCAL` cross-`.so` symbol resolution (`RTLD_NOLOAD`), bumped Turnip to API 35 (`VK_KHR_load_store_op_none` + `maintenance5/6`), and verified live on Honor Magic5 Pro (Android 16): `Turnip Adreno 740` (`Graphics pipeline libraries supported`, `D3D_FEATURE_LEVEL_11_1`, `2848x1312` triple-buffered swapchain) rendered 120 frames at 60 FPS + XAudio2.7 + XInput in `2.443s` wall time with clean `ExitProcess(0)`.
- [x] **M27 — Async Double-Buffered Turnip WSI Present, 900p Hardware-Scaled Swapchain Cap & Boot-Log Pacing Telemetry:** Upgraded `TurnipWsiShim` to lock-free cached `DeviceRec`, zero-alloc stack `wait_stages[8]`, contiguous `stride == width` blit, double-buffered async staging (`kStagingSlots = 2`) over `>=3` images, and aspect-preserving `<=900p` render scaling (`MOBIRO_MAX_RENDER_HEIGHT`, SurfaceFlinger hardware-upscaled); added `frames`/`drops`/`avgMs`/`maxMs` directly to `mobiro_boot.log` on guest exit.

---

## Legal & Compliance Notice

*Sekiro: Shadows Die Twice* is a trademark of FromSoftware, Inc. and Activision Publishing, Inc. Mobiro is an independent clean-room runtime research project with no affiliation to FromSoftware or Activision. It does not distribute game files, does not include decryption keys, and does not bypass DRM.
