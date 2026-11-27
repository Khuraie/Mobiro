# Mobiro Progress Log

> Live engineering record for **Mobiro** — a clean-room, Bring-Your-Own-Files (BYOF) ARM64 Android native runtime container for *Sekiro: Shadows Die Twice*.

---

## Log Entries

### Increment 29 — M27: Async Double-Buffered Turnip WSI Present Pipeline, 900p Hardware-Scaled Swapchain Cap & Boot-Log Frame Pacing Telemetry (2026-11-27)
- **Status:** Implemented & verified (local MSVC 2022 tests + retail `--verify-byof` + GitHub Actions CI + bundled ARM64 APK)
- **Changes:**
  - Eliminated per-frame CPU-GPU pipeline stalls and heap allocations in `TurnipWsiShim` (`app/src/main/cpp/gfx/turnip_wsi_shim.hpp`):
    - Upgraded `SwapchainObj` to **double-buffered async UMA staging slots** (`kStagingSlots = 2`, per-slot buffer/cmdbuf/fence) over a guaranteed `>=3`-image swapchain so frame `N` transfers asynchronously on Adreno while frame `N-1` posts to `ANativeWindow`.
    - Replaced per-present `std::vector<VkPipelineStageFlags>` heap allocation with a zero-alloc `VkPipelineStageFlags[8]` stack fast path, cached `DeviceRec` inside `SwapchainObj` to eliminate 2 mutex locks + 2 hash lookups per frame, and collapsed row-by-row `memcpy` into a single contiguous `memcpy` when `stride == width`.
    - Added aspect-preserving `compute_scaled_swapchain_extent()` (default `900p` cap, configurable via `MOBIRO_MAX_RENDER_HEIGHT`, `0` = native panel) so 1312p/1440p panels render at crisp `1954×900` (>2.1× lower GPU fill-rate & staging bandwidth) while SurfaceFlinger hardware-scales to native resolution via `ANativeWindow_setBuffersGeometry`.
  - Logged exact `frames`, `drops`, `avgMs`, `maxMs`, `trace`, and `maxH` directly into `mobiro_boot.log` (`ANDROID_LOG_WARN`) on guest exit in `app/src/main/cpp/runtime_main.cpp` so OEM logcat filters never hide 60 FPS telemetry.
  - Added `test_m27_turnip_wsi_scaled_extent` in `tests/test_core.cpp` (27/27 suites passing).

---

### Increment 28 — M26: Clean-Room Public-NDK Turnip Vulkan WSI Shim (`VK_KHR_android_surface`/`VK_KHR_swapchain`), DXVK 3.2+ on Mesa Turnip 26.99.99 & Live 2848×1312 60 FPS Verification on Snapdragon 8 Gen 2 (2026-11-27)
- **Status:** Implemented & **verified LIVE on Honor Magic5 Pro (`PGT-AN10`, Snapdragon 8 Gen 2 / Adreno 740, Android 16)** (`Run 45959634972`)
- **Changes:**
  - Verified live on Honor Magic5 Pro (Android 16): patched Mesa Turnip (`libvulkan_freedreno.so`) loads natively via Android HAL `HMI` (`turnip=1, turnip_err=none`), whereas Qualcomm's OEM Adreno 740 driver (`0.676.3`) was skipped by DXVK 3.2+ for lacking `shaderInt64`.
  - Implemented clean-room `TurnipWsiShim` (`app/src/main/cpp/gfx/turnip_wsi_shim.hpp`) layered directly over Mesa Turnip's Vulkan 1.3 ICD using 100% public Android NDK `ANativeWindow` APIs (zero root / zero linker-namespace bypasses): advertises `VK_KHR_surface`, `VK_KHR_android_surface`, and `VK_KHR_swapchain`, allocates Turnip device-local swapchain images + UMA host-coherent staging copy, and presents via `ANativeWindow_lock`/`ANativeWindow_unlockAndPost`.
  - Exported `mobiro_get_vk_instance_proc_addr()` from `runtime_main.cpp`, patched DXVK's `src/vulkan/vulkan_loader.cpp` (`scripts/patch_dxvk_android_wsi.py`) to bind to it, fixed Android `RTLD_LOCAL` cross-`.so` symbol lookup via `dlopen("libsekiro_runtime.so", RTLD_NOW | RTLD_NOLOAD)` across `wsi_platform_android.cpp`, `mobiro_touch_hud.cpp`, and `vulkan_loader.cpp`, and bumped Turnip to `-Dplatform-sdk-version=35 -Dandroid-strict=false` (`scripts/build_turnip_android.sh`) to expose `VK_KHR_load_store_op_none` and `VK_KHR_maintenance5/6`.
  - **Live Hardware Telemetry (`AD3J023A18000309`, zero-trace run):** `libvulkan_freedreno.so` (`turnip=1, dxvk_native=1, turnip_err=none`) → DXVK 3.2+ bound `Turnip Adreno (TM) 740 (turnip Mesa driver 26.99.99)` with `Graphics pipeline libraries supported`, `D3D_FEATURE_LEVEL_11_1`, and triple-buffered `2848x1312` `VK_FORMAT_R8G8B8A8_UNORM` swapchain (`60.0 FPS` limiter) → Box64 ARM64 Dynarec executed `mobiro_selftest.exe` (XAudio2.7 → AAudio, dynamic D3D11 constant buffers, `XInputGetState`, 120 rendered `Present` frames + `MobiroTouchHud`) end-to-end in `2.443s` total wall time (cold init + 2.00s @ 60 FPS) with clean `Guest exited ok=1 rax=0x0`.
  - Added `test_m26_turnip_wsi_extension_filter` in `tests/test_core.cpp` (26/26 suites passing).

---

### Increment 27 — M25: Lock-Free `Present` Hook, Full XAudio2 + D3D11 Dynamic Buffer Self-Test & One-Command `-SelfTest` ADB Runner (2026-11-27)
- **Status:** Implemented & verified (local MSVC 2022 tests + GitHub Actions CI + bundled ARM64 APK)
- **Changes:**
  - Added lock-free, zero-allocation `set_present_hook_fast(PresentHookRawFn)` (`std::atomic<PresentHookRawFn>`) in `app/src/main/cpp/gfx/d3d11_com_bridge.hpp` and wired `runtime_main.cpp` to it, eliminating the per-frame `std::mutex` lock + `std::function` copy on `IDXGISwapChain::Present`.
  - Expanded clean-room `tools/mobiro_selftest.c` (`-nostdlib`) to exercise `IXAudio2_7` voice creation (`Initialize`, `CreateMasteringVoice`, `CreateSourceVoice`, `SetVolume(0.25f)` via `XMM1`, 50 ms stereo 48 kHz PCM16 `SubmitSourceBuffer`, `Start`, `DestroyVoice`) and per-frame D3D11 dynamic constant buffer updates (`CreateBuffer`, `Map`, `Unmap`, `VSSetConstantBuffers`).
  - Added `-SelfTest` and `-Trace` flags to `scripts/stage_byof_adb.ps1` for one-command clean-room 60 FPS hardware benchmarking without staging BYOF files.
  - Added `test_m25_lockfree_present_raw_hook` in `tests/test_core.cpp` (25/25 suites passing).

---

### Increment 26 — M24: `SetResourceMinLOD` (`XMM2`), Exact `avgMs`/`maxMs` Frame Telemetry & Clean Guest-Exit UX (2026-11-27)
- **Status:** Implemented & verified (local MSVC 2022 tests + live retail `--verify-byof` + GitHub Actions CI)
- **Changes:**
  - Added Win64 `XMM2` scalar float forwarding + resource proxy unwrapping for `ID3D11DeviceContext::SetResourceMinLOD` (slot 55) in `app/src/main/cpp/gfx/d3d11_com_bridge.hpp`, protecting FromSoftware texture streaming LOD clamping.
  - Added `total_frame_ns` + `avg_frame_ms()` / `max_frame_ms()` to `FramePacingStats` (`app/src/main/cpp/gfx/dxvk_interop.hpp`) and surfaced `avgMs=... maxMs=...` in `nativeGetDiagnosticsSummary()` (`runtime_main.cpp`).
  - Added a lightweight 1 Hz guest-exit watcher in `MainActivity.kt` (cancelled in `onDestroy()`) surfacing clean guest exit diagnostics (`exit=0x35` Steam client requirement or clean `exit=0x0` self-test `frames`/`drops`/`avgMs`/`maxMs` summary).
  - Fixed `-Wcomment` warning in `tools/mobiro_selftest.c`, added `test_m24_set_resource_min_lod_xmm2_and_frame_ms_stats` (`24/24` suites) in `tests/test_core.cpp`, and updated `README.md` with M21–M24 milestones and `--ez selftest true` / `--ez trace true` instructions.

---

### Increment 25 — M23: D3D11 Draw-Loop Fast Path, Turnip VNDK `AHardwareBuffer_getNativeHandle` Bridge & Built-In APK 60 FPS Self-Test Mode (2026-11-27)
- **Status:** Implemented & verified (local MSVC 2022 tests + GitHub Actions CI + full bundled ARM64 APK rebuild)
- **Changes:**
  - Hardened `scripts/patch_turnip_android_stubs.py` + `scripts/build_turnip_android.sh`: replaced the private VNDK `AHardwareBuffer_getNativeHandle` dynamic import in Mesa Turnip with an internal static `dlsym("libnativewindow.so", ...)` bridge (gracefully returning `NULL` if hidden in Android 15/16 `clns-*`) and added an automated `llvm-readelf --dyn-syms` CI gate.
  - Optimized `D3D11ComBridge::dispatch_slot` (`app/src/main/cpp/gfx/d3d11_com_bridge.hpp`): eliminated unconditional 384-byte stack zero-initialization on non-array slots, added a 1..4-arg fast path for `AddRef`/`Release` and hot `D3D11DeviceContext` draw/state slots (`DrawIndexed`, `Draw`, `Unmap`, `IASetPrimitiveTopology`, `RSSetViewports`/`ScissorRects`, `ClearRenderTargetView`), and added proxy-array unwrapping for `SOSetTargets` (37) and all `HS`/`DS` resource/sampler/CB slots (59, 61, 62, 63, 65, 66).
  - Wired built-in clean-room 60 FPS self-test mode (`--ez selftest true`) and trace toggle (`--ez trace true`) across `MainActivity.kt`, `runtime_main.cpp`, and `.github/workflows/build-third-party.yml` (bundling MinGW-compiled `app/src/main/assets/mobiro_selftest.exe` directly into the APK).
  - Added `test_m23_d3d11_hot_loop_and_hs_ds_so_unwrap` in `tests/test_core.cpp` (23/23 suites passing, verifying 12,000 `DrawIndexed` dispatches complete well inside one 16.6 ms frame budget).

---

### Increment 24 — M22: Zero-Overhead 60 FPS Trace Gating, Mesa Turnip Android 16 `clns-*` Stub Fix & Clean-Room Win64 D3D11 Self-Test (2026-11-27)
- **Status:** Implemented & verified (local MSVC 2022 tests `0.22s` + retail `--verify-byof` + GitHub Actions CI & Turnip `arm64-v8a` rebuild)
- **Changes:**
  - Gated verbose Box64 (`BOX64_LOG`/`BOX64_TRACE_FILE`/`BOX64_SHOWBT`/`BOX64_SHOWSEGV`) and Win32 IAT (`MOBIRO_API_TRACE_FILE`) tracing in `app/src/main/cpp/runtime_main.cpp` behind an opt-in marker file (`<files>/mobiro_trace.enable`), restoring zero-logging-overhead direct Box64 Dynarec thunk dispatch by default for locked 60 FPS; exposed `trace=on/off` and `exit=0x...` guest exit status in `nativeGetDiagnosticsSummary()`.
  - Fixed Android 15/16 app linker namespace (`clns-9`) rejection of bundled Mesa Turnip (`libvulkan_freedreno.so`): added `scripts/patch_turnip_android_stubs.py` and wired it into `scripts/build_turnip_android.sh` (`-Dandroid-libbacktrace=disabled`, static `hardware_stub.cpp` returning `-ENOENT`, static `sync_stub.cpp` backed by real Linux `poll()`/`SYNC_IOC_MERGE`/`SYNC_IOC_FILE_INFO` ioctls, dynamic public NDK `liblog.so`/`libnativewindow.so`) plus an automated `llvm-readelf -d` gate rejecting private HAL/VNDK `DT_NEEDED` entries.
  - Added clean-room Win64 x86_64 `-nostdlib` D3D11 + DXGI + XAudio2 + XInput 60 FPS self-test payload (`tools/mobiro_selftest.c`) and `--verify-pe <exe>` loader verifier in `tests/test_core.cpp`, wired into `.github/workflows/ci.yml` via `x86_64-w64-mingw32-gcc`.
  - Added `test_m21_vfs_prefix_crt_file_mapping_and_ntdll` and `test_m22_end_to_end_d3d11_xaudio_xinput_60fps_selftest` in `tests/test_core.cpp` (22/22 test suites passing).

---

### Increment 23 — M21: Live Snapdragon 8 Gen 2 (Honor Magic5 Pro) ARM64 Dynarec Bring-Up & 1,507-Call Real Win32 Execution Trace (2026-11-27)
- **Status:** Implemented & verified live on Honor Magic5 Pro (`PGT-AN10`, Snapdragon 8 Gen 2 / Adreno 740, Android 16) + local MSVC 2022 tests (`0.17s`) + GitHub Actions fast bundled APK builds (`~90s`)
- **Changes:**
  - Fixed embedded Box64 ARM64 Dynarec initialization in `app/src/main/cpp/cpu_mem/box64_c_shim.c`: mirrored upstream `core.c::initialize()` (`box64_pagesize`, `ftrace`, `LoadEnvVariables()`, `InitializeSystemInfo()`, `DetectHostCpuFeatures()`, `loadProtectionFromMap()`, `SetupX64Emu()`, `ResetFlags()`, `thread_set_emu()`), resolving the initial `MAP_FAILED` `SIGSEGV` and `prot=0` faults.
  - Wired `GuestArena` (`guest_arena.hpp`) and all `NativeBridgeStub` / COM proxy slabs (`box64_bridge.hpp`, `win32_shim.cpp`, `d3d11_com_bridge.hpp`, `xaudio2_com_bridge.hpp`, `win32_sekiro_compat.hpp`) directly into Box64's `setProtection()` via `mobiro_box64_set_prot`, enabling dynamic guest `VirtualAlloc`/`VirtualProtect` JIT/unpack execution on ARM64.
  - Added GuestHeap-backed `msvcrt.dll`/`ucrtbase.dll` CRT thunks (`malloc`/`calloc`/`realloc`/`free`/`vsprintf`/`snprintf`/strings/stdio), `FileMappingStore` (`CreateFileMapping*`/`OpenFileMapping*`/`MapViewOfFile*`), `IsBad*Ptr`, `ntdll.dll` `Nt*`/`Zw*`/`Rtl*` thunks (`NtSetInformationThread`, `NtProtectVirtualMemory`, `NtAllocateVirtualMemory`, `RtlGetVersion`), clean guest quit (`mobiro_box64_request_quit` in `ExitProcess`/`TerminateProcess`), and proper `OpenProcess(pid==0) -> NULL`.
  - Fixed a real path-resolution bug in `VfsMapper::strip_prefix` (`vfs_mapper.hpp`): stripped `\\?\` and canonical `sekiro/` virtual game-root prefixes so `CreateFileW("C:\Sekiro\Sekiro.exe")` resolves to the staged BYOF root.
  - Added persistent `mobiro_boot.log` + opt-in `mobiro_box64.log` / `mobiro_api.log` diagnostics (`runtime_main.cpp`), throttled the idle `ALooper_pollOnce` loop, and cached a deterministic workspace `MOBIRO_DEBUG_KEYSTORE` (`build.gradle.kts`, `build-third-party.yml`) enabling 2-second in-place `adb install -r` updates without disturbing the staged 12.5 GB BYOF folder.
  - **Live Hardware Telemetry (`AD3J023A18000309`):** Native AArch64 DXVK (`dxvk_native=1`) + Adreno 740 Vulkan (`libvulkan.so`) + `ANativeWindow` (`2848x1312`) bound cleanly; all 6 retail BYOF DLL `DllMain`s (`oo2core_6_win64.dll`, `bink2w64.dll`, `amd_ags_x64.dll`, `fmodex64.dll`, `fmod_event64.dll`, `steam_api64.dll`) executed under Box64 ARM64 Dynarec and returned `TRUE (rax=1)`; `sekiro.exe` executed `1,507` consecutive real Win32 API calls (unpacked dynamic code at `0x180000000`, opened & verified `C:\Sekiro\Sekiro.exe`) until the retail Steam wrapper queried `HKCU\Software\Valve\Steam\ActiveProcess` / `steamclient64.dll`, invoked `ShellExecuteA("steam://rungameid/814380")`, and cleanly requested exit (`TerminateProcess(-1, 0x35)`). (Clean-room BYOF: zero DRM bypasses.)
  - Also diagnosed why bundled `libvulkan_freedreno.so` fell back to system Adreno 740 `libvulkan.so`: Android 16 app linker namespace `clns-9` blocks private `/system/lib64/libhardware.so`.

---

### Increment 22 — M20: Full-Stack Bundled APK Green (`52.9 MB`, All 3 Upstream Layers + `MobiroTouchHud`) & Android 15 MuMu Smoke Test Fixes (2026-11-27)
- **Status:** Implemented & verified (GitHub Actions full-stack Run `45885793713` PASS + Android 15 MuMu Player live install & launch)
- **Changes:**
  - Fixed two real DXVK/patcher issues uncovered by compiling `patches/dxvk/mobiro_touch_hud.cpp` against live upstream DXVK (`doitsujin/dxvk`): corrected the 2-space `src/dxvk/meson.build` anchor in `scripts/patch_dxvk_android_wsi.py` (`a2fd958`) and switched `MobiroTouchHud` to 100% public `DxvkCommandList` draw methods (`cmdSetViewport`/`cmdSetScissor`/`cmdBindPipeline`/`cmdBindVertexBuffers`/`cmdDraw`) fed by `mobiro_touch_overlay_copy_vertices` (`4292a7f`).
  - Fixed two real Android 15 runtime bugs caught during live MuMu Player testing (`967b2af`):
    1. Added bare-soname `dlopen` fallback (`"libvulkan_freedreno.so"`, `"libdxvk_dxgi.so"`, `"libdxvk_d3d11.so"`) in `turnip_loader.hpp` and `dxvk_interop.hpp` so uncompressed `.so` libraries packaged with `android:extractNativeLibs="false"` load cleanly via Android's linker namespace.
    2. Wrapped SAF `OpenDocumentTree` launch in `try/catch (ActivityNotFoundException)` in `MainActivity.kt` so Android builds without `DocumentsUI` stay running cleanly and show the target BYOF storage path instead of crashing `onCreate()`.
  - Verified full-stack bundled APK (`Run 45885793713`, `52.9 MB`, all 5 uncompressed `arm64-v8a` `.so` libraries: `libsekiro_runtime.so` 23.7 MB + `libvulkan_freedreno.so` 8.8 MB + `libdxvk_d3d11.so` 6.3 MB + `libdxvk_dxgi.so` 4.4 MB + `libc++_shared.so` 1.3 MB) installed and stayed `"state": "running"` on Android 15 MuMu Player.

---

### Increment 21 — M19: Win64 Implicit Static TLS (`GS:[0x58]`) Isolation & One-Command ADB BYOF Staging Script (2026-11-27)
- **Status:** Implemented & verified (local MSVC 2022 + live retail BYOF PE64 dry-run + GitHub Actions CI)
- **Changes:**
  - Fixed a critical Win64 `__declspec(thread)` / `thread_local` crash gap across `sekiro.exe`, `fmod_event64.dll`, and `fmodex64.dll` (all three ship non-empty `IMAGE_TLS_DIRECTORY64` templates):
    - Added `StaticTlsRegistry` (`app/src/main/cpp/cpu_mem/win64_teb.hpp`) and separated `Win64Teb::static_tls_ptrs[32]` (`GS:[0x58]`) from dynamic `TlsAlloc` `tls_slots[64]` (`GS:[0x1480]`).
    - Updated `PeLoader::load_pe64_impl` (`pe_loader.hpp`) to register each PE's `.tls` raw template + zero-fill and patch `*AddressOfIndex` (`_tls_index`) before tightening section protections.
    - Populated isolated per-thread copies of all registered `.tls` templates inside `Win64ThreadEnv::init_main_thread` (`runtime_main.cpp`) and `GuestThreadTable::create_thread` (`win32_thread_wait.hpp`).
  - Added clean-room PC → Android deployment helper `scripts/stage_byof_adb.ps1` (installs APK, validates & pushes user's own local BYOF files into `/sdcard/Android/data/com.mobiro.runtime/files/game`, launches `com.mobiro.runtime`, and optionally streams `adb logcat -s Mobiro`).
  - Added `test_m19_win64_static_tls_pointer_isolation` in `tests/test_core.cpp` (20/20 test suites passing; live retail `--verify-byof` confirmed `static_tls_mods=3`, `iat_resolved=534`, `iat_unresolved=0`).

---

### Increment 20 — M18: 100% Retail `sekiro.exe` + BYOF DLL Import Coverage, Real `Data1..Data5` Validator Fix, FMODEx/Bink2 `waveOut*` → `AAudio` Bridge & DirectInput8 `onebridge_t` Proxy (2026-11-27)
- **Status:** Implemented & verified (local MSVC 2022 + real BYOF PE64 dry-run load & IAT patch + GitHub Actions CI)
- **Changes:**
  - Audited structural PE32+ import tables of a local retail BYOF *Sekiro* install (`sekiro.exe` + 7 shipped DLLs) and fixed 4 critical real-boot blockers:
    1. `archive_probe.hpp`: updated `validate_byof_directory` to validate retail `Data1..Data5` (optional `Data0`) non-empty readable archives without falsely rejecting encrypted/DCX `.bdt` files for missing literal `"BDF4"` bytes at offset 0.
    2. `win32_sekiro_compat.hpp`: registered `dxgi.dll!CreateDXGIFactory` (alias to `CreateDXGIFactory1`) and `xinput1_3.dll` ordinals `#2` (`XInputGetState`) and `#3` (`XInputSetState`), plus `d3d9!D3DPERF_GetStatus`, `imm32!ImmDisableIME`, and full `kernel32`/`user32`/`gdi32`/`ole32`/`oleaut32`/`shell32`/`advapi32`/`crypt32`/`ws2_32`/`wsock32`/`wldap32` coverage.
    3. `app/src/main/cpp/audio/winmm_waveout_bridge.hpp`: implemented a real WinMM `waveOut*` → `AAudioXAudioBridge` low-latency audio bridge (with `CALLBACK_EVENT` signaling, linear resampling, and `waveOutGetPosition`) powering `fmodex64.dll` and `bink2w64.dll`.
    4. Wrapped `DirectInput8Create` in a Box64 `onebridge_t` proxy (`DirectInput8ComBridge`) so ARM64 guest code never jumps into raw native vtable pointers.
  - Added `test_m18_winmm_waveout_xinput_ordinals_and_sekiro_compat` and a clean-room `--verify-byof <dir>` CLI diagnostic mode in `tests/test_core.cpp` (19/19 test suites passing).

---

### Increment 19 — M17: XAudio2 Box64 `onebridge_t` COM Bridge, Zero-Alloc Audio Ring, PE64 Forwarded Exports/`DllMain` & Healing-Gourd Touch + Camera Decay (2026-11-27)
- **Status:** Implemented & verified (local MSVC 2022 + GitHub Actions Linux GCC/`spirv-val` + Android ARM64 NDK)
- **Changes:**
  - Fixed a critical ARM64 Box64 audio ABI bug by implementing `XAudio2ComBridge` (`app/src/main/cpp/audio/xaudio2_com_bridge.hpp`), wrapping `IXAudio2`, `IXAudio2_7`, `IXAudio2Voice`, and `IXAudio2SourceVoice` in lock-free 32-byte Box64 `onebridge_t` (`NativeBridgeStub`) COM proxies with `XMM1` float forwarding (`SetVolume`, `SetFrequencyRatio`), automatic voice out-param wrapping, and proxy cleanup on `DestroyVoice`/`Release == 0`; wired directly into `thunk_XAudio2Create_27`/`29` (`win32_shim.cpp`).
  - Eliminated per-submit heap allocations in `IXAudio2SourceVoiceCom::source_submit_buffer` (`xaudio2_com.hpp`) via reusable per-voice scratch buffers, added `WAVE_FORMAT_EXTENSIBLE` (`0xFFFE`) & multichannel (5.1/7.1 -> stereo) downmix support, and upgraded `PcmRingBuffer` (`aaudio_xaudio_bridge.hpp`) to contiguous bulk `std::memcpy` wrap transfers.
  - Upgraded `PeLoader` (`pe_loader.hpp`) + `GuestExecutor::run_entry` (`guest_executor.hpp`) to resolve forwarded PE exports (`"DLL.Symbol"`) cleanly instead of returning ASCII string pointers and to run `TLS` callbacks + `DllMain(DLL_PROCESS_ATTACH)` for all auto-loaded dependent BYOF DLLs in topological order before entering `Sekiro.exe`.
  - Added Healing Gourd (`D-Pad Up`), Item Cycle (`D-Pad Down`), and Crouch/Stealth (`L3`) to `TouchController` (`touch_controller.hpp`) and wired `decay_camera_look()` in `runtime_main.cpp` so touch camera stops immediately when thumb movement stops.
  - Added `test_m17_xaudio2_onebridge_ring_and_gourd_touch` in `tests/test_core.cpp` (18/18 test suites passing).

---

### Increment 18 — M16: Box64 `LoadEnvVariables()` Dynarec Activation, Live DXVK In-Swapchain Touch HUD Renderer & Sekiro CRT/SList/InitOnce Shims (2026-11-27)
- **Status:** Implemented & verified (local MSVC 2022 + GitHub Actions Linux GCC/`spirv-val` + Android ARM64 NDK)
- **Changes:**
  - Fixed a critical embedded-Box64 Dynarec initialization gap in `app/src/main/cpp/cpu_mem/box64_c_shim.c`: included upstream `env.h` and called `LoadEnvVariables()` inside `mobiro_init_box64_context_once()` before `NewBox64Context(0)` (since `libbox64_core.a` excludes `main.c.o`), ensuring `BOX64_DYNAREC=1` + `BIGBLOCK=3`/`CALLRET=1`/`STRONGMEM=1` actually take effect at runtime.
  - Implemented DXVK in-swapchain touch HUD renderer `patches/dxvk/mobiro_touch_hud.{h,cpp}` and injected it via `scripts/patch_dxvk_android_wsi.py` into `DxvkSwapchainBlitter` (inside the active `VK_KHR_dynamic_rendering` swapchain pass — zero extra render passes or Adreno GMEM copies), lazily creating the alpha-blended Vulkan 1.0 SPIR-V pipeline & 64 KiB host-coherent VBO and binding `mobiro_touch_overlay_*` via `dlsym(RTLD_DEFAULT)`.
  - Added 25+ Sekiro / MSVC 2017 CRT / Oodle / Bink2 Win32 shims in `win32_shim.cpp`: `InitializeSListHead`/`Interlocked{Push,Pop,Flush}EntrySList`/`QueryDepthSList` (`kernel32` + `ntdll`), `InitOnce{Initialize,BeginInitialize,Complete}` (`std::call_once`), `GetLocalTime`/`GetSystemTime`, `GetTickCount`, `GetFileInformationByHandle`, `SetEndOfFile`, `VirtualQuery`, `GetUserDefault{LCID,UILanguage}`, processor-query helpers, and `XInputGetCapabilities`.
  - Added `test_m16_init_once_slist_time_query_and_xinput_caps` in `tests/test_core.cpp` (17/17 test suites passing).

---

### Increment 17 — M15: O(1) Segregated GuestHeap, 64-Shard Lock Tables, Parallel File I/O & In-Swapchain HUD C ABI Exports (2026-11-27)
- **Status:** Implemented & verified (local MSVC 2022 + GitHub Actions Linux GCC/`spirv-val` + Android ARM64 NDK)
- **Changes:**
  - Replaced `GuestHeap`'s `std::unordered_map` + O(N) linear `free_list_` scan/erase (`app/src/main/cpp/cpu_mem/win32_proc_sync.hpp`) with an O(1) 20-bucket power-of-2 segregated intrusive freelist (`16 B..8 MiB`) and 16-byte inline `BlockHeader` magic validation (chunk-bounds checked + double-free safe).
  - Replaced the single global mutex in `SrwLockTable`, `CriticalSectionTable`, and `ConditionVariableTable` (`app/src/main/cpp/cpu_mem/win32_file_sync.hpp`) with a 64-shard `alignas(64)` `ShardedObjectMap` (`std::shared_mutex` reader-lock fast path) and added `alignas(64)` to `AddressWaitTable::Bucket` (`win32_thread_wait.hpp`), removing cross-core serialization across multi-threaded engine locks.
  - Upgraded `FileHandleTable` (`win32_file_sync.hpp`) to per-file `OpenFile::io_mu` locking so concurrent `.bdt` archive streaming and save-file reads execute in parallel without blocking a global handle-table mutex.
  - Made `TouchOverlayVk` (`touch_overlay_vk.hpp`) thread-safe across `pack_quads` / `record_draw_commands` and exported `mobiro_touch_overlay_pipeline_spec`, `mobiro_touch_overlay_attach_device`, and `mobiro_touch_overlay_record_draw` C ABI symbols from `libsekiro_runtime.so` (`runtime_main.cpp`).
  - Added `test_m15_segregated_heap_sharded_sync_and_parallel_io` in `tests/test_core.cpp` (16/16 test suites passing).

---

### Increment 16 — M14: Locked 60 FPS Zero-Drop Optimization Pass (Lock-Free COM Slab, Hybrid Pacer + ADPF Closed Loop, Box64 Dynarec Tuning & Native ARM64 CRT Thunks) (2026-11-27)
- **Status:** Implemented & verified (local MSVC 2022 + GitHub Actions Linux GCC/`spirv-val` + Android ARM64 NDK)
- **Changes:**
  - Replaced `D3D11ComBridge`'s mutex-guarded `std::unordered_map` with a contiguous 65,536-slot `alignas(32)` `ComProxyObject` slab + O(1) intrusive freelist (`app/src/main/cpp/gfx/d3d11_com_bridge.hpp`), eliminating 10–40 mutex lock/hash lookups per D3D11 draw call on `find_proxy()` / `unwrap_arg()` in favor of lock-free range/alignment + atomic `alive` checks.
  - Upgraded `DxvkInterop::pace_present()` (`app/src/main/cpp/gfx/dxvk_interop.hpp`) with a hybrid sleep + 400 µs spin window to prevent Linux timer-slack VSync drops, live `FramePacingStats` (`frames_presented`, `frames_dropped`, `last_work_ns`, `max_frame_ns`), and returned frame work duration wired directly into Android ADPF (`ThreadBalancer::report_frame_work` + thread-safe `adpf_mu_` + `update_target_work_duration`) in `runtime_main.cpp`.
  - Tuned Box64 ARM64 Dynarec + Mesa Turnip runtime defaults (`BOX64_DYNAREC_BIGBLOCK=3`, `CALLRET=1`, `FASTNAN=1`, `FASTROUND=1`, `NATIVEFLAGS=1`, `STRONGMEM=1`, `ALIGNED_ATOMICS=1`, `MESA_DISK_CACHE_SINGLE_FILE=1`, `dxvk.trackPipelineLifetime = True`), added `pthread_once` context init safety in `box64_c_shim.c`, and added thermal hysteresis (`>=0.90` → 30 FPS, `<=0.78` → 60 FPS) to prevent 60↔30 oscillation.
  - Added native ARM64 NEON-backed CRT & `ntdll` bulk memory/string thunks (`memcpy`, `memmove`, `memset`, `memcmp`, `strlen`, `wcslen`, `strcmp`, `strncmp`, `RtlCopyMemory`, `RtlMoveMemory`, `RtlZeroMemory`, `RtlFillMemory`) across `vcruntime140.dll`, `ucrtbase.dll`, `msvcrt.dll`, `api-ms-win-crt-string-l1-1-0.dll`, `ntdll.dll`, and `kernel32.dll` in `win32_shim.cpp`.
  - Added `test_m14_lockfree_com_pool_pacer_and_native_crt_mem` in `tests/test_core.cpp` (15/15 test suites passing, including 100k concurrent lock-free COM dispatches).

---

### Increment 15 — M13: Full D3D11/DXGI COM Out-Param Auto-Wrapping, Zero-Heap Pointer-Array Unwrapping & Display/Mutex/Find Shims (2026-11-27)
- **Status:** Implemented & verified (local MSVC 2022 + GitHub Actions Linux GCC/`spirv-val` + Android ARM64 NDK)
- **Changes:**
  - Expanded `scripts/gen_d3d11_thunks.py` → `app/src/main/cpp/gfx/d3d11_com_thunks_gen.hpp` to 8 DXGI/D3D11 COM interfaces (237 vtable slots), adding `DXGIOutput` (19 slots) and `D3D11ResourceChild` (14 slots).
  - Upgraded `D3D11ComBridge` (`app/src/main/cpp/gfx/d3d11_com_bridge.hpp`) with automatic Win64 `ComProxyObject` out-parameter wrapping across `IUnknown::QueryInterface` (with DXGI/D3D11 IID classification), `IDXGIFactory1::{EnumAdapters, EnumAdapters1, CreateSwapChain}`, `IDXGIAdapter1::EnumOutputs`, `IDXGISwapChain::GetBuffer`, `ID3D11Device::{CreateBuffer..CreateQuery, CreateDeferredContext, GetImmediateContext}`, and `GetDevice`, plus zero-heap stack pointer-array unwrapping for `OMSetRenderTargets*`, `IASetVertexBuffers`, and all `VS/PS/GS/CS` `SetConstantBuffers`/`SetShaderResources`/`SetSamplers` slots.
  - Added Win32 mutex (`CreateMutexW/A`, `ReleaseMutex`, `DuplicateHandle`), display/monitor (`MonitorFromWindow`, `GetMonitorInfoW`, `EnumDisplaySettingsW`), `FindFirstFileW`/`FindNextFileW`/`FindClose`, `SetThreadDescription`, `SetProcessDPIAware`, and `GetKeyState`/`GetAsyncKeyState` thunks in `win32_shim.cpp`.
  - Added `test_m13_com_out_param_wrapping_and_array_unwrapping` in `tests/test_core.cpp` (14/14 test suites passing).

---

### Increment 14 — M12: Dependent BYOF DLL Auto-Load, Safe Unresolved-Import Traps, Default `CreateThread` Execution & Android Diagnostics (2026-11-27)
- **Status:** Implemented & verified (local MSVC 2022 + GitHub Actions Linux GCC/`spirv-val` + Android ARM64 NDK)
- **Changes:**
  - Added recursive BYOF dependent guest DLL auto-loading (with cycle guard) in `PeLoader::load_pe64` (`app/src/main/cpp/cpu_mem/pe_loader.hpp`) so statically imported game-shipped DLLs (e.g. `oo2core_6_win64.dll`, `bink2w64.dll`) map and bind automatically before main IAT patching.
  - Added safe `onebridge_t` unresolved-import trap stubs (`Box64Bridge::resolve_unresolved_trap` / `mobiro_unresolved_import_wrapper` in `box64_bridge.hpp` + `win32_shim.cpp`) so calling an unimplemented Win32 API logs the exact `dll!symbol` to Android `logcat` + telemetry and returns `0` cleanly instead of jumping to an unmapped RVA.
  - Wired default `GuestExecutor::call_guest_fn` execution into `GuestThreadTable` (`win32_thread_wait.hpp` + `Box64Bridge::initialize`) so every guest `CreateThread` runs real x86_64 code on its own TEB + 512 KB stack + EngineWorker core automatically.
  - Added `TouchOverlayVk::pipeline_spec()` and `resolve_device_draw_procs()` (`touch_overlay_vk.hpp`), plus `nativeGetDiagnosticsSummary()` JNI status reporting in `runtime_main.cpp` and `MainActivity.kt`.
  - Added `test_m12_dep_dll_unresolved_trap_and_create_thread_exec` in `tests/test_core.cpp` (13/13 test suites passing).

---

### Increment 13 — M11: Box64 `onebridge_t` Live Native-Thunk Dispatch, Prime-Core Guest Entry Thread & `ntdll`/CRT Sync Expansion (2026-11-27)
- **Status:** Implemented & verified (local MSVC 2022 + GitHub Actions Linux GCC/`spirv-val` + Android ARM64 NDK)
- **Changes:**
  - Upgraded `NativeBridgeStub` (`app/src/main/cpp/cpu_mem/box64_bridge.hpp`) to exact 32-byte upstream Box64 `onebridge_t` binary layout (`0xCC 'S' 'C' <wrapper_ptr> <thunk_ptr> 0xC3`, static-asserted offsets + `alignas(32)`) and added `mobiro_native_thunk_wrapper(x64emu_t*, uintptr_t)` so Box64's ARM64 Dynarec (`dynarec_arm64_00.c`) and `x64Int3` natively dispatch every IAT thunk and all 204 D3D11/DXGI COM vtable slots with zero patches to Box64.
  - Added Box64-native clean exit stub (`0xCC 'S' 'C' 0ULL`) in `app/src/main/cpp/cpu_mem/box64_c_shim.c` so guest `RET` cleanly sets `emu->quit = 1` and returns `RAX` to C++.
  - Wired Prime-core `guest_thread` launch (`GuestExecutor::run_entry`) into `android_main` (`app/src/main/cpp/runtime_main.cpp`) once BYOF PE64 mapping and `ANativeWindow` are both ready, with clean `WM_QUIT` + thread join on Android teardown (removing duplicate TLS callback execution).
  - Implemented `ConditionVariableTable` (`std::condition_variable_any` supporting both `SRWLOCK` and `CRITICAL_SECTION`), semaphores (`CreateSemaphoreW/A`, `ReleaseSemaphore`), `WaitForMultipleObjects`, `ntdll.dll!Rtl*SRWLock`/`Rtl*ConditionVariable`, and 30+ MSVC CRT & VFS-safe file shims (`GetCurrentProcess/Thread`, `GetACP`/`GetCPInfo`, `GetModuleHandleExW`, `GetCurrentDirectoryW`, `GetTempPathW`, overlay-scoped `MoveFileExW`/`DeleteFileW`, `ws2_32.dll!WSAStartup/WSACleanup`).
  - Added `test_m11_box64_onebridge_condvar_sem_and_crt` in `tests/test_core.cpp` (12/12 test suites passing).

---

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
- **Increment 25 (M23 — Live Android 16 Turnip + `mobiro_selftest.exe` 60 FPS Benchmark & Frame-Time Telemetry):** When the user next requests on-device validation, verify the rebuilt `libvulkan_freedreno.so` loads natively on Adreno 740 (`Vk=Turnip`) and measure 120-frame 60 FPS pacing + `MobiroTouchHud` + XAudio2 using the clean-room `mobiro_selftest.exe` payload.
