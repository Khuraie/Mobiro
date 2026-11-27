#include "audio/aaudio_xaudio_bridge.hpp"
#include "cpu_mem/box64_bridge.hpp"
#include "cpu_mem/guest_arena.hpp"
#include "cpu_mem/guest_executor.hpp"
#include "cpu_mem/pe_loader.hpp"
#include "cpu_mem/win64_teb.hpp"
#include "gfx/d3d11_com_bridge.hpp"
#include "gfx/dxvk_config_gen.hpp"
#include "gfx/dxvk_interop.hpp"
#include "gfx/pipeline_cache_warmer.hpp"
#include "gfx/touch_overlay_vk.hpp"
#include "gfx/turnip_loader.hpp"
#include "gfx/turnip_wsi_shim.hpp"
#include "input/input_router.hpp"
#include "input/touch_controller.hpp"
#include "sched/thread_balancer.hpp"
#include "validator/archive_probe.hpp"
#include "validator/vfs_mapper.hpp"

#include <android/log.h>
#include <game-activity/native_app_glue/android_native_app_glue.h>
#include <jni.h>
#include <sys/sysinfo.h>

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>

namespace {

constexpr const char* kLogTag = "Mobiro";

struct MobiroRuntimeState {
    mobiro::validator::VfsMapper vfs;
    mobiro::mem::GuestArena arena;
    mobiro::cpu::Box64Bridge box64;
    mobiro::cpu::LoadedPeImage pe_image;
    mobiro::cpu::Win64ThreadEnv main_thread_env;
    mobiro::gfx::VulkanDriverHandle vk_driver;
    mobiro::gfx::PipelineCacheWarmer cache_warmer;
    mobiro::gfx::TouchOverlayVk touch_overlay;
    mobiro::input::TouchController touch_ctrl;
    mobiro::sched::ThreadBalancer balancer;
    std::atomic<int> target_fps{60};
    std::atomic<bool> configured{false};
    std::atomic<bool> dxvk_loaded{false};
    std::atomic<bool> guest_started{false};
    std::atomic<bool> guest_exited{false};
    std::atomic<uint64_t> guest_exit_code{0};
    std::atomic<bool> trace_enabled{false};
    std::thread guest_thread;
    std::mutex log_mu;
    std::string boot_log_path;
};

MobiroRuntimeState g_rt;

void mobiro_boot_log(const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    __android_log_print(ANDROID_LOG_WARN, kLogTag, "%s", buf);
    std::lock_guard<std::mutex> lock(g_rt.log_mu);
    if (!g_rt.boot_log_path.empty()) {
        if (FILE* f = std::fopen(g_rt.boot_log_path.c_str(), "a")) {
            std::fprintf(f, "%s\n", buf);
            std::fflush(f);
            std::fclose(f);
        }
    }
}

uint64_t query_total_ram_mb() {
    struct sysinfo si{};
    if (sysinfo(&si) == 0) {
        return (static_cast<uint64_t>(si.totalram) * si.mem_unit) / (1024ULL * 1024ULL);
    }
    return 8192;
}

void process_game_activity_input(android_app* app) {
    android_input_buffer* buf = android_app_swap_input_buffers(app);
    if (!buf) return;

    auto& router = mobiro::input::InputRouter::global();

    for (uint64_t i = 0; i < buf->keyEventsCount; ++i) {
        const auto& ev = buf->keyEvents[i];
        const bool down = (ev.action == AKEY_EVENT_ACTION_DOWN);
        switch (ev.keyCode) {
            case AKEYCODE_BUTTON_A:      router.set_button(mobiro::input::kButtonA, down); break;
            case AKEYCODE_BUTTON_B:      router.set_button(mobiro::input::kButtonB, down); break;
            case AKEYCODE_BUTTON_X:      router.set_button(mobiro::input::kButtonX, down); break;
            case AKEYCODE_BUTTON_Y:      router.set_button(mobiro::input::kButtonY, down); break;
            case AKEYCODE_BUTTON_L1:     router.set_button(mobiro::input::kLeftShoulder, down); break;
            case AKEYCODE_BUTTON_R1:     router.set_button(mobiro::input::kRightShoulder, down); break;
            case AKEYCODE_BUTTON_START:  router.set_button(mobiro::input::kStart, down); break;
            case AKEYCODE_BUTTON_SELECT: router.set_button(mobiro::input::kBack, down); break;
            default: break;
        }
    }

    bool saw_touch_move = false;
    for (uint64_t i = 0; i < buf->motionEventsCount; ++i) {
        const auto& ev = buf->motionEvents[i];
        if ((ev.source & AINPUT_SOURCE_JOYSTICK) == AINPUT_SOURCE_JOYSTICK && ev.pointerCount > 0) {
            g_rt.touch_overlay.set_enabled(false); // Auto-hide touch HUD when physical controller is active
            const auto& ptr = ev.pointers[0];
            float lx = GameActivityPointerAxes_getAxisValue(&ptr, AMOTION_EVENT_AXIS_X);
            float ly = -GameActivityPointerAxes_getAxisValue(&ptr, AMOTION_EVENT_AXIS_Y);
            float rx = GameActivityPointerAxes_getAxisValue(&ptr, AMOTION_EVENT_AXIS_Z);
            float ry = -GameActivityPointerAxes_getAxisValue(&ptr, AMOTION_EVENT_AXIS_RZ);
            float lt = GameActivityPointerAxes_getAxisValue(&ptr, AMOTION_EVENT_AXIS_LTRIGGER);
            float rt = GameActivityPointerAxes_getAxisValue(&ptr, AMOTION_EVENT_AXIS_RTRIGGER);
            router.set_left_stick(lx, ly);
            router.set_right_stick(rx, ry);
            router.set_triggers(lt, rt);
        } else if ((ev.source & AINPUT_SOURCE_TOUCHSCREEN) == AINPUT_SOURCE_TOUCHSCREEN && ev.pointerCount > 0) {
            g_rt.touch_overlay.set_enabled(true);
            const int32_t masked = ev.action & AMOTION_EVENT_ACTION_MASK;
            const int32_t idx = (ev.action & AMOTION_EVENT_ACTION_POINTER_INDEX_MASK)
                                >> AMOTION_EVENT_ACTION_POINTER_INDEX_SHIFT;
            if (masked == AMOTION_EVENT_ACTION_DOWN || masked == AMOTION_EVENT_ACTION_POINTER_DOWN) {
                if (idx >= 0 && static_cast<uint32_t>(idx) < ev.pointerCount) {
                    const auto& p = ev.pointers[idx];
                    g_rt.touch_ctrl.on_pointer(
                        p.id, mobiro::input::TouchAction::Down,
                        GameActivityPointerAxes_getX(&p), GameActivityPointerAxes_getY(&p), router);
                }
            } else if (masked == AMOTION_EVENT_ACTION_UP || masked == AMOTION_EVENT_ACTION_POINTER_UP) {
                if (idx >= 0 && static_cast<uint32_t>(idx) < ev.pointerCount) {
                    const auto& p = ev.pointers[idx];
                    g_rt.touch_ctrl.on_pointer(
                        p.id, mobiro::input::TouchAction::Up,
                        GameActivityPointerAxes_getX(&p), GameActivityPointerAxes_getY(&p), router);
                }
            } else if (masked == AMOTION_EVENT_ACTION_MOVE) {
                saw_touch_move = true;
                for (uint32_t k = 0; k < ev.pointerCount; ++k) {
                    const auto& p = ev.pointers[k];
                    g_rt.touch_ctrl.on_pointer(
                        p.id, mobiro::input::TouchAction::Move,
                        GameActivityPointerAxes_getX(&p), GameActivityPointerAxes_getY(&p), router);
                }
            } else if (masked == AMOTION_EVENT_ACTION_CANCEL) {
                g_rt.touch_ctrl.on_pointer(0, mobiro::input::TouchAction::Cancel, 0.0f, 0.0f, router);
            }
        }
    }
    if (!saw_touch_move) {
        g_rt.touch_ctrl.decay_camera_look(router);
    }

    android_app_clear_key_events(buf);
    android_app_clear_motion_events(buf);
}

} // namespace

// Exported C symbols resolved via dlsym(RTLD_DEFAULT) by DXVK's AndroidWsiDriver / Vulkan loader / HUD hook
extern "C" __attribute__((visibility("default")))
void* mobiro_get_android_native_window() {
    return mobiro::gfx::DxvkInterop::global().surface().native_window;
}

extern "C" __attribute__((visibility("default")))
void* mobiro_get_vk_instance_proc_addr() {
    return mobiro::gfx::TurnipWsiShim::global().get_instance_proc_addr_fn();
}

extern "C" __attribute__((visibility("default")))
const mobiro::gfx::TouchOverlayVk::HudPipelineSpec* mobiro_touch_overlay_pipeline_spec() {
    static const auto spec = mobiro::gfx::TouchOverlayVk::pipeline_spec();
    return &spec;
}

extern "C" __attribute__((visibility("default")))
int mobiro_touch_overlay_attach_device(void* vk_device,
                                       void* pfn_gdpa,
                                       uint64_t pipeline,
                                       uint64_t vertex_buffer,
                                       void* mapped_vbo,
                                       size_t capacity_bytes) {
    if (!vk_device || !pfn_gdpa) return 0;
    auto gdpa = reinterpret_cast<mobiro::gfx::TouchOverlayVk::PfnGetDeviceProcAddr>(pfn_gdpa);
    mobiro::gfx::TouchOverlayVk::VkDrawBindings b{};
    b.pipeline = pipeline;
    b.vertex_buffer = vertex_buffer;
    b.mapped_vbo = mapped_vbo;
    b.mapped_capacity_bytes = capacity_bytes;
    b.cmd_bind_pipeline = reinterpret_cast<mobiro::gfx::TouchOverlayVk::PfnVkCmdBindPipeline>(
        gdpa(vk_device, "vkCmdBindPipeline"));
    b.cmd_bind_vbo = reinterpret_cast<mobiro::gfx::TouchOverlayVk::PfnVkCmdBindVertexBuffers>(
        gdpa(vk_device, "vkCmdBindVertexBuffers"));
    b.cmd_draw = reinterpret_cast<mobiro::gfx::TouchOverlayVk::PfnVkCmdDraw>(
        gdpa(vk_device, "vkCmdDraw"));
    if (!b.cmd_bind_pipeline || !b.cmd_bind_vbo || !b.cmd_draw) return 0;
    g_rt.touch_overlay.attach_draw_bindings(b);
    return 1;
}

extern "C" __attribute__((visibility("default")))
int mobiro_touch_overlay_record_draw(void* vk_cmd_buffer) {
    return g_rt.touch_overlay.record_draw_commands(vk_cmd_buffer) ? 1 : 0;
}

extern "C" __attribute__((visibility("default")))
size_t mobiro_touch_overlay_copy_vertices(void* dst_vbo, size_t max_bytes) {
    return g_rt.touch_overlay.copy_vertices(dst_vbo, max_bytes);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_mobiro_runtime_MainActivity_nativeConfigureAndValidate(
    JNIEnv* env, jobject /*thiz*/, jstring jGameDir, jstring jSaveDir, jstring jCacheDir,
    jstring jNativeLibDir, jboolean jSelfTest) {
    const char* c_game  = env->GetStringUTFChars(jGameDir, nullptr);
    const char* c_save  = env->GetStringUTFChars(jSaveDir, nullptr);
    const char* c_cache = env->GetStringUTFChars(jCacheDir, nullptr);
    const char* c_libs  = env->GetStringUTFChars(jNativeLibDir, nullptr);

    std::string game_dir  = c_game  ? c_game  : "";
    std::string save_dir  = c_save  ? c_save  : "";
    std::string cache_dir = c_cache ? c_cache : "";
    std::string lib_dir   = c_libs  ? c_libs  : "";
    const bool self_test  = (jSelfTest == JNI_TRUE);

    env->ReleaseStringUTFChars(jGameDir, c_game);
    env->ReleaseStringUTFChars(jSaveDir, c_save);
    env->ReleaseStringUTFChars(jCacheDir, c_cache);
    env->ReleaseStringUTFChars(jNativeLibDir, c_libs);

    {
        std::lock_guard<std::mutex> lock(g_rt.log_mu);
        g_rt.boot_log_path = (std::filesystem::path(game_dir).parent_path() / "mobiro_boot.log").string();
        if (FILE* f = std::fopen(g_rt.boot_log_path.c_str(), "w")) {
            std::fprintf(f, "=== Mobiro Boot Log ===\n");
            std::fflush(f);
            std::fclose(f);
        }
    }
    mobiro_boot_log("Configure start: game_dir=%s lib_dir=%s selftest=%d",
                    game_dir.c_str(), lib_dir.c_str(), self_test ? 1 : 0);

    // 1. Clean-room BYOF validation (or direct PE64 index in clean-room self-test mode)
    std::string build_fingerprint = "mobiro_selftest";
    if (self_test) {
        if (!g_rt.vfs.index_root(game_dir)) {
            mobiro_boot_log("Self-test directory missing: %s", game_dir.c_str());
            return env->NewStringUTF("Self-test directory missing.");
        }
    } else {
        auto report = mobiro::validator::validate_byof_directory(game_dir, g_rt.vfs);
        if (!report.ok) {
            mobiro_boot_log("BYOF validation failed: %s", report.error.c_str());
            return env->NewStringUTF(report.error.c_str());
        }
        build_fingerprint = report.pe.build_fingerprint;
    }

    // 2. Initialize thread topology & bind main thread
    g_rt.balancer.initialize(16'666'666);
    g_rt.balancer.bind_current_thread(mobiro::sched::ThreadRole::MainSimPhysics);

    // 3. Configure persistent writable save overlay + per-build shader/pipeline cache + dynamic dxvk.conf
    g_rt.vfs.set_write_overlay(save_dir);
    const std::string build_cache = cache_dir + "/" + build_fingerprint;
    std::error_code ec;
    std::filesystem::create_directories(build_cache + "/turnip", ec);
    std::filesystem::create_directories(build_cache + "/dxvk", ec);
    g_rt.cache_warmer.start_async_warm(cache_dir, build_fingerprint, &g_rt.balancer);

    const std::string dxvk_conf_path = build_cache + "/dxvk.conf";
    mobiro::gfx::DxvkProfileParams params{
        .total_ram_mb = query_total_ram_mb(),
        .compiler_threads = g_rt.balancer.recommended_compiler_threads(),
        .max_frame_rate = g_rt.target_fps.load(),
        .enable_hud = false
    };
    mobiro::gfx::write_dxvk_conf(dxvk_conf_path, params);

    setenv("DXVK_WSI_DRIVER", "Android", 1);
    setenv("DXVK_CONFIG_FILE", dxvk_conf_path.c_str(), 1);
    setenv("DXVK_STATE_CACHE_PATH", (build_cache + "/dxvk").c_str(), 1);
    setenv("DXVK_ASYNC", "1", 0);
    setenv("MESA_SHADER_CACHE_DIR", (build_cache + "/turnip").c_str(), 1);
    setenv("MESA_SHADER_CACHE_MAX_SIZE", "1G", 1);
    setenv("MESA_DISK_CACHE_SINGLE_FILE", "1", 0);

    // High-throughput Box64 ARM64 Dynarec defaults for locked 60 FPS on Snapdragon 8 Gen 2+
    setenv("BOX64_DYNAREC", "1", 0);
    setenv("BOX64_DYNAREC_BIGBLOCK", "3", 0);
    setenv("BOX64_DYNAREC_CALLRET", "1", 0);
    setenv("BOX64_DYNAREC_FASTNAN", "1", 0);
    setenv("BOX64_DYNAREC_FASTROUND", "1", 0);
    setenv("BOX64_DYNAREC_NATIVEFLAGS", "1", 0);
    setenv("BOX64_DYNAREC_STRONGMEM", "1", 0);
    setenv("BOX64_DYNAREC_ALIGNED_ATOMICS", "1", 0);
    setenv("BOX64_DYNAREC_WAIT", "1", 0);
    setenv("BOX64_NOBANNER", "1", 0);
    // Gate verbose Box64 / Win32 API tracing behind an opt-in marker file so default runs have zero logging overhead for locked 60 FPS
    const auto parent_dir = std::filesystem::path(game_dir).parent_path();
    const bool trace_on = std::filesystem::exists(parent_dir / "mobiro_trace.enable", ec);
    g_rt.trace_enabled.store(trace_on, std::memory_order_relaxed);
    if (trace_on) {
        const std::string box64_log = (parent_dir / "mobiro_box64.log").string();
        const std::string api_log = (parent_dir / "mobiro_api.log").string();
        setenv("BOX64_TRACE_FILE", box64_log.c_str(), 1);
        setenv("BOX64_LOG", "1", 1);
        setenv("BOX64_SHOWBT", "1", 1);
        setenv("BOX64_SHOWSEGV", "1", 1);
        setenv("MOBIRO_API_TRACE_FILE", api_log.c_str(), 1);
        setenv("DXVK_LOG_PATH", parent_dir.string().c_str(), 1);
        setenv("DXVK_LOG_LEVEL", "debug", 1);
    } else {
        setenv("BOX64_LOG", "0", 1);
        unsetenv("BOX64_TRACE_FILE");
        unsetenv("MOBIRO_API_TRACE_FILE");
        setenv("DXVK_LOG_LEVEL", "none", 1);
        unsetenv("DXVK_LOG_PATH");
    }

    // 4. Load Mesa Turnip ICD (with graceful fallback to system Vulkan) + public-NDK WSI shim + native DXVK
    g_rt.vk_driver = mobiro::gfx::load_vulkan_driver(lib_dir);
    mobiro::gfx::TurnipWsiShim::global().initialize(g_rt.vk_driver);
    g_rt.touch_overlay.attach_vulkan_loader(g_rt.vk_driver.get_instance_proc_addr);
    const bool dxvk_loaded = mobiro::gfx::DxvkInterop::global().load_native_libraries(lib_dir);
    g_rt.dxvk_loaded.store(dxvk_loaded, std::memory_order_relaxed);
    mobiro::gfx::D3D11ComBridge::global().set_present_hook_fast(
        +[](void*, uint32_t, uint32_t) {
            g_rt.touch_overlay.pack_quads(g_rt.touch_ctrl.build_hud_quads());
            const int64_t work_ns = mobiro::gfx::DxvkInterop::global().pace_present();
            if (work_ns > 0) g_rt.balancer.report_frame_work(work_ns);
        });
    mobiro_boot_log("Vulkan ICD loaded: %s (turnip=%d, dxvk_native=%d, maxH=%u, turnip_err=%s)",
                    g_rt.vk_driver.loaded_path.c_str(),
                    g_rt.vk_driver.using_turnip ? 1 : 0,
                    dxvk_loaded ? 1 : 0,
                    mobiro::gfx::TurnipWsiShim::global().max_render_height(),
                    g_rt.vk_driver.turnip_error.empty() ? "none" : g_rt.vk_driver.turnip_error.c_str());

    // 5. Reserve Win64 guest VA arena & initialize Box64 thunk bridge + memprot sync
    if (!g_rt.arena.reserve(0x0000000100000000ULL, 10ULL * 1024 * 1024 * 1024)) {
        return env->NewStringUTF("Failed to reserve low-47-bit guest VA arena.");
    }
#ifdef MOBIRO_HAVE_BOX64
    mobiro_box64_ensure_init();
    g_rt.arena.set_prot_sync_hook(&mobiro_box64_set_prot);
#endif
    if (!g_rt.box64.initialize(&g_rt.arena, &g_rt.vfs)) {
        return env->NewStringUTF("Failed to initialize Box64 native thunk bridge.");
    }
    g_rt.box64.threads().set_balancer(&g_rt.balancer);

    // 6. Map sekiro.exe PE64 sections, apply relocations, patch IAT, and initialize Win64 TEB/PEB
    std::string exe_host_path;
    if (!g_rt.vfs.resolve("sekiro.exe", exe_host_path)) {
        return env->NewStringUTF("Unable to resolve sekiro.exe via VFS.");
    }
    g_rt.pe_image = mobiro::cpu::PeLoader::load_pe64(exe_host_path, g_rt.arena, g_rt.box64);
    if (!g_rt.pe_image.ok) {
        return env->NewStringUTF(g_rt.pe_image.error.c_str());
    }
    g_rt.box64.set_main_module_base(g_rt.pe_image.mapped_base);
    if (g_rt.pe_image.pdata_va && g_rt.pe_image.pdata_size) {
        g_rt.box64.seh().register_image(
            g_rt.pe_image.mapped_base, g_rt.pe_image.pdata_va, g_rt.pe_image.pdata_size);
    }

    const uint32_t cpus = static_cast<uint32_t>(sysconf(_SC_NPROCESSORS_CONF));
    if (!g_rt.main_thread_env.init_main_thread(
            g_rt.arena, g_rt.pe_image.mapped_base, cpus,
            static_cast<uint64_t>(getpid()), static_cast<uint64_t>(gettid()),
            2 * 1024 * 1024, &g_rt.box64.static_tls())) {
        return env->NewStringUTF("Failed to initialize Win64 TEB/PEB.");
    }
    g_rt.box64.set_main_thread_env(&g_rt.main_thread_env);

    g_rt.configured.store(true, std::memory_order_release);
    mobiro_boot_log("Mobiro mapped PE64: base=0x%llx ep=0x%llx relocs=%zu iat_ok=%zu iat_missing=%zu",
                    static_cast<unsigned long long>(g_rt.pe_image.mapped_base),
                    static_cast<unsigned long long>(g_rt.pe_image.entry_point),
                    g_rt.pe_image.relocations_applied,
                    g_rt.pe_image.imports_resolved,
                    g_rt.pe_image.unresolved_imports.size());
    for (size_t i = 0; i < g_rt.pe_image.unresolved_imports.size() && i < 64; ++i) {
        mobiro_boot_log("  unresolved IAT[%zu]: %s", i, g_rt.pe_image.unresolved_imports[i].c_str());
    }
    return env->NewStringUTF("");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_mobiro_runtime_MainActivity_nativeGetDiagnosticsSummary(JNIEnv* env, jobject /*thiz*/) {
    const auto called = g_rt.box64.called_unresolved_imports();
    const auto pace = mobiro::gfx::DxvkInterop::global().pacing_stats();
    std::string summary =
        std::string("Vk=") + (g_rt.vk_driver.using_turnip ? "Turnip" : "System") +
        " DXVK=" + (g_rt.dxvk_loaded.load(std::memory_order_relaxed) ? "native" : "none") +
#ifdef MOBIRO_HAVE_BOX64
        " Box64=embedded" +
#else
        " Box64=stub" +
#endif
        " IAT=" + std::to_string(g_rt.pe_image.imports_resolved) +
        "/" + std::to_string(g_rt.pe_image.imports_resolved + g_rt.pe_image.unresolved_imports.size()) +
        " missingCalled=" + std::to_string(called.size()) +
        " fps=" + std::to_string(g_rt.target_fps.load(std::memory_order_relaxed)) +
        " frames=" + std::to_string(pace.frames_presented) +
        " drops=" + std::to_string(pace.frames_dropped) +
        " trace=" + (g_rt.trace_enabled.load(std::memory_order_relaxed) ? "on" : "off");
    if (pace.frames_presented > 1) {
        char ms_buf[64];
        std::snprintf(ms_buf, sizeof(ms_buf), " avgMs=%.2f maxMs=%.2f",
                      pace.avg_frame_ms(), pace.max_frame_ms());
        summary += ms_buf;
    }
    if (g_rt.guest_exited.load(std::memory_order_acquire)) {
        char hex[32];
        std::snprintf(hex, sizeof(hex), " exit=0x%llx",
                      static_cast<unsigned long long>(g_rt.guest_exit_code.load(std::memory_order_relaxed)));
        summary += hex;
    }
    return env->NewStringUTF(summary.c_str());
}

extern "C" JNIEXPORT void JNICALL
Java_com_mobiro_runtime_MainActivity_nativeOnMemoryPressure(
    JNIEnv* /*env*/, jobject /*thiz*/, jint trimLevel) {
    __android_log_print(ANDROID_LOG_WARN, kLogTag, "Memory trim level=%d; reclaiming pages", trimLevel);
    g_rt.arena.trim_unused_pages();
}

extern "C" JNIEXPORT void JNICALL
Java_com_mobiro_runtime_MainActivity_nativeOnThermalHeadroom(
    JNIEnv* /*env*/, jobject /*thiz*/, jfloat headroom) {
    // Hysteresis prevents 60<->30 ping-ponging on brief thermal spikes while protecting sustained 60 FPS
    const int cur = g_rt.target_fps.load(std::memory_order_relaxed);
    int desired = cur;
    if (headroom >= 0.90f) {
        desired = 30;
    } else if (headroom <= 0.78f) {
        desired = 60;
    }
    if (desired != cur) {
        g_rt.target_fps.store(desired, std::memory_order_relaxed);
        mobiro::gfx::DxvkInterop::global().set_target_fps(desired);
        g_rt.balancer.update_target_work_duration((desired <= 30) ? 33'333'333LL : 16'666'666LL);
    }
}

namespace {
void handle_app_cmd(android_app* app, int32_t cmd) {
    switch (cmd) {
        case APP_CMD_INIT_WINDOW:
            if (app->window) {
                mobiro::gfx::DxvkInterop::global().set_native_window(app->window);
                auto s = mobiro::gfx::DxvkInterop::global().surface();
                g_rt.touch_ctrl.set_viewport(static_cast<float>(s.width), static_cast<float>(s.height));
                g_rt.box64.window().set_dimensions(s.width, s.height);
                mobiro_boot_log("ANativeWindow bound: %dx%d (gen=%llu)",
                                s.width, s.height,
                                static_cast<unsigned long long>(s.generation));
            }
            break;
        case APP_CMD_TERM_WINDOW:
            mobiro::gfx::DxvkInterop::global().set_native_window(nullptr, 0, 0);
            mobiro_boot_log("ANativeWindow released");
            break;
        default:
            break;
    }
}
} // namespace

extern "C" void android_main(struct android_app* app) {
    app->onAppCmd = handle_app_cmd;
    while (!app->destroyRequested) {
        int events = 0;
        android_poll_source* source = nullptr;
        const int poll_ms = g_rt.guest_started.load(std::memory_order_relaxed) ? 4 : 16;
        while (ALooper_pollOnce(poll_ms, nullptr, &events, reinterpret_cast<void**>(&source)) >= 0) {
            if (source) source->process(app, source);
        }
        process_game_activity_input(app);

        // Start x86_64 guest entry point on Prime core once BYOF PE64 + ANativeWindow are both ready
        if (g_rt.configured.load(std::memory_order_acquire) &&
            !g_rt.guest_started.load(std::memory_order_relaxed) &&
            mobiro::gfx::DxvkInterop::global().surface().native_window != nullptr) {
            if (!g_rt.guest_started.exchange(true, std::memory_order_acq_rel)) {
                g_rt.guest_thread = std::thread([]() {
                    g_rt.balancer.bind_current_thread(mobiro::sched::ThreadRole::MainSimPhysics);
                    mobiro_boot_log("Launching guest entry point at 0x%llx",
                                    static_cast<unsigned long long>(g_rt.pe_image.entry_point));
                    auto res = mobiro::cpu::GuestExecutor::run_entry(
                        g_rt.pe_image, g_rt.main_thread_env, g_rt.box64);
                    g_rt.guest_exit_code.store(res.exit_rax, std::memory_order_relaxed);
                    g_rt.guest_exited.store(true, std::memory_order_release);
                    const auto pace = mobiro::gfx::DxvkInterop::global().pacing_stats();
                    mobiro_boot_log(
                        "Guest exited ok=%d rax=0x%llx frames=%llu drops=%llu avgMs=%.2f maxMs=%.2f trace=%s err=%s",
                        res.ok ? 1 : 0,
                        static_cast<unsigned long long>(res.exit_rax),
                        static_cast<unsigned long long>(pace.frames_presented),
                        static_cast<unsigned long long>(pace.frames_dropped),
                        pace.avg_frame_ms(),
                        pace.max_frame_ms(),
                        g_rt.trace_enabled.load(std::memory_order_relaxed) ? "on" : "off",
                        res.error.c_str());
                    const auto called = g_rt.box64.called_unresolved_imports();
                    for (size_t i = 0; i < called.size() && i < 32; ++i) {
                        mobiro_boot_log("  called missing IAT[%zu]: %s", i, called[i].c_str());
                    }
                });
            }
        }
    }
    g_rt.box64.window().post_quit(0);
    if (g_rt.guest_thread.joinable()) g_rt.guest_thread.join();
    g_rt.cache_warmer.wait();
    g_rt.box64.shutdown();
    mobiro::audio::AAudioXAudioBridge::global().stop();
    mobiro::gfx::DxvkInterop::global().unload();
    mobiro::gfx::TurnipWsiShim::global().shutdown();
    mobiro::gfx::unload_vulkan_driver(g_rt.vk_driver);
}
