#include "audio/aaudio_xaudio_bridge.hpp"
#include "cpu_mem/box64_bridge.hpp"
#include "cpu_mem/guest_arena.hpp"
#include "cpu_mem/pe_loader.hpp"
#include "cpu_mem/win64_teb.hpp"
#include "gfx/dxvk_config_gen.hpp"
#include "gfx/dxvk_interop.hpp"
#include "gfx/pipeline_cache_warmer.hpp"
#include "gfx/turnip_loader.hpp"
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
#include <cstdlib>
#include <filesystem>
#include <string>

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
    mobiro::input::TouchController touch_ctrl;
    mobiro::sched::ThreadBalancer balancer;
    std::atomic<int> target_fps{60};
    std::atomic<bool> configured{false};
};

MobiroRuntimeState g_rt;

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

    for (uint64_t i = 0; i < buf->motionEventsCount; ++i) {
        const auto& ev = buf->motionEvents[i];
        if ((ev.source & AINPUT_SOURCE_JOYSTICK) == AINPUT_SOURCE_JOYSTICK && ev.pointerCount > 0) {
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

    android_app_clear_key_events(buf);
    android_app_clear_motion_events(buf);
}

} // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_mobiro_runtime_MainActivity_nativeConfigureAndValidate(
    JNIEnv* env, jobject /*thiz*/, jstring jGameDir, jstring jSaveDir, jstring jCacheDir, jstring jNativeLibDir) {
    const char* c_game  = env->GetStringUTFChars(jGameDir, nullptr);
    const char* c_save  = env->GetStringUTFChars(jSaveDir, nullptr);
    const char* c_cache = env->GetStringUTFChars(jCacheDir, nullptr);
    const char* c_libs  = env->GetStringUTFChars(jNativeLibDir, nullptr);

    std::string game_dir  = c_game  ? c_game  : "";
    std::string save_dir  = c_save  ? c_save  : "";
    std::string cache_dir = c_cache ? c_cache : "";
    std::string lib_dir   = c_libs  ? c_libs  : "";

    env->ReleaseStringUTFChars(jGameDir, c_game);
    env->ReleaseStringUTFChars(jSaveDir, c_save);
    env->ReleaseStringUTFChars(jCacheDir, c_cache);
    env->ReleaseStringUTFChars(jNativeLibDir, c_libs);

    // 1. Clean-room BYOF validation (PE32+ header + Data0..5 .bhd/.bdt BDF4 magic)
    auto report = mobiro::validator::validate_byof_directory(game_dir, g_rt.vfs);
    if (!report.ok) {
        return env->NewStringUTF(report.error.c_str());
    }

    // 2. Initialize thread topology & bind main thread
    g_rt.balancer.initialize(16'666'666);
    g_rt.balancer.bind_current_thread(mobiro::sched::ThreadRole::MainSimPhysics);

    // 3. Configure persistent writable save overlay + per-build shader/pipeline cache + dynamic dxvk.conf
    g_rt.vfs.set_write_overlay(save_dir);
    const std::string build_cache = cache_dir + "/" + report.pe.build_fingerprint;
    std::error_code ec;
    std::filesystem::create_directories(build_cache + "/turnip", ec);
    std::filesystem::create_directories(build_cache + "/dxvk", ec);
    g_rt.cache_warmer.start_async_warm(cache_dir, report.pe.build_fingerprint, &g_rt.balancer);

    const std::string dxvk_conf_path = build_cache + "/dxvk.conf";
    mobiro::gfx::DxvkProfileParams params{
        .total_ram_mb = query_total_ram_mb(),
        .compiler_threads = g_rt.balancer.recommended_compiler_threads(),
        .max_frame_rate = g_rt.target_fps.load(),
        .enable_hud = false
    };
    mobiro::gfx::write_dxvk_conf(dxvk_conf_path, params);

    setenv("DXVK_CONFIG_FILE", dxvk_conf_path.c_str(), 1);
    setenv("DXVK_STATE_CACHE_PATH", (build_cache + "/dxvk").c_str(), 1);
    setenv("MESA_SHADER_CACHE_DIR", (build_cache + "/turnip").c_str(), 1);
    setenv("MESA_SHADER_CACHE_MAX_SIZE", "1G", 1);

    // 4. Load Mesa Turnip ICD (with graceful fallback to system Vulkan) + native AArch64 DXVK
    g_rt.vk_driver = mobiro::gfx::load_vulkan_driver(lib_dir);
    const bool dxvk_loaded = mobiro::gfx::DxvkInterop::global().load_native_libraries(lib_dir);
    __android_log_print(ANDROID_LOG_INFO, kLogTag, "Vulkan ICD loaded: %s (turnip=%d, dxvk_native=%d)",
                        g_rt.vk_driver.loaded_path.c_str(),
                        g_rt.vk_driver.using_turnip ? 1 : 0,
                        dxvk_loaded ? 1 : 0);

    // 5. Reserve Win64 guest VA arena & initialize Box64 thunk bridge
    if (!g_rt.arena.reserve(0x0000000100000000ULL, 10ULL * 1024 * 1024 * 1024)) {
        return env->NewStringUTF("Failed to reserve low-47-bit guest VA arena.");
    }
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
            static_cast<uint64_t>(getpid()), static_cast<uint64_t>(gettid()))) {
        return env->NewStringUTF("Failed to initialize Win64 TEB/PEB.");
    }
    g_rt.box64.set_main_teb(g_rt.main_thread_env.teb);

    g_rt.configured.store(true, std::memory_order_release);
    __android_log_print(ANDROID_LOG_INFO, kLogTag,
                        "Mobiro mapped PE64: base=0x%llx ep=0x%llx relocs=%zu iat_ok=%zu iat_missing=%zu",
                        static_cast<unsigned long long>(g_rt.pe_image.mapped_base),
                        static_cast<unsigned long long>(g_rt.pe_image.entry_point),
                        g_rt.pe_image.relocations_applied,
                        g_rt.pe_image.imports_resolved,
                        g_rt.pe_image.unresolved_imports.size());
    return env->NewStringUTF("");
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
    // Step down from 60 -> 30 FPS cleanly before aggressive thermal throttling hits
    int desired = (headroom >= 0.85f) ? 30 : 60;
    g_rt.target_fps.store(desired, std::memory_order_relaxed);
    mobiro::gfx::DxvkInterop::global().set_target_fps(desired);
}

namespace {
void handle_app_cmd(android_app* app, int32_t cmd) {
    switch (cmd) {
        case APP_CMD_INIT_WINDOW:
            if (app->window) {
                mobiro::gfx::DxvkInterop::global().set_native_window(app->window);
                auto s = mobiro::gfx::DxvkInterop::global().surface();
                g_rt.touch_ctrl.set_viewport(static_cast<float>(s.width), static_cast<float>(s.height));
                __android_log_print(ANDROID_LOG_INFO, kLogTag,
                                    "ANativeWindow bound: %dx%d (gen=%llu)",
                                    s.width, s.height,
                                    static_cast<unsigned long long>(s.generation));
            }
            break;
        case APP_CMD_TERM_WINDOW:
            mobiro::gfx::DxvkInterop::global().set_native_window(nullptr, 0, 0);
            __android_log_print(ANDROID_LOG_INFO, kLogTag, "ANativeWindow released");
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
        while (ALooper_pollOnce(0, nullptr, &events, reinterpret_cast<void**>(&source)) >= 0) {
            if (source) source->process(app, source);
        }
        process_game_activity_input(app);
    }
    g_rt.cache_warmer.wait();
    g_rt.box64.shutdown();
    mobiro::audio::AAudioXAudioBridge::global().stop();
    mobiro::gfx::DxvkInterop::global().unload();
    mobiro::gfx::unload_vulkan_driver(g_rt.vk_driver);
}
