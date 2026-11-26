#pragma once

#include "turnip_loader.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>

#if defined(__ANDROID__)
#include <android/native_window.h>
#endif
#if defined(__linux__) || defined(__ANDROID__)
#include <dlfcn.h>
#endif

namespace mobiro::gfx {

// Native AArch64 DXVK entry point signatures (matches D3D11/DXGI ABI cleanly)
using PfnD3D11CreateDevice = int32_t (*)(
    void* adapter,
    uint32_t driver_type,
    void* software,
    uint32_t flags,
    const uint32_t* feature_levels,
    uint32_t num_feature_levels,
    uint32_t sdk_version,
    void** out_device,
    uint32_t* out_feature_level,
    void** out_immediate_context);

using PfnD3D11CreateDeviceAndSwapChain = int32_t (*)(
    void* adapter,
    uint32_t driver_type,
    void* software,
    uint32_t flags,
    const uint32_t* feature_levels,
    uint32_t num_feature_levels,
    uint32_t sdk_version,
    const void* swap_chain_desc,
    void** out_swap_chain,
    void** out_device,
    uint32_t* out_feature_level,
    void** out_immediate_context);

using PfnCreateDXGIFactory1 = int32_t (*)(const void* riid, void** out_factory);

struct DxvkBackendTable {
    PfnD3D11CreateDevice d3d11_create_device = nullptr;
    PfnD3D11CreateDeviceAndSwapChain d3d11_create_device_and_swap_chain = nullptr;
    PfnCreateDXGIFactory1 create_dxgi_factory1 = nullptr;
};

struct SurfaceSnapshot {
    void* native_window = nullptr;
    int32_t width = 0;
    int32_t height = 0;
    int32_t target_fps = 60;
    uint64_t generation = 0;
};

struct FramePacingStats {
    uint64_t frames_presented = 0;
    uint64_t frames_dropped = 0;
    int64_t last_work_ns = 0;
    int64_t last_frame_ns = 0;
    int64_t max_frame_ns = 0;
};

// Bridges Android ANativeWindow + Mesa Turnip ICD + native AArch64 DXVK libraries
// (libdxvk_d3d11.so / libdxvk_dxgi.so) with zero x86 emulation of graphics calls.
class DxvkInterop {
public:
    static constexpr int32_t kHrENotImpl = static_cast<int32_t>(0x80004001u);

    static DxvkInterop& global() {
        static DxvkInterop inst;
        return inst;
    }

    bool load_native_libraries(const std::string& native_lib_dir) {
#if defined(__linux__) || defined(__ANDROID__)
        std::lock_guard<std::mutex> lock(mu_);
        const std::string dxgi_path  = native_lib_dir + "/libdxvk_dxgi.so";
        const std::string d3d11_path = native_lib_dir + "/libdxvk_d3d11.so";

        dxgi_dl_  = dlopen(dxgi_path.c_str(), RTLD_NOW | RTLD_LOCAL);
        d3d11_dl_ = dlopen(d3d11_path.c_str(), RTLD_NOW | RTLD_LOCAL);

        if (dxgi_dl_) {
            backend_.create_dxgi_factory1 =
                reinterpret_cast<PfnCreateDXGIFactory1>(dlsym(dxgi_dl_, "CreateDXGIFactory1"));
        }
        if (d3d11_dl_) {
            backend_.d3d11_create_device =
                reinterpret_cast<PfnD3D11CreateDevice>(dlsym(d3d11_dl_, "D3D11CreateDevice"));
            backend_.d3d11_create_device_and_swap_chain =
                reinterpret_cast<PfnD3D11CreateDeviceAndSwapChain>(
                    dlsym(d3d11_dl_, "D3D11CreateDeviceAndSwapChain"));
        }
        const bool ok = backend_.d3d11_create_device != nullptr && backend_.create_dxgi_factory1 != nullptr;
        auto_wrap_com_.store(ok, std::memory_order_release);
        return ok;
#else
        (void)native_lib_dir;
        return false;
#endif
    }

    void unload() {
#if defined(__linux__) || defined(__ANDROID__)
        std::lock_guard<std::mutex> lock(mu_);
        if (d3d11_dl_) { dlclose(d3d11_dl_); d3d11_dl_ = nullptr; }
        if (dxgi_dl_)  { dlclose(dxgi_dl_);  dxgi_dl_  = nullptr; }
        backend_ = {};
#else
        std::lock_guard<std::mutex> lock(mu_);
        backend_ = {};
#endif
    }

    void set_backend_override(const DxvkBackendTable& table, bool auto_wrap_com = false) {
        std::lock_guard<std::mutex> lock(mu_);
        backend_ = table;
        auto_wrap_com_.store(auto_wrap_com, std::memory_order_release);
    }

    void set_auto_wrap_com(bool enable) { auto_wrap_com_.store(enable, std::memory_order_release); }
    bool auto_wrap_com() const { return auto_wrap_com_.load(std::memory_order_acquire); }

    // Hybrid sleep + sub-ms spin frame pacer for zero-jitter 60/30 FPS presentation.
    // Returns actual frame work duration (ns) for Android ADPF closed-loop frequency scaling.
    int64_t pace_present() {
        const int64_t interval_ns = target_frame_interval_ns();
        const auto interval = std::chrono::nanoseconds(interval_ns);
        const auto now = std::chrono::steady_clock::now();
        std::chrono::steady_clock::time_point wake_at{};
        int64_t work_ns = 0;
        bool need_wait = false;
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (last_present_.time_since_epoch().count() == 0) {
                last_present_ = now;
                prev_frame_end_ = now;
                stats_.frames_presented = 1;
                return 0;
            }
            work_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now - prev_frame_end_).count();
            const int64_t frame_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now - last_present_).count();
            ++stats_.frames_presented;
            stats_.last_work_ns = work_ns;
            stats_.last_frame_ns = frame_ns;
            if (frame_ns > stats_.max_frame_ns) stats_.max_frame_ns = frame_ns;
            if (frame_ns > interval_ns + 1'500'000LL) ++stats_.frames_dropped;

            wake_at = last_present_ + interval;
            need_wait = (wake_at > now);
            last_present_ = need_wait ? wake_at : now;
        }
        if (need_wait) {
            constexpr auto kSpinWindow = std::chrono::microseconds(400);
            if (wake_at - now > kSpinWindow) {
                std::this_thread::sleep_until(wake_at - kSpinWindow);
            }
            while (std::chrono::steady_clock::now() < wake_at) {
                std::this_thread::yield();
            }
        }
        const auto end_tp = std::chrono::steady_clock::now();
        {
            std::lock_guard<std::mutex> lock(mu_);
            prev_frame_end_ = end_tp;
        }
        return work_ns;
    }

    void reset_pacer() {
        std::lock_guard<std::mutex> lock(mu_);
        last_present_ = {};
        prev_frame_end_ = {};
        stats_ = {};
    }

    FramePacingStats pacing_stats() const {
        std::lock_guard<std::mutex> lock(mu_);
        return stats_;
    }

    void set_native_window(void* window, int32_t width = 0, int32_t height = 0) {
        std::lock_guard<std::mutex> lock(mu_);
        surface_.native_window = window;
#if defined(__ANDROID__)
        if (window && (width == 0 || height == 0)) {
            auto* nw = static_cast<ANativeWindow*>(window);
            width = ANativeWindow_getWidth(nw);
            height = ANativeWindow_getHeight(nw);
        }
#endif
        surface_.width = width;
        surface_.height = height;
        ++surface_.generation;
    }

    void set_target_fps(int32_t fps) {
        const int32_t clamped = (fps <= 30) ? 30 : 60;
        target_fps_.store(clamped, std::memory_order_relaxed);
        std::lock_guard<std::mutex> lock(mu_);
        surface_.target_fps = clamped;
    }

    int64_t target_frame_interval_ns() const noexcept {
        return (target_fps_.load(std::memory_order_relaxed) <= 30) ? 33'333'333LL : 16'666'666LL;
    }

    SurfaceSnapshot surface() const {
        std::lock_guard<std::mutex> lock(mu_);
        return surface_;
    }

    int32_t call_d3d11_create_device(
        void* adapter, uint32_t driver_type, void* software, uint32_t flags,
        const uint32_t* feature_levels, uint32_t num_feature_levels, uint32_t sdk_version,
        void** out_device, uint32_t* out_feature_level, void** out_immediate_context) const {
        PfnD3D11CreateDevice fn = nullptr;
        {
            std::lock_guard<std::mutex> lock(mu_);
            fn = backend_.d3d11_create_device;
        }
        if (!fn) return kHrENotImpl;
        return fn(adapter, driver_type, software, flags, feature_levels,
                  num_feature_levels, sdk_version, out_device, out_feature_level, out_immediate_context);
    }

    int32_t call_d3d11_create_device_and_swap_chain(
        void* adapter, uint32_t driver_type, void* software, uint32_t flags,
        const uint32_t* feature_levels, uint32_t num_feature_levels, uint32_t sdk_version,
        const void* swap_chain_desc, void** out_swap_chain,
        void** out_device, uint32_t* out_feature_level, void** out_immediate_context) const {
        PfnD3D11CreateDeviceAndSwapChain fn = nullptr;
        {
            std::lock_guard<std::mutex> lock(mu_);
            fn = backend_.d3d11_create_device_and_swap_chain;
        }
        if (!fn) return kHrENotImpl;
        return fn(adapter, driver_type, software, flags, feature_levels, num_feature_levels,
                  sdk_version, swap_chain_desc, out_swap_chain, out_device,
                  out_feature_level, out_immediate_context);
    }

    int32_t call_create_dxgi_factory1(const void* riid, void** out_factory) const {
        PfnCreateDXGIFactory1 fn = nullptr;
        {
            std::lock_guard<std::mutex> lock(mu_);
            fn = backend_.create_dxgi_factory1;
        }
        if (!fn) return kHrENotImpl;
        return fn(riid, out_factory);
    }

private:
    mutable std::mutex mu_;
    DxvkBackendTable backend_{};
    SurfaceSnapshot surface_{};
    std::atomic<int32_t> target_fps_{60};
    std::atomic<bool> auto_wrap_com_{false};
    std::chrono::steady_clock::time_point last_present_{};
    std::chrono::steady_clock::time_point prev_frame_end_{};
    FramePacingStats stats_{};
    void* dxgi_dl_ = nullptr;
    void* d3d11_dl_ = nullptr;
};

} // namespace mobiro::gfx
