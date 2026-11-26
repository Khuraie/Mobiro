#pragma once

#include <string>

#if defined(__linux__) || defined(__ANDROID__)
#include <dlfcn.h>
#endif

namespace mobiro::gfx {

using PfnGetInstanceProcAddr = void* (*)(void* instance, const char* name);

struct VulkanDriverHandle {
    void* dl_handle = nullptr;
    PfnGetInstanceProcAddr get_instance_proc_addr = nullptr;
    bool using_turnip = false;
    std::string loaded_path;
};

// Loads open-source Mesa Turnip ICD (libvulkan_freedreno.so) directly from app nativeLibDir
// to bypass outdated OEM Adreno Vulkan drivers, falling back cleanly to system libvulkan.so.
inline VulkanDriverHandle load_vulkan_driver(const std::string& native_lib_dir) {
    VulkanDriverHandle res;
#if defined(__linux__) || defined(__ANDROID__)
    const std::string turnip_path = native_lib_dir + "/libvulkan_freedreno.so";
    void* h = dlopen(turnip_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (h) {
        auto* fn = reinterpret_cast<PfnGetInstanceProcAddr>(dlsym(h, "vk_icdGetInstanceProcAddr"));
        if (!fn) fn = reinterpret_cast<PfnGetInstanceProcAddr>(dlsym(h, "vkGetInstanceProcAddr"));
        if (fn) {
            res.dl_handle = h;
            res.get_instance_proc_addr = fn;
            res.using_turnip = true;
            res.loaded_path = turnip_path;
            return res;
        }
        dlclose(h);
    }

    // Fallback for non-Adreno GPUs (Mali / Xclipse) or builds without Turnip submodule
    h = dlopen("libvulkan.so", RTLD_NOW | RTLD_LOCAL);
    if (h) {
        auto* fn = reinterpret_cast<PfnGetInstanceProcAddr>(dlsym(h, "vkGetInstanceProcAddr"));
        if (fn) {
            res.dl_handle = h;
            res.get_instance_proc_addr = fn;
            res.using_turnip = false;
            res.loaded_path = "libvulkan.so";
            return res;
        }
        dlclose(h);
    }
#else
    (void)native_lib_dir;
#endif
    return res;
}

inline void unload_vulkan_driver(VulkanDriverHandle& h) {
#if defined(__linux__) || defined(__ANDROID__)
    if (h.dl_handle) {
        dlclose(h.dl_handle);
        h.dl_handle = nullptr;
    }
#endif
    h.get_instance_proc_addr = nullptr;
    h.using_turnip = false;
}

} // namespace mobiro::gfx
