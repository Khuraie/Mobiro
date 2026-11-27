#pragma once

#include <cstdint>
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
    std::string turnip_error;
};

// Loads open-source Mesa Turnip ICD (libvulkan_freedreno.so) directly from app nativeLibDir
// to bypass outdated OEM Adreno Vulkan drivers, falling back cleanly to system libvulkan.so.
inline VulkanDriverHandle load_vulkan_driver(const std::string& native_lib_dir) {
    VulkanDriverHandle res;
#if defined(__linux__) || defined(__ANDROID__)
    const std::string turnip_path = native_lib_dir + "/libvulkan_freedreno.so";
    void* h = dlopen(turnip_path.c_str(), RTLD_NOW | RTLD_LOCAL);
    std::string used_path = turnip_path;
    if (!h) {
        const char* e1 = dlerror();
        if (e1) res.turnip_error = e1;
        // Android extractNativeLibs="false" keeps .so inside APK; bare soname resolves via linker namespace
        h = dlopen("libvulkan_freedreno.so", RTLD_NOW | RTLD_LOCAL);
        used_path = "libvulkan_freedreno.so";
        if (!h) {
            const char* e2 = dlerror();
            if (e2) {
                if (!res.turnip_error.empty()) res.turnip_error += " | ";
                res.turnip_error += e2;
            }
        }
    }
    if (h) {
        auto* fn = reinterpret_cast<PfnGetInstanceProcAddr>(dlsym(h, "vk_icdGetInstanceProcAddr"));
        if (!fn) fn = reinterpret_cast<PfnGetInstanceProcAddr>(dlsym(h, "vkGetInstanceProcAddr"));
        if (!fn) {
            // Android Mesa Turnip builds export the Android Vulkan HAL module symbol `HMI`
            // (hwvulkan_module_t) whose methods->open(hmi, "vk0", &dev) returns GetInstanceProcAddr.
            struct HwModuleMethods {
                int (*open)(const void* module, const char* id, void** device);
            };
            struct HwModule {
                uint32_t tag;
                uint16_t module_api_version;
                uint16_t hal_api_version;
                const char* id;
                const char* name;
                const char* author;
                const HwModuleMethods* methods;
            };
            struct HwVulkanDevice {
                uint32_t tag;
                uint32_t version;
                void* module;
                uint64_t reserved[12];
                int (*close)(void* device);
                void* enumerate_instance_extension_properties;
                void* create_instance;
                PfnGetInstanceProcAddr get_instance_proc_addr;
            };
            if (auto* hmi = reinterpret_cast<const HwModule*>(dlsym(h, "HMI"));
                hmi && hmi->methods && hmi->methods->open) {
                void* dev = nullptr;
                if (hmi->methods->open(hmi, "vk0", &dev) == 0 && dev) {
                    auto* vk_dev = reinterpret_cast<HwVulkanDevice*>(dev);
                    fn = vk_dev->get_instance_proc_addr;
                    if (vk_dev->close) vk_dev->close(dev);
                }
            }
        }
        if (fn) {
            res.dl_handle = h;
            res.get_instance_proc_addr = fn;
            res.using_turnip = true;
            res.loaded_path = used_path;
            res.turnip_error.clear();
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
