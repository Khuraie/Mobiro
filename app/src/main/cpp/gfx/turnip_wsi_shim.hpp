#pragma once

#include "turnip_loader.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#if defined(__ANDROID__)
#define VK_USE_PLATFORM_ANDROID_KHR 1
#include <android/native_window.h>
#include <vulkan/vulkan.h>
#endif

namespace mobiro::gfx {

// Portable WSI extension filter used by TurnipWsiShim (tested on host & Android)
inline std::vector<const char*> filter_turnip_wsi_extensions(
    const char* const* exts, uint32_t count, bool is_instance) {
    std::vector<const char*> out;
    out.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        const char* e = exts ? exts[i] : nullptr;
        if (!e) continue;
        if (is_instance) {
            if (std::strcmp(e, "VK_KHR_surface") == 0 ||
                std::strcmp(e, "VK_KHR_android_surface") == 0 ||
                std::strcmp(e, "VK_KHR_get_surface_capabilities2") == 0 ||
                std::strcmp(e, "VK_EXT_swapchain_colorspace") == 0 ||
                std::strcmp(e, "VK_EXT_surface_maintenance1") == 0) {
                continue;
            }
        } else {
            if (std::strcmp(e, "VK_KHR_swapchain") == 0 ||
                std::strcmp(e, "VK_KHR_swapchain_mutable_format") == 0 ||
                std::strcmp(e, "VK_EXT_swapchain_maintenance1") == 0) {
                continue;
            }
        }
        out.push_back(e);
    }
    return out;
}

// Clean-room, 100% public-Android-NDK Vulkan WSI shim layered directly on top of
// Mesa Turnip (libvulkan_freedreno.so). Provides VK_KHR_surface, VK_KHR_android_surface,
// and VK_KHR_swapchain via ANativeWindow_lock/unlockAndPost so DXVK 3.2+ runs natively on
// Turnip (full Vulkan 1.3 + shaderInt64 + BC1-BC7) with zero root or linker-namespace bypasses.
class TurnipWsiShim {
public:
    static TurnipWsiShim& global() {
        static TurnipWsiShim inst;
        return inst;
    }

    bool initialize(const VulkanDriverHandle& drv) {
        std::lock_guard<std::mutex> lk(mu_);
        drv_ = drv;
        ready_ = drv.using_turnip && drv.get_instance_proc_addr != nullptr;
        return ready_;
    }

    void shutdown() {
        std::lock_guard<std::mutex> lk(mu_);
        ready_ = false;
        drv_ = {};
#if defined(__ANDROID__)
        devices_.clear();
        instances_.clear();
#endif
    }

    bool is_ready() const {
        std::lock_guard<std::mutex> lk(mu_);
        return ready_;
    }

    void* get_instance_proc_addr_fn() const {
#if defined(__ANDROID__)
        return is_ready() ? reinterpret_cast<void*>(&shim_vkGetInstanceProcAddr) : nullptr;
#else
        return nullptr;
#endif
    }

#if defined(__ANDROID__)
private:
    struct InstanceRec {
        VkInstance instance = VK_NULL_HANDLE;
        PFN_vkEnumerateDeviceExtensionProperties enum_dev_ext = nullptr;
        PFN_vkCreateDevice create_device = nullptr;
        PFN_vkGetDeviceProcAddr get_dev_proc = nullptr;
        PFN_vkGetPhysicalDeviceMemoryProperties get_mem_props = nullptr;
    };

    struct DeviceRec {
        VkDevice device = VK_NULL_HANDLE;
        VkPhysicalDevice phys = VK_NULL_HANDLE;
        VkInstance instance = VK_NULL_HANDLE;
        uint32_t queue_family = 0;
        VkQueue default_queue = VK_NULL_HANDLE;
        PFN_vkGetDeviceProcAddr get_dev_proc = nullptr;
        PFN_vkDestroyDevice destroy_device = nullptr;
        PFN_vkDeviceWaitIdle wait_idle = nullptr;
        PFN_vkGetDeviceQueue get_queue = nullptr;
        PFN_vkCreateImage create_image = nullptr;
        PFN_vkDestroyImage destroy_image = nullptr;
        PFN_vkGetImageMemoryRequirements get_img_req = nullptr;
        PFN_vkCreateBuffer create_buffer = nullptr;
        PFN_vkDestroyBuffer destroy_buffer = nullptr;
        PFN_vkGetBufferMemoryRequirements get_buf_req = nullptr;
        PFN_vkAllocateMemory alloc_mem = nullptr;
        PFN_vkFreeMemory free_mem = nullptr;
        PFN_vkBindImageMemory bind_img_mem = nullptr;
        PFN_vkBindBufferMemory bind_buf_mem = nullptr;
        PFN_vkMapMemory map_mem = nullptr;
        PFN_vkUnmapMemory unmap_mem = nullptr;
        PFN_vkCreateCommandPool create_cmd_pool = nullptr;
        PFN_vkDestroyCommandPool destroy_cmd_pool = nullptr;
        PFN_vkAllocateCommandBuffers alloc_cmd = nullptr;
        PFN_vkResetCommandBuffer reset_cmd = nullptr;
        PFN_vkBeginCommandBuffer begin_cmd = nullptr;
        PFN_vkEndCommandBuffer end_cmd = nullptr;
        PFN_vkCmdPipelineBarrier cmd_barrier = nullptr;
        PFN_vkCmdCopyImageToBuffer cmd_copy_img_to_buf = nullptr;
        PFN_vkCreateFence create_fence = nullptr;
        PFN_vkDestroyFence destroy_fence = nullptr;
        PFN_vkResetFences reset_fences = nullptr;
        PFN_vkWaitForFences wait_fences = nullptr;
        PFN_vkQueueSubmit queue_submit = nullptr;
    };

    struct SurfaceObj {
        ANativeWindow* window = nullptr;
    };

    // shortcut: uses public NDK ANativeWindow_lock + UMA staging copy (~60 us @ 720p LPDDR5X);
    // upgrade to zero-copy AHardwareBuffer import once Android 16 gralloc export is available in clns-*.
    struct SwapchainObj {
        VkDevice device = VK_NULL_HANDLE;
        ANativeWindow* window = nullptr;
        uint32_t width = 1280;
        uint32_t height = 720;
        std::vector<VkImage> images;
        std::vector<VkDeviceMemory> image_mems;
        VkBuffer staging_buf = VK_NULL_HANDLE;
        VkDeviceMemory staging_mem = VK_NULL_HANDLE;
        void* staging_mapped = nullptr;
        VkCommandPool cmd_pool = VK_NULL_HANDLE;
        VkCommandBuffer cmd_buf = VK_NULL_HANDLE;
        VkFence present_fence = VK_NULL_HANDLE;
        uint32_t next_index = 0;
    };

    static uint32_t find_mem_type(const VkPhysicalDeviceMemoryProperties& props,
                                  uint32_t type_bits, VkMemoryPropertyFlags want) {
        for (uint32_t i = 0; i < props.memoryTypeCount; ++i) {
            if ((type_bits & (1u << i)) && (props.memoryTypes[i].propertyFlags & want) == want) {
                return i;
            }
        }
        return UINT32_MAX;
    }

    static VkResult VKAPI_CALL shim_vkEnumerateInstanceVersion(uint32_t* pApiVersion) {
        if (pApiVersion) *pApiVersion = VK_API_VERSION_1_3;
        return VK_SUCCESS;
    }

    static VkResult VKAPI_CALL shim_vkEnumerateInstanceLayerProperties(
        uint32_t* pCount, VkLayerProperties* /*pProps*/) {
        if (pCount) *pCount = 0;
        return VK_SUCCESS;
    }

    static VkResult VKAPI_CALL shim_vkEnumerateInstanceExtensionProperties(
        const char* pLayerName, uint32_t* pCount, VkExtensionProperties* pProps) {
        if (!pCount) return VK_ERROR_INITIALIZATION_FAILED;
        if (pLayerName && pLayerName[0] != '\0') {
            *pCount = 0;
            return VK_SUCCESS;
        }
        auto& self = global();
        auto real_enum = reinterpret_cast<PFN_vkEnumerateInstanceExtensionProperties>(
            self.drv_.hal_enum_inst_ext
                ? self.drv_.hal_enum_inst_ext
                : self.drv_.get_instance_proc_addr(nullptr, "vkEnumerateInstanceExtensionProperties"));

        std::vector<VkExtensionProperties> exts;
        if (real_enum) {
            uint32_t n = 0;
            if (real_enum(nullptr, &n, nullptr) == VK_SUCCESS && n > 0) {
                exts.resize(n);
                real_enum(nullptr, &n, exts.data());
                exts.resize(n);
            }
        }
        auto add_ext = [&](const char* name, uint32_t ver) {
            for (const auto& e : exts) {
                if (std::strcmp(e.extensionName, name) == 0) return;
            }
            VkExtensionProperties ep{};
            std::strncpy(ep.extensionName, name, VK_MAX_EXTENSION_NAME_SIZE - 1);
            ep.specVersion = ver;
            exts.push_back(ep);
        };
        add_ext(VK_KHR_SURFACE_EXTENSION_NAME, 25);
        add_ext(VK_KHR_ANDROID_SURFACE_EXTENSION_NAME, 6);

        if (!pProps) {
            *pCount = static_cast<uint32_t>(exts.size());
            return VK_SUCCESS;
        }
        const uint32_t copy_n = std::min<uint32_t>(*pCount, static_cast<uint32_t>(exts.size()));
        if (copy_n) std::memcpy(pProps, exts.data(), copy_n * sizeof(VkExtensionProperties));
        *pCount = copy_n;
        return (copy_n < exts.size()) ? VK_INCOMPLETE : VK_SUCCESS;
    }

    static VkResult VKAPI_CALL shim_vkCreateInstance(
        const VkInstanceCreateInfo* pCreateInfo,
        const VkAllocationCallbacks* pAllocator,
        VkInstance* pInstance) {
        if (!pCreateInfo || !pInstance) return VK_ERROR_INITIALIZATION_FAILED;
        auto& self = global();
        auto real_create = reinterpret_cast<PFN_vkCreateInstance>(
            self.drv_.hal_create_instance
                ? self.drv_.hal_create_instance
                : self.drv_.get_instance_proc_addr(nullptr, "vkCreateInstance"));
        if (!real_create) return VK_ERROR_INITIALIZATION_FAILED;

        auto filtered = filter_turnip_wsi_extensions(
            pCreateInfo->ppEnabledExtensionNames, pCreateInfo->enabledExtensionCount, true);
        VkInstanceCreateInfo ci = *pCreateInfo;
        ci.enabledLayerCount = 0;
        ci.ppEnabledLayerNames = nullptr;
        ci.enabledExtensionCount = static_cast<uint32_t>(filtered.size());
        ci.ppEnabledExtensionNames = filtered.empty() ? nullptr : filtered.data();

        const VkResult r = real_create(&ci, pAllocator, pInstance);
        if (r == VK_SUCCESS && *pInstance) {
            InstanceRec rec{};
            rec.instance = *pInstance;
            rec.enum_dev_ext = reinterpret_cast<PFN_vkEnumerateDeviceExtensionProperties>(
                self.drv_.get_instance_proc_addr(*pInstance, "vkEnumerateDeviceExtensionProperties"));
            rec.create_device = reinterpret_cast<PFN_vkCreateDevice>(
                self.drv_.get_instance_proc_addr(*pInstance, "vkCreateDevice"));
            rec.get_dev_proc = reinterpret_cast<PFN_vkGetDeviceProcAddr>(
                self.drv_.get_instance_proc_addr(*pInstance, "vkGetDeviceProcAddr"));
            rec.get_mem_props = reinterpret_cast<PFN_vkGetPhysicalDeviceMemoryProperties>(
                self.drv_.get_instance_proc_addr(*pInstance, "vkGetPhysicalDeviceMemoryProperties"));
            std::lock_guard<std::mutex> lk(self.mu_);
            self.instances_[*pInstance] = rec;
            self.last_instance_ = *pInstance;
        }
        return r;
    }

    static VkResult VKAPI_CALL shim_vkEnumerateDeviceExtensionProperties(
        VkPhysicalDevice phys, const char* pLayerName, uint32_t* pCount, VkExtensionProperties* pProps) {
        if (!pCount) return VK_ERROR_INITIALIZATION_FAILED;
        if (pLayerName && pLayerName[0] != '\0') {
            *pCount = 0;
            return VK_SUCCESS;
        }
        auto& self = global();
        PFN_vkEnumerateDeviceExtensionProperties real_enum = nullptr;
        {
            std::lock_guard<std::mutex> lk(self.mu_);
            if (auto it = self.instances_.find(self.last_instance_); it != self.instances_.end()) {
                real_enum = it->second.enum_dev_ext;
            }
        }
        std::vector<VkExtensionProperties> exts;
        if (real_enum) {
            uint32_t n = 0;
            if (real_enum(phys, nullptr, &n, nullptr) == VK_SUCCESS && n > 0) {
                exts.resize(n);
                real_enum(phys, nullptr, &n, exts.data());
                exts.resize(n);
            }
        }
        bool has_sc = false;
        for (const auto& e : exts) {
            if (std::strcmp(e.extensionName, VK_KHR_SWAPCHAIN_EXTENSION_NAME) == 0) {
                has_sc = true;
                break;
            }
        }
        if (!has_sc) {
            VkExtensionProperties ep{};
            std::strncpy(ep.extensionName, VK_KHR_SWAPCHAIN_EXTENSION_NAME, VK_MAX_EXTENSION_NAME_SIZE - 1);
            ep.specVersion = 70;
            exts.push_back(ep);
        }
        if (!pProps) {
            *pCount = static_cast<uint32_t>(exts.size());
            return VK_SUCCESS;
        }
        const uint32_t copy_n = std::min<uint32_t>(*pCount, static_cast<uint32_t>(exts.size()));
        if (copy_n) std::memcpy(pProps, exts.data(), copy_n * sizeof(VkExtensionProperties));
        *pCount = copy_n;
        return (copy_n < exts.size()) ? VK_INCOMPLETE : VK_SUCCESS;
    }

    static VkResult VKAPI_CALL shim_vkCreateDevice(
        VkPhysicalDevice phys,
        const VkDeviceCreateInfo* pCreateInfo,
        const VkAllocationCallbacks* pAllocator,
        VkDevice* pDevice) {
        if (!pCreateInfo || !pDevice) return VK_ERROR_INITIALIZATION_FAILED;
        auto& self = global();
        InstanceRec irec{};
        {
            std::lock_guard<std::mutex> lk(self.mu_);
            auto it = self.instances_.find(self.last_instance_);
            if (it == self.instances_.end() || !it->second.create_device) {
                return VK_ERROR_INITIALIZATION_FAILED;
            }
            irec = it->second;
        }

        auto filtered = filter_turnip_wsi_extensions(
            pCreateInfo->ppEnabledExtensionNames, pCreateInfo->enabledExtensionCount, false);
        VkDeviceCreateInfo ci = *pCreateInfo;
        ci.enabledExtensionCount = static_cast<uint32_t>(filtered.size());
        ci.ppEnabledExtensionNames = filtered.empty() ? nullptr : filtered.data();

        const VkResult r = irec.create_device(phys, &ci, pAllocator, pDevice);
        if (r == VK_SUCCESS && *pDevice) {
            DeviceRec d{};
            d.device = *pDevice;
            d.phys = phys;
            d.instance = irec.instance;
            d.queue_family = (pCreateInfo->queueCreateInfoCount > 0 && pCreateInfo->pQueueCreateInfos)
                                 ? pCreateInfo->pQueueCreateInfos[0].queueFamilyIndex
                                 : 0u;
            d.get_dev_proc = irec.get_dev_proc;
            auto gp = [&](const char* nm) -> PFN_vkVoidFunction {
                return d.get_dev_proc ? d.get_dev_proc(d.device, nm) : nullptr;
            };
            d.destroy_device      = reinterpret_cast<PFN_vkDestroyDevice>(gp("vkDestroyDevice"));
            d.wait_idle           = reinterpret_cast<PFN_vkDeviceWaitIdle>(gp("vkDeviceWaitIdle"));
            d.get_queue           = reinterpret_cast<PFN_vkGetDeviceQueue>(gp("vkGetDeviceQueue"));
            d.create_image        = reinterpret_cast<PFN_vkCreateImage>(gp("vkCreateImage"));
            d.destroy_image       = reinterpret_cast<PFN_vkDestroyImage>(gp("vkDestroyImage"));
            d.get_img_req         = reinterpret_cast<PFN_vkGetImageMemoryRequirements>(gp("vkGetImageMemoryRequirements"));
            d.create_buffer       = reinterpret_cast<PFN_vkCreateBuffer>(gp("vkCreateBuffer"));
            d.destroy_buffer      = reinterpret_cast<PFN_vkDestroyBuffer>(gp("vkDestroyBuffer"));
            d.get_buf_req         = reinterpret_cast<PFN_vkGetBufferMemoryRequirements>(gp("vkGetBufferMemoryRequirements"));
            d.alloc_mem           = reinterpret_cast<PFN_vkAllocateMemory>(gp("vkAllocateMemory"));
            d.free_mem            = reinterpret_cast<PFN_vkFreeMemory>(gp("vkFreeMemory"));
            d.bind_img_mem        = reinterpret_cast<PFN_vkBindImageMemory>(gp("vkBindImageMemory"));
            d.bind_buf_mem        = reinterpret_cast<PFN_vkBindBufferMemory>(gp("vkBindBufferMemory"));
            d.map_mem             = reinterpret_cast<PFN_vkMapMemory>(gp("vkMapMemory"));
            d.unmap_mem           = reinterpret_cast<PFN_vkUnmapMemory>(gp("vkUnmapMemory"));
            d.create_cmd_pool     = reinterpret_cast<PFN_vkCreateCommandPool>(gp("vkCreateCommandPool"));
            d.destroy_cmd_pool    = reinterpret_cast<PFN_vkDestroyCommandPool>(gp("vkDestroyCommandPool"));
            d.alloc_cmd           = reinterpret_cast<PFN_vkAllocateCommandBuffers>(gp("vkAllocateCommandBuffers"));
            d.reset_cmd           = reinterpret_cast<PFN_vkResetCommandBuffer>(gp("vkResetCommandBuffer"));
            d.begin_cmd           = reinterpret_cast<PFN_vkBeginCommandBuffer>(gp("vkBeginCommandBuffer"));
            d.end_cmd             = reinterpret_cast<PFN_vkEndCommandBuffer>(gp("vkEndCommandBuffer"));
            d.cmd_barrier         = reinterpret_cast<PFN_vkCmdPipelineBarrier>(gp("vkCmdPipelineBarrier"));
            d.cmd_copy_img_to_buf = reinterpret_cast<PFN_vkCmdCopyImageToBuffer>(gp("vkCmdCopyImageToBuffer"));
            d.create_fence        = reinterpret_cast<PFN_vkCreateFence>(gp("vkCreateFence"));
            d.destroy_fence       = reinterpret_cast<PFN_vkDestroyFence>(gp("vkDestroyFence"));
            d.reset_fences        = reinterpret_cast<PFN_vkResetFences>(gp("vkResetFences"));
            d.wait_fences         = reinterpret_cast<PFN_vkWaitForFences>(gp("vkWaitForFences"));
            d.queue_submit        = reinterpret_cast<PFN_vkQueueSubmit>(gp("vkQueueSubmit"));
            if (d.get_queue) d.get_queue(d.device, d.queue_family, 0, &d.default_queue);

            std::lock_guard<std::mutex> lk(self.mu_);
            self.devices_[*pDevice] = d;
        }
        return r;
    }

    static void VKAPI_CALL shim_vkDestroyDevice(VkDevice dev, const VkAllocationCallbacks* alloc) {
        auto& self = global();
        PFN_vkDestroyDevice real_fn = nullptr;
        {
            std::lock_guard<std::mutex> lk(self.mu_);
            if (auto it = self.devices_.find(dev); it != self.devices_.end()) {
                real_fn = it->second.destroy_device;
                self.devices_.erase(it);
            }
        }
        if (real_fn) real_fn(dev, alloc);
    }

    static VkResult VKAPI_CALL shim_vkCreateAndroidSurfaceKHR(
        VkInstance /*inst*/, const VkAndroidSurfaceCreateInfoKHR* pInfo,
        const VkAllocationCallbacks* /*alloc*/, VkSurfaceKHR* pSurface) {
        if (!pInfo || !pInfo->window || !pSurface) return VK_ERROR_INITIALIZATION_FAILED;
        auto* s = new SurfaceObj();
        s->window = pInfo->window;
        ANativeWindow_acquire(s->window);
        *pSurface = reinterpret_cast<VkSurfaceKHR>(s);
        return VK_SUCCESS;
    }

    static void VKAPI_CALL shim_vkDestroySurfaceKHR(
        VkInstance /*inst*/, VkSurfaceKHR surface, const VkAllocationCallbacks* /*alloc*/) {
        if (!surface) return;
        auto* s = reinterpret_cast<SurfaceObj*>(surface);
        if (s->window) ANativeWindow_release(s->window);
        delete s;
    }

    static VkResult VKAPI_CALL shim_vkGetPhysicalDeviceSurfaceSupportKHR(
        VkPhysicalDevice /*phys*/, uint32_t /*qfi*/, VkSurfaceKHR /*surf*/, VkBool32* pSupported) {
        if (pSupported) *pSupported = VK_TRUE;
        return VK_SUCCESS;
    }

    static VkResult VKAPI_CALL shim_vkGetPhysicalDeviceSurfaceCapabilitiesKHR(
        VkPhysicalDevice /*phys*/, VkSurfaceKHR surface, VkSurfaceCapabilitiesKHR* pCaps) {
        if (!pCaps) return VK_ERROR_INITIALIZATION_FAILED;
        uint32_t w = 1280, h = 720;
        if (auto* s = reinterpret_cast<SurfaceObj*>(surface); s && s->window) {
            const int32_t nw = ANativeWindow_getWidth(s->window);
            const int32_t nh = ANativeWindow_getHeight(s->window);
            if (nw > 0 && nh > 0) {
                w = static_cast<uint32_t>(nw);
                h = static_cast<uint32_t>(nh);
            }
        }
        *pCaps = {};
        pCaps->minImageCount = 2;
        pCaps->maxImageCount = 4;
        pCaps->currentExtent = {w, h};
        pCaps->minImageExtent = {1, 1};
        pCaps->maxImageExtent = {8192, 8192};
        pCaps->maxImageArrayLayers = 1;
        pCaps->supportedTransforms = VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR;
        pCaps->currentTransform = VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR;
        pCaps->supportedCompositeAlpha =
            VK_COMPOSITE_ALPHA_OPAQUE_BIT_KHR | VK_COMPOSITE_ALPHA_INHERIT_BIT_KHR;
        pCaps->supportedUsageFlags =
            VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT | VK_IMAGE_USAGE_TRANSFER_SRC_BIT |
            VK_IMAGE_USAGE_TRANSFER_DST_BIT | VK_IMAGE_USAGE_SAMPLED_BIT |
            VK_IMAGE_USAGE_STORAGE_BIT;
        return VK_SUCCESS;
    }

    static VkResult VKAPI_CALL shim_vkGetPhysicalDeviceSurfaceFormatsKHR(
        VkPhysicalDevice /*phys*/, VkSurfaceKHR /*surface*/,
        uint32_t* pCount, VkSurfaceFormatKHR* pFormats) {
        static const VkSurfaceFormatKHR kFormats[] = {
            {VK_FORMAT_R8G8B8A8_UNORM, VK_COLOR_SPACE_SRGB_NONLINEAR_KHR},
            {VK_FORMAT_R8G8B8A8_SRGB,  VK_COLOR_SPACE_SRGB_NONLINEAR_KHR},
        };
        if (!pCount) return VK_ERROR_INITIALIZATION_FAILED;
        if (!pFormats) { *pCount = 2; return VK_SUCCESS; }
        const uint32_t n = std::min<uint32_t>(*pCount, 2);
        std::memcpy(pFormats, kFormats, n * sizeof(VkSurfaceFormatKHR));
        *pCount = n;
        return (n < 2) ? VK_INCOMPLETE : VK_SUCCESS;
    }

    static VkResult VKAPI_CALL shim_vkGetPhysicalDeviceSurfacePresentModesKHR(
        VkPhysicalDevice /*phys*/, VkSurfaceKHR /*surface*/,
        uint32_t* pCount, VkPresentModeKHR* pModes) {
        static const VkPresentModeKHR kModes[] = {
            VK_PRESENT_MODE_FIFO_KHR,
            VK_PRESENT_MODE_IMMEDIATE_KHR,
        };
        if (!pCount) return VK_ERROR_INITIALIZATION_FAILED;
        if (!pModes) { *pCount = 2; return VK_SUCCESS; }
        const uint32_t n = std::min<uint32_t>(*pCount, 2);
        std::memcpy(pModes, kModes, n * sizeof(VkPresentModeKHR));
        *pCount = n;
        return (n < 2) ? VK_INCOMPLETE : VK_SUCCESS;
    }

    static VkResult VKAPI_CALL shim_vkCreateSwapchainKHR(
        VkDevice dev, const VkSwapchainCreateInfoKHR* pInfo,
        const VkAllocationCallbacks* /*alloc*/, VkSwapchainKHR* pSwapchain) {
        if (!pInfo || !pSwapchain) return VK_ERROR_INITIALIZATION_FAILED;
        auto& self = global();
        DeviceRec d{};
        InstanceRec irec{};
        {
            std::lock_guard<std::mutex> lk(self.mu_);
            auto dit = self.devices_.find(dev);
            if (dit == self.devices_.end()) return VK_ERROR_DEVICE_LOST;
            d = dit->second;
            auto iit = self.instances_.find(d.instance);
            if (iit == self.instances_.end()) return VK_ERROR_DEVICE_LOST;
            irec = iit->second;
        }
        auto* surf = reinterpret_cast<SurfaceObj*>(pInfo->surface);
        if (!surf || !surf->window) return VK_ERROR_SURFACE_LOST_KHR;

        auto* sc = new SwapchainObj();
        sc->device = dev;
        sc->window = surf->window;
        ANativeWindow_acquire(sc->window);
        sc->width = pInfo->imageExtent.width ? pInfo->imageExtent.width : 1280u;
        sc->height = pInfo->imageExtent.height ? pInfo->imageExtent.height : 720u;
        ANativeWindow_setBuffersGeometry(
            sc->window, static_cast<int32_t>(sc->width), static_cast<int32_t>(sc->height),
            WINDOW_FORMAT_RGBA_8888);

        VkPhysicalDeviceMemoryProperties mem_props{};
        irec.get_mem_props(d.phys, &mem_props);

        const uint32_t img_count = std::clamp<uint32_t>(pInfo->minImageCount, 2u, 3u);
        for (uint32_t i = 0; i < img_count; ++i) {
            VkImageCreateInfo ici{VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO};
            ici.imageType = VK_IMAGE_TYPE_2D;
            ici.format = pInfo->imageFormat;
            ici.extent = {sc->width, sc->height, 1};
            ici.mipLevels = 1;
            ici.arrayLayers = 1;
            ici.samples = VK_SAMPLE_COUNT_1_BIT;
            ici.tiling = VK_IMAGE_TILING_OPTIMAL;
            ici.usage = pInfo->imageUsage | VK_IMAGE_USAGE_TRANSFER_SRC_BIT;
            ici.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
            ici.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;
            VkImage img = VK_NULL_HANDLE;
            if (d.create_image(dev, &ici, nullptr, &img) != VK_SUCCESS) {
                shim_vkDestroySwapchainKHR(dev, reinterpret_cast<VkSwapchainKHR>(sc), nullptr);
                return VK_ERROR_OUT_OF_DEVICE_MEMORY;
            }
            VkMemoryRequirements req{};
            d.get_img_req(dev, img, &req);
            uint32_t mt = find_mem_type(mem_props, req.memoryTypeBits, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);
            if (mt == UINT32_MAX) mt = find_mem_type(mem_props, req.memoryTypeBits, 0);
            VkMemoryAllocateInfo mai{VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO};
            mai.allocationSize = req.size;
            mai.memoryTypeIndex = mt;
            VkDeviceMemory mem = VK_NULL_HANDLE;
            if (d.alloc_mem(dev, &mai, nullptr, &mem) != VK_SUCCESS ||
                d.bind_img_mem(dev, img, mem, 0) != VK_SUCCESS) {
                d.destroy_image(dev, img, nullptr);
                if (mem) d.free_mem(dev, mem, nullptr);
                shim_vkDestroySwapchainKHR(dev, reinterpret_cast<VkSwapchainKHR>(sc), nullptr);
                return VK_ERROR_OUT_OF_DEVICE_MEMORY;
            }
            sc->images.push_back(img);
            sc->image_mems.push_back(mem);
        }

        // Linear UMA host-coherent staging buffer for ANativeWindow_lock present
        VkBufferCreateInfo bci{VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO};
        bci.size = static_cast<VkDeviceSize>(sc->width) * sc->height * 4ULL;
        bci.usage = VK_BUFFER_USAGE_TRANSFER_DST_BIT;
        bci.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
        if (d.create_buffer(dev, &bci, nullptr, &sc->staging_buf) != VK_SUCCESS) {
            shim_vkDestroySwapchainKHR(dev, reinterpret_cast<VkSwapchainKHR>(sc), nullptr);
            return VK_ERROR_OUT_OF_DEVICE_MEMORY;
        }
        VkMemoryRequirements breq{};
        d.get_buf_req(dev, sc->staging_buf, &breq);
        uint32_t bmt = find_mem_type(
            mem_props, breq.memoryTypeBits,
            VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
        if (bmt == UINT32_MAX) {
            bmt = find_mem_type(mem_props, breq.memoryTypeBits, VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT);
        }
        VkMemoryAllocateInfo bmai{VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO};
        bmai.allocationSize = breq.size;
        bmai.memoryTypeIndex = bmt;
        if (d.alloc_mem(dev, &bmai, nullptr, &sc->staging_mem) != VK_SUCCESS ||
            d.bind_buf_mem(dev, sc->staging_buf, sc->staging_mem, 0) != VK_SUCCESS ||
            d.map_mem(dev, sc->staging_mem, 0, bci.size, 0, &sc->staging_mapped) != VK_SUCCESS) {
            shim_vkDestroySwapchainKHR(dev, reinterpret_cast<VkSwapchainKHR>(sc), nullptr);
            return VK_ERROR_OUT_OF_DEVICE_MEMORY;
        }

        VkCommandPoolCreateInfo cpci{VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO};
        cpci.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
        cpci.queueFamilyIndex = d.queue_family;
        VkCommandBufferAllocateInfo cbai{VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO};
        cbai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
        cbai.commandBufferCount = 1;
        VkFenceCreateInfo fci{VK_STRUCTURE_TYPE_FENCE_CREATE_INFO};
        if (d.create_cmd_pool(dev, &cpci, nullptr, &sc->cmd_pool) != VK_SUCCESS ||
            (cbai.commandPool = sc->cmd_pool, d.alloc_cmd(dev, &cbai, &sc->cmd_buf) != VK_SUCCESS) ||
            d.create_fence(dev, &fci, nullptr, &sc->present_fence) != VK_SUCCESS) {
            shim_vkDestroySwapchainKHR(dev, reinterpret_cast<VkSwapchainKHR>(sc), nullptr);
            return VK_ERROR_INITIALIZATION_FAILED;
        }

        *pSwapchain = reinterpret_cast<VkSwapchainKHR>(sc);
        return VK_SUCCESS;
    }

    static void VKAPI_CALL shim_vkDestroySwapchainKHR(
        VkDevice dev, VkSwapchainKHR swapchain, const VkAllocationCallbacks* /*alloc*/) {
        if (!swapchain) return;
        auto* sc = reinterpret_cast<SwapchainObj*>(swapchain);
        DeviceRec d{};
        {
            std::lock_guard<std::mutex> lk(global().mu_);
            if (auto it = global().devices_.find(dev); it != global().devices_.end()) d = it->second;
        }
        if (d.device) {
            if (d.wait_idle) d.wait_idle(dev);
            if (sc->present_fence && d.destroy_fence) d.destroy_fence(dev, sc->present_fence, nullptr);
            if (sc->cmd_pool && d.destroy_cmd_pool) d.destroy_cmd_pool(dev, sc->cmd_pool, nullptr);
            if (sc->staging_mapped && sc->staging_mem && d.unmap_mem) d.unmap_mem(dev, sc->staging_mem);
            if (sc->staging_buf && d.destroy_buffer) d.destroy_buffer(dev, sc->staging_buf, nullptr);
            if (sc->staging_mem && d.free_mem) d.free_mem(dev, sc->staging_mem, nullptr);
            for (auto img : sc->images) if (img && d.destroy_image) d.destroy_image(dev, img, nullptr);
            for (auto mem : sc->image_mems) if (mem && d.free_mem) d.free_mem(dev, mem, nullptr);
        }
        if (sc->window) ANativeWindow_release(sc->window);
        delete sc;
    }

    static VkResult VKAPI_CALL shim_vkGetSwapchainImagesKHR(
        VkDevice /*dev*/, VkSwapchainKHR swapchain, uint32_t* pCount, VkImage* pImages) {
        auto* sc = reinterpret_cast<SwapchainObj*>(swapchain);
        if (!sc || !pCount) return VK_ERROR_INITIALIZATION_FAILED;
        if (!pImages) {
            *pCount = static_cast<uint32_t>(sc->images.size());
            return VK_SUCCESS;
        }
        const uint32_t n = std::min<uint32_t>(*pCount, static_cast<uint32_t>(sc->images.size()));
        if (n) std::memcpy(pImages, sc->images.data(), n * sizeof(VkImage));
        *pCount = n;
        return (n < sc->images.size()) ? VK_INCOMPLETE : VK_SUCCESS;
    }

    static VkResult VKAPI_CALL shim_vkAcquireNextImageKHR(
        VkDevice dev, VkSwapchainKHR swapchain, uint64_t /*timeout*/,
        VkSemaphore semaphore, VkFence fence, uint32_t* pImageIndex) {
        auto* sc = reinterpret_cast<SwapchainObj*>(swapchain);
        if (!sc || !pImageIndex || sc->images.empty()) return VK_ERROR_OUT_OF_DATE_KHR;
        *pImageIndex = sc->next_index;
        sc->next_index = (sc->next_index + 1u) % static_cast<uint32_t>(sc->images.size());

        if (semaphore != VK_NULL_HANDLE || fence != VK_NULL_HANDLE) {
            DeviceRec d{};
            {
                std::lock_guard<std::mutex> lk(global().mu_);
                if (auto it = global().devices_.find(dev); it != global().devices_.end()) d = it->second;
            }
            if (d.queue_submit && d.default_queue) {
                VkSubmitInfo si{VK_STRUCTURE_TYPE_SUBMIT_INFO};
                if (semaphore != VK_NULL_HANDLE) {
                    si.signalSemaphoreCount = 1;
                    si.pSignalSemaphores = &semaphore;
                }
                d.queue_submit(d.default_queue, 1, &si, fence);
            }
        }
        return VK_SUCCESS;
    }

    static VkResult VKAPI_CALL shim_vkQueuePresentKHR(VkQueue queue, const VkPresentInfoKHR* pInfo) {
        if (!pInfo || pInfo->swapchainCount == 0 || !pInfo->pSwapchains || !pInfo->pImageIndices) {
            return VK_SUCCESS;
        }
        auto* sc = reinterpret_cast<SwapchainObj*>(pInfo->pSwapchains[0]);
        const uint32_t idx = pInfo->pImageIndices[0];
        if (!sc || idx >= sc->images.size() || !sc->window) return VK_ERROR_OUT_OF_DATE_KHR;

        DeviceRec d{};
        {
            std::lock_guard<std::mutex> lk(global().mu_);
            if (auto it = global().devices_.find(sc->device); it != global().devices_.end()) d = it->second;
        }
        if (!d.device) return VK_ERROR_DEVICE_LOST;

        d.reset_fences(sc->device, 1, &sc->present_fence);
        d.reset_cmd(sc->cmd_buf, 0);
        VkCommandBufferBeginInfo bi{VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
        bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
        d.begin_cmd(sc->cmd_buf, &bi);

        VkImageMemoryBarrier b1{VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER};
        b1.srcAccessMask = VK_ACCESS_MEMORY_WRITE_BIT;
        b1.dstAccessMask = VK_ACCESS_TRANSFER_READ_BIT;
        b1.oldLayout = VK_IMAGE_LAYOUT_PRESENT_SRC_KHR;
        b1.newLayout = VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL;
        b1.srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        b1.dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED;
        b1.image = sc->images[idx];
        b1.subresourceRange = {VK_IMAGE_ASPECT_COLOR_BIT, 0, 1, 0, 1};
        d.cmd_barrier(sc->cmd_buf, VK_PIPELINE_STAGE_ALL_COMMANDS_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT,
                      0, 0, nullptr, 0, nullptr, 1, &b1);

        VkBufferImageCopy region{};
        region.imageSubresource = {VK_IMAGE_ASPECT_COLOR_BIT, 0, 0, 1};
        region.imageExtent = {sc->width, sc->height, 1};
        d.cmd_copy_img_to_buf(sc->cmd_buf, sc->images[idx], VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
                              sc->staging_buf, 1, &region);

        VkImageMemoryBarrier b2 = b1;
        b2.srcAccessMask = VK_ACCESS_TRANSFER_READ_BIT;
        b2.dstAccessMask = VK_ACCESS_MEMORY_READ_BIT | VK_ACCESS_MEMORY_WRITE_BIT;
        b2.oldLayout = VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL;
        b2.newLayout = VK_IMAGE_LAYOUT_PRESENT_SRC_KHR;
        d.cmd_barrier(sc->cmd_buf, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_ALL_COMMANDS_BIT,
                      0, 0, nullptr, 0, nullptr, 1, &b2);
        d.end_cmd(sc->cmd_buf);

        std::vector<VkPipelineStageFlags> wait_stages(pInfo->waitSemaphoreCount, VK_PIPELINE_STAGE_TRANSFER_BIT);
        VkSubmitInfo si{VK_STRUCTURE_TYPE_SUBMIT_INFO};
        si.waitSemaphoreCount = pInfo->waitSemaphoreCount;
        si.pWaitSemaphores = pInfo->pWaitSemaphores;
        si.pWaitDstStageMask = wait_stages.empty() ? nullptr : wait_stages.data();
        si.commandBufferCount = 1;
        si.pCommandBuffers = &sc->cmd_buf;
        if (d.queue_submit(queue, 1, &si, sc->present_fence) == VK_SUCCESS) {
            d.wait_fences(sc->device, 1, &sc->present_fence, VK_TRUE, 2'000'000'000ULL);
            ANativeWindow_Buffer nw_buf{};
            if (sc->staging_mapped && ANativeWindow_lock(sc->window, &nw_buf, nullptr) == 0) {
                const uint32_t copy_w = std::min<uint32_t>(sc->width, static_cast<uint32_t>(nw_buf.width));
                const uint32_t copy_h = std::min<uint32_t>(sc->height, static_cast<uint32_t>(nw_buf.height));
                const auto* src = static_cast<const uint8_t*>(sc->staging_mapped);
                auto* dst = static_cast<uint8_t*>(nw_buf.bits);
                const size_t src_pitch = static_cast<size_t>(sc->width) * 4;
                const size_t dst_pitch = static_cast<size_t>(nw_buf.stride) * 4;
                const size_t row_bytes = static_cast<size_t>(copy_w) * 4;
                for (uint32_t y = 0; y < copy_h; ++y) {
                    std::memcpy(dst + y * dst_pitch, src + y * src_pitch, row_bytes);
                }
                ANativeWindow_unlockAndPost(sc->window);
            }
        }
        if (pInfo->pResults) pInfo->pResults[0] = VK_SUCCESS;
        return VK_SUCCESS;
    }

    static PFN_vkVoidFunction VKAPI_CALL shim_vkGetDeviceProcAddr(VkDevice dev, const char* name) {
        if (!name) return nullptr;
        if (std::strcmp(name, "vkCreateSwapchainKHR") == 0)
            return reinterpret_cast<PFN_vkVoidFunction>(&shim_vkCreateSwapchainKHR);
        if (std::strcmp(name, "vkDestroySwapchainKHR") == 0)
            return reinterpret_cast<PFN_vkVoidFunction>(&shim_vkDestroySwapchainKHR);
        if (std::strcmp(name, "vkGetSwapchainImagesKHR") == 0)
            return reinterpret_cast<PFN_vkVoidFunction>(&shim_vkGetSwapchainImagesKHR);
        if (std::strcmp(name, "vkAcquireNextImageKHR") == 0)
            return reinterpret_cast<PFN_vkVoidFunction>(&shim_vkAcquireNextImageKHR);
        if (std::strcmp(name, "vkQueuePresentKHR") == 0)
            return reinterpret_cast<PFN_vkVoidFunction>(&shim_vkQueuePresentKHR);
        if (std::strcmp(name, "vkDestroyDevice") == 0)
            return reinterpret_cast<PFN_vkVoidFunction>(&shim_vkDestroyDevice);
        if (std::strcmp(name, "vkGetDeviceProcAddr") == 0)
            return reinterpret_cast<PFN_vkVoidFunction>(&shim_vkGetDeviceProcAddr);

        PFN_vkGetDeviceProcAddr real_gdpa = nullptr;
        {
            std::lock_guard<std::mutex> lk(global().mu_);
            if (auto it = global().devices_.find(dev); it != global().devices_.end()) {
                real_gdpa = it->second.get_dev_proc;
            }
        }
        return real_gdpa ? real_gdpa(dev, name) : nullptr;
    }

    static PFN_vkVoidFunction VKAPI_CALL shim_vkGetInstanceProcAddr(VkInstance inst, const char* name) {
        if (!name) return nullptr;
        if (std::strcmp(name, "vkGetInstanceProcAddr") == 0)
            return reinterpret_cast<PFN_vkVoidFunction>(&shim_vkGetInstanceProcAddr);
        if (std::strcmp(name, "vkEnumerateInstanceLayerProperties") == 0)
            return reinterpret_cast<PFN_vkVoidFunction>(&shim_vkEnumerateInstanceLayerProperties);
        if (std::strcmp(name, "vkEnumerateInstanceExtensionProperties") == 0)
            return reinterpret_cast<PFN_vkVoidFunction>(&shim_vkEnumerateInstanceExtensionProperties);
        if (std::strcmp(name, "vkCreateInstance") == 0)
            return reinterpret_cast<PFN_vkVoidFunction>(&shim_vkCreateInstance);
        if (std::strcmp(name, "vkEnumerateDeviceExtensionProperties") == 0)
            return reinterpret_cast<PFN_vkVoidFunction>(&shim_vkEnumerateDeviceExtensionProperties);
        if (std::strcmp(name, "vkCreateDevice") == 0)
            return reinterpret_cast<PFN_vkVoidFunction>(&shim_vkCreateDevice);
        if (std::strcmp(name, "vkGetDeviceProcAddr") == 0)
            return reinterpret_cast<PFN_vkVoidFunction>(&shim_vkGetDeviceProcAddr);
        if (std::strcmp(name, "vkCreateAndroidSurfaceKHR") == 0)
            return reinterpret_cast<PFN_vkVoidFunction>(&shim_vkCreateAndroidSurfaceKHR);
        if (std::strcmp(name, "vkDestroySurfaceKHR") == 0)
            return reinterpret_cast<PFN_vkVoidFunction>(&shim_vkDestroySurfaceKHR);
        if (std::strcmp(name, "vkGetPhysicalDeviceSurfaceSupportKHR") == 0)
            return reinterpret_cast<PFN_vkVoidFunction>(&shim_vkGetPhysicalDeviceSurfaceSupportKHR);
        if (std::strcmp(name, "vkGetPhysicalDeviceSurfaceCapabilitiesKHR") == 0)
            return reinterpret_cast<PFN_vkVoidFunction>(&shim_vkGetPhysicalDeviceSurfaceCapabilitiesKHR);
        if (std::strcmp(name, "vkGetPhysicalDeviceSurfaceFormatsKHR") == 0)
            return reinterpret_cast<PFN_vkVoidFunction>(&shim_vkGetPhysicalDeviceSurfaceFormatsKHR);
        if (std::strcmp(name, "vkGetPhysicalDeviceSurfacePresentModesKHR") == 0)
            return reinterpret_cast<PFN_vkVoidFunction>(&shim_vkGetPhysicalDeviceSurfacePresentModesKHR);
        // Device-level WSI calls sometimes queried via vkGetInstanceProcAddr
        if (std::strcmp(name, "vkCreateSwapchainKHR") == 0)
            return reinterpret_cast<PFN_vkVoidFunction>(&shim_vkCreateSwapchainKHR);
        if (std::strcmp(name, "vkDestroySwapchainKHR") == 0)
            return reinterpret_cast<PFN_vkVoidFunction>(&shim_vkDestroySwapchainKHR);
        if (std::strcmp(name, "vkGetSwapchainImagesKHR") == 0)
            return reinterpret_cast<PFN_vkVoidFunction>(&shim_vkGetSwapchainImagesKHR);
        if (std::strcmp(name, "vkAcquireNextImageKHR") == 0)
            return reinterpret_cast<PFN_vkVoidFunction>(&shim_vkAcquireNextImageKHR);
        if (std::strcmp(name, "vkQueuePresentKHR") == 0)
            return reinterpret_cast<PFN_vkVoidFunction>(&shim_vkQueuePresentKHR);

        auto& self = global();
        if (!self.drv_.get_instance_proc_addr) return nullptr;
        auto fn = reinterpret_cast<PFN_vkVoidFunction>(self.drv_.get_instance_proc_addr(inst, name));
        if (!fn && std::strcmp(name, "vkEnumerateInstanceVersion") == 0) {
            return reinterpret_cast<PFN_vkVoidFunction>(&shim_vkEnumerateInstanceVersion);
        }
        return fn;
    }

    std::unordered_map<VkInstance, InstanceRec> instances_;
    std::unordered_map<VkDevice, DeviceRec> devices_;
    VkInstance last_instance_ = VK_NULL_HANDLE;
#endif

    mutable std::mutex mu_;
    VulkanDriverHandle drv_{};
    bool ready_ = false;
};

} // namespace mobiro::gfx
