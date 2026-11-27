#if defined(DXVK_WSI_ANDROID)

#include "wsi_platform_android.h"

#include "../../util/log/log.h"

#include <android/native_window.h>
#include <dlfcn.h>
#include <vulkan/vulkan_android.h>

#include <cstring>
#include <string>

namespace dxvk::wsi {

  static constexpr uint32_t AndroidMonitorId = 1;

  static void* resolveMobiroSym(const char* name) {
    if (void* s = dlsym(RTLD_DEFAULT, name))
      return s;
    static void* h = dlopen("libsekiro_runtime.so", RTLD_NOW | RTLD_NOLOAD);
    return h ? dlsym(h, name) : nullptr;
  }

  // Resolves the live ANativeWindow* exported by libsekiro_runtime.so first so swapchain
  // creation stays valid across Android pause/resume, falling back to hWindow as ANativeWindow*.
  static ANativeWindow* resolveAndroidWindow(HWND hWindow) {
    using PfnGetWin = void* (*)();
    static auto pfn = reinterpret_cast<PfnGetWin>(
        resolveMobiroSym("mobiro_get_android_native_window"));
    if (pfn) {
      if (auto* w = static_cast<ANativeWindow*>(pfn()))
        return w;
    }
    return reinterpret_cast<ANativeWindow*>(hWindow);
  }

  static void getAndroidMode(WsiMode* pMode) {
    uint32_t w = 1920;
    uint32_t h = 1080;
    if (ANativeWindow* win = resolveAndroidWindow(nullptr)) {
      const int32_t nw = ANativeWindow_getWidth(win);
      const int32_t nh = ANativeWindow_getHeight(win);
      if (nw > 0 && nh > 0) {
        w = static_cast<uint32_t>(nw);
        h = static_cast<uint32_t>(nh);
      }
    }
    pMode->width        = w;
    pMode->height       = h;
    pMode->refreshRate  = WsiRational{ 60000, 1000 };
    pMode->bitsPerPixel = 32;
    pMode->interlaced   = false;
  }

  static bool isAndroidMonitor(HMONITOR hMonitor) {
    return reinterpret_cast<uintptr_t>(hMonitor) == AndroidMonitorId;
  }

  std::vector<const char*> AndroidWsiDriver::getInstanceExtensions() {
    static const char* candidates[] = {
      VK_KHR_SURFACE_EXTENSION_NAME,
      VK_KHR_ANDROID_SURFACE_EXTENSION_NAME,
    };

    Rc<vk::LibraryFn> vkl = new vk::LibraryFn();
    std::vector<VkExtensionProperties> available;

    if (vkl->vkEnumerateInstanceExtensionProperties) {
      uint32_t count = 0;
      vkl->vkEnumerateInstanceExtensionProperties(nullptr, &count, nullptr);
      available.resize(count);
      vkl->vkEnumerateInstanceExtensionProperties(nullptr, &count, available.data());
    }

    std::vector<const char*> result;
    for (const char* name : candidates) {
      for (const auto& ext : available) {
        if (!std::strcmp(ext.extensionName, name)) {
          result.push_back(name);
          break;
        }
      }
    }
    if (result.empty()) {
      result.push_back(VK_KHR_SURFACE_EXTENSION_NAME);
      result.push_back(VK_KHR_ANDROID_SURFACE_EXTENSION_NAME);
    }
    return result;
  }

  HMONITOR AndroidWsiDriver::getDefaultMonitor() {
    return enumMonitors(0);
  }

  HMONITOR AndroidWsiDriver::enumMonitors(uint32_t index) {
    return index == 0
      ? reinterpret_cast<HMONITOR>(uintptr_t(AndroidMonitorId))
      : nullptr;
  }

  HMONITOR AndroidWsiDriver::enumMonitors(const LUID* /*adapterLUID*/[], uint32_t /*numLUIDs*/, uint32_t index) {
    return enumMonitors(index);
  }

  bool AndroidWsiDriver::getDisplayName(HMONITOR hMonitor, WCHAR (&Name)[32]) {
    if (!isAndroidMonitor(hMonitor))
      return false;
    std::wstring name = LR"(\\.\DISPLAY1)";
    std::memset(Name, 0, sizeof(Name));
    name.copy(Name, name.length(), 0);
    return true;
  }

  bool AndroidWsiDriver::getDesktopCoordinates(HMONITOR hMonitor, RECT* pRect) {
    if (!isAndroidMonitor(hMonitor) || !pRect)
      return false;
    WsiMode mode{};
    getAndroidMode(&mode);
    pRect->left   = 0;
    pRect->top    = 0;
    pRect->right  = LONG(mode.width);
    pRect->bottom = LONG(mode.height);
    return true;
  }

  bool AndroidWsiDriver::getDisplayMode(HMONITOR hMonitor, uint32_t modeNumber, WsiMode* pMode) {
    if (!isAndroidMonitor(hMonitor) || modeNumber != 0 || !pMode)
      return false;
    getAndroidMode(pMode);
    return true;
  }

  bool AndroidWsiDriver::getCurrentDisplayMode(HMONITOR hMonitor, WsiMode* pMode) {
    return getDisplayMode(hMonitor, 0, pMode);
  }

  bool AndroidWsiDriver::getDesktopDisplayMode(HMONITOR hMonitor, WsiMode* pMode) {
    return getDisplayMode(hMonitor, 0, pMode);
  }

  WsiEdidData AndroidWsiDriver::getMonitorEdid(HMONITOR /*hMonitor*/) {
    return {};
  }

  void AndroidWsiDriver::getWindowSize(HWND hWindow, uint32_t* pWidth, uint32_t* pHeight) {
    uint32_t w = 1920;
    uint32_t h = 1080;
    if (ANativeWindow* win = resolveAndroidWindow(hWindow)) {
      const int32_t nw = ANativeWindow_getWidth(win);
      const int32_t nh = ANativeWindow_getHeight(win);
      if (nw > 0 && nh > 0) {
        w = static_cast<uint32_t>(nw);
        h = static_cast<uint32_t>(nh);
      }
    }
    if (pWidth)  *pWidth  = w;
    if (pHeight) *pHeight = h;
  }

  void AndroidWsiDriver::resizeWindow(HWND, DxvkWindowState*, uint32_t, uint32_t) {}
  void AndroidWsiDriver::saveWindowState(HWND, DxvkWindowState*, bool) {}
  void AndroidWsiDriver::restoreWindowState(HWND, DxvkWindowState*, bool) {}

  bool AndroidWsiDriver::setWindowMode(HMONITOR, HWND, DxvkWindowState*, const WsiMode&) {
    return true;
  }

  bool AndroidWsiDriver::enterFullscreenMode(HMONITOR, HWND, DxvkWindowState*, bool) {
    return true;
  }

  bool AndroidWsiDriver::leaveFullscreenMode(HWND, DxvkWindowState*) {
    return true;
  }

  bool AndroidWsiDriver::restoreDisplayMode() {
    return true;
  }

  HMONITOR AndroidWsiDriver::getWindowMonitor(HWND) {
    return getDefaultMonitor();
  }

  bool AndroidWsiDriver::isWindow(HWND hWindow) {
    return resolveAndroidWindow(hWindow) != nullptr;
  }

  bool AndroidWsiDriver::isMinimized(HWND hWindow) {
    return resolveAndroidWindow(hWindow) == nullptr;
  }

  bool AndroidWsiDriver::isOccluded(HWND) {
    return false;
  }

  void AndroidWsiDriver::updateFullscreenWindow(HMONITOR, HWND, bool) {}

  VkResult AndroidWsiDriver::createSurface(
      HWND hWindow,
      PFN_vkGetInstanceProcAddr pfnVkGetInstanceProcAddr,
      VkInstance instance,
      VkSurfaceKHR* pSurface) {
    ANativeWindow* window = resolveAndroidWindow(hWindow);
    if (!window) {
      Logger::err("Android WSI: ANativeWindow is null");
      return VK_ERROR_INITIALIZATION_FAILED;
    }

    auto pfnCreateSurface = reinterpret_cast<PFN_vkCreateAndroidSurfaceKHR>(
        pfnVkGetInstanceProcAddr(instance, "vkCreateAndroidSurfaceKHR"));
    if (!pfnCreateSurface) {
      Logger::err("Android WSI: vkCreateAndroidSurfaceKHR not available");
      return VK_ERROR_EXTENSION_NOT_PRESENT;
    }

    VkAndroidSurfaceCreateInfoKHR info = {};
    info.sType  = VK_STRUCTURE_TYPE_ANDROID_SURFACE_CREATE_INFO_KHR;
    info.pNext  = nullptr;
    info.flags  = 0;
    info.window = window;
    return pfnCreateSurface(instance, &info, nullptr, pSurface);
  }

  static bool createAndroidWsiDriver(WsiDriver** driver) {
    *driver = new AndroidWsiDriver();
    return true;
  }

  WsiBootstrap AndroidWSI = {
    "Android",
    createAndroidWsiDriver
  };

}

#endif
