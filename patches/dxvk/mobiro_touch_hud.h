#pragma once

#include "dxvk_cmdlist.h"
#include "dxvk_device.h"
#include "dxvk_image.h"

namespace dxvk {

  // Lightweight in-swapchain Vulkan overlay hook for Mobiro's TouchOverlayVk.
  // Resolves mobiro_touch_overlay_* dynamically via dlsym(RTLD_DEFAULT) so DXVK
  // retains zero link-time dependency on libsekiro_runtime.so.
  class MobiroTouchHud {
  public:
    MobiroTouchHud() = default;
    ~MobiroTouchHud();

    MobiroTouchHud(const MobiroTouchHud&) = delete;
    MobiroTouchHud& operator=(const MobiroTouchHud&) = delete;

    void render(
      const Rc<DxvkDevice>&      device,
      const Rc<DxvkCommandList>& ctx,
      const Rc<DxvkImageView>&   dstView);

  private:
    bool ensureResources(const Rc<DxvkDevice>& device, VkFormat colorFormat);
    void destroyResources();

    Rc<DxvkDevice>   m_device;
    VkFormat         m_colorFormat   = VK_FORMAT_UNDEFINED;
    VkPipelineLayout m_pipelineLayout = VK_NULL_HANDLE;
    VkPipeline       m_pipeline      = VK_NULL_HANDLE;
    VkBuffer         m_vbo           = VK_NULL_HANDLE;
    VkDeviceMemory   m_vboMemory     = VK_NULL_HANDLE;
    void*            m_mappedVbo     = nullptr;
    bool             m_unavailable   = false;
  };

} // namespace dxvk
