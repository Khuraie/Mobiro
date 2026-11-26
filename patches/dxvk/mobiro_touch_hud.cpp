#include "mobiro_touch_hud.h"

#if defined(DXVK_WSI_ANDROID)
#include <dlfcn.h>
#include <cstddef>
#include <cstdint>
#endif

namespace dxvk {

  namespace {

    constexpr VkDeviceSize kMobiroHudVboBytes = 64u * 1024u;

    struct MobiroVertexInputAttrSpec {
      uint32_t location;
      uint32_t binding;
      uint32_t vk_format;
      uint32_t offset;
    };

    struct MobiroHudPipelineSpec {
      const uint32_t*           vert_spv;
      size_t                    vert_spv_bytes;
      const uint32_t*           frag_spv;
      size_t                    frag_spv_bytes;
      uint32_t                  vertex_stride;
      MobiroVertexInputAttrSpec attrs[2];
    };

    using PfnGetSpec      = const MobiroHudPipelineSpec* (*)();
    using PfnCopyVertices = size_t (*)(void* dst_vbo, size_t max_bytes);

#if defined(DXVK_WSI_ANDROID)
    uint32_t findHostCoherentMemType(
      const VkPhysicalDeviceMemoryProperties& props,
            uint32_t                          typeBits) {
      const VkMemoryPropertyFlags want =
        VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;
      for (uint32_t i = 0; i < props.memoryTypeCount; ++i) {
        if ((typeBits & (1u << i)) && (props.memoryTypes[i].propertyFlags & want) == want)
          return i;
      }
      return UINT32_MAX;
    }
#endif

  } // namespace

  MobiroTouchHud::~MobiroTouchHud() {
    destroyResources();
  }

  void MobiroTouchHud::destroyResources() {
    if (!m_device)
      return;
    auto vkd = m_device->vkd();
    if (m_mappedVbo && m_vboMemory) {
      vkd->vkUnmapMemory(vkd->device(), m_vboMemory);
      m_mappedVbo = nullptr;
    }
    if (m_pipeline) {
      vkd->vkDestroyPipeline(vkd->device(), m_pipeline, nullptr);
      m_pipeline = VK_NULL_HANDLE;
    }
    if (m_pipelineLayout) {
      vkd->vkDestroyPipelineLayout(vkd->device(), m_pipelineLayout, nullptr);
      m_pipelineLayout = VK_NULL_HANDLE;
    }
    if (m_vbo) {
      vkd->vkDestroyBuffer(vkd->device(), m_vbo, nullptr);
      m_vbo = VK_NULL_HANDLE;
    }
    if (m_vboMemory) {
      vkd->vkFreeMemory(vkd->device(), m_vboMemory, nullptr);
      m_vboMemory = VK_NULL_HANDLE;
    }
    m_colorFormat = VK_FORMAT_UNDEFINED;
    m_device = nullptr;
  }

  bool MobiroTouchHud::ensureResources(const Rc<DxvkDevice>& device, VkFormat colorFormat) {
#if !defined(DXVK_WSI_ANDROID)
    (void)device;
    (void)colorFormat;
    return false;
#else
    if (m_unavailable)
      return false;
    if (m_pipeline && m_device == device && m_colorFormat == colorFormat)
      return true;

    destroyResources();

    static auto pfnGetSpec = reinterpret_cast<PfnGetSpec>(
      dlsym(RTLD_DEFAULT, "mobiro_touch_overlay_pipeline_spec"));
    if (!pfnGetSpec) {
      m_unavailable = true;
      return false;
    }

    const MobiroHudPipelineSpec* spec = pfnGetSpec();
    if (!spec || !spec->vert_spv || !spec->frag_spv) {
      m_unavailable = true;
      return false;
    }

    m_device = device;
    auto vkd = device->vkd();

    // 1. Host-coherent vertex buffer for single-draw touch HUD quads
    VkBufferCreateInfo bufInfo = { VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO };
    bufInfo.size        = kMobiroHudVboBytes;
    bufInfo.usage       = VK_BUFFER_USAGE_VERTEX_BUFFER_BIT;
    bufInfo.sharingMode = VK_SHARING_MODE_EXCLUSIVE;
    if (vkd->vkCreateBuffer(vkd->device(), &bufInfo, nullptr, &m_vbo) != VK_SUCCESS) {
      destroyResources();
      m_unavailable = true;
      return false;
    }

    VkMemoryRequirements req = {};
    vkd->vkGetBufferMemoryRequirements(vkd->device(), m_vbo, &req);
    const uint32_t memType = findHostCoherentMemType(
      device->adapter()->memoryProperties(), req.memoryTypeBits);
    if (memType == UINT32_MAX) {
      destroyResources();
      m_unavailable = true;
      return false;
    }

    VkMemoryAllocateInfo allocInfo = { VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO };
    allocInfo.allocationSize  = req.size;
    allocInfo.memoryTypeIndex = memType;
    if (vkd->vkAllocateMemory(vkd->device(), &allocInfo, nullptr, &m_vboMemory) != VK_SUCCESS ||
        vkd->vkBindBufferMemory(vkd->device(), m_vbo, m_vboMemory, 0) != VK_SUCCESS ||
        vkd->vkMapMemory(vkd->device(), m_vboMemory, 0, kMobiroHudVboBytes, 0, &m_mappedVbo) != VK_SUCCESS) {
      destroyResources();
      m_unavailable = true;
      return false;
    }

    // 2. Shader modules from Mobiro's validated Vulkan 1.0 SPIR-V
    VkShaderModuleCreateInfo vsInfo = { VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO };
    vsInfo.codeSize = spec->vert_spv_bytes;
    vsInfo.pCode    = spec->vert_spv;
    VkShaderModule vsMod = VK_NULL_HANDLE;

    VkShaderModuleCreateInfo fsInfo = { VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO };
    fsInfo.codeSize = spec->frag_spv_bytes;
    fsInfo.pCode    = spec->frag_spv;
    VkShaderModule fsMod = VK_NULL_HANDLE;

    if (vkd->vkCreateShaderModule(vkd->device(), &vsInfo, nullptr, &vsMod) != VK_SUCCESS ||
        vkd->vkCreateShaderModule(vkd->device(), &fsInfo, nullptr, &fsMod) != VK_SUCCESS) {
      if (vsMod) vkd->vkDestroyShaderModule(vkd->device(), vsMod, nullptr);
      if (fsMod) vkd->vkDestroyShaderModule(vkd->device(), fsMod, nullptr);
      destroyResources();
      m_unavailable = true;
      return false;
    }

    VkPipelineLayoutCreateInfo plInfo = { VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO };
    if (vkd->vkCreatePipelineLayout(vkd->device(), &plInfo, nullptr, &m_pipelineLayout) != VK_SUCCESS) {
      vkd->vkDestroyShaderModule(vkd->device(), vsMod, nullptr);
      vkd->vkDestroyShaderModule(vkd->device(), fsMod, nullptr);
      destroyResources();
      m_unavailable = true;
      return false;
    }

    VkPipelineShaderStageCreateInfo stages[2] = {};
    stages[0].sType  = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stages[0].stage  = VK_SHADER_STAGE_VERTEX_BIT;
    stages[0].module = vsMod;
    stages[0].pName  = "main";
    stages[1].sType  = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stages[1].stage  = VK_SHADER_STAGE_FRAGMENT_BIT;
    stages[1].module = fsMod;
    stages[1].pName  = "main";

    VkVertexInputBindingDescription vtxBind = {};
    vtxBind.binding   = 0;
    vtxBind.stride    = spec->vertex_stride;
    vtxBind.inputRate = VK_VERTEX_INPUT_RATE_VERTEX;

    VkVertexInputAttributeDescription vtxAttrs[2] = {};
    for (int i = 0; i < 2; ++i) {
      vtxAttrs[i].location = spec->attrs[i].location;
      vtxAttrs[i].binding  = spec->attrs[i].binding;
      vtxAttrs[i].format   = static_cast<VkFormat>(spec->attrs[i].vk_format);
      vtxAttrs[i].offset   = spec->attrs[i].offset;
    }

    VkPipelineVertexInputStateCreateInfo viState = { VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO };
    viState.vertexBindingDescriptionCount   = 1;
    viState.pVertexBindingDescriptions      = &vtxBind;
    viState.vertexAttributeDescriptionCount = 2;
    viState.pVertexAttributeDescriptions    = vtxAttrs;

    VkPipelineInputAssemblyStateCreateInfo iaState = { VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO };
    iaState.topology = VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST;

    VkPipelineViewportStateCreateInfo vpState = { VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO };
    vpState.viewportCount = 0;
    vpState.scissorCount  = 0;

    VkPipelineRasterizationStateCreateInfo rsState = { VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO };
    rsState.polygonMode = VK_POLYGON_MODE_FILL;
    rsState.cullMode    = VK_CULL_MODE_NONE;
    rsState.frontFace   = VK_FRONT_FACE_CLOCKWISE;
    rsState.lineWidth   = 1.0f;

    VkPipelineMultisampleStateCreateInfo msState = { VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO };
    msState.rasterizationSamples = VK_SAMPLE_COUNT_1_BIT;

    VkPipelineColorBlendAttachmentState cbAtt = {};
    cbAtt.blendEnable         = VK_TRUE;
    cbAtt.srcColorBlendFactor = VK_BLEND_FACTOR_SRC_ALPHA;
    cbAtt.dstColorBlendFactor = VK_BLEND_FACTOR_ONE_MINUS_SRC_ALPHA;
    cbAtt.colorBlendOp        = VK_BLEND_OP_ADD;
    cbAtt.srcAlphaBlendFactor = VK_BLEND_FACTOR_ONE;
    cbAtt.dstAlphaBlendFactor = VK_BLEND_FACTOR_ONE_MINUS_SRC_ALPHA;
    cbAtt.alphaBlendOp        = VK_BLEND_OP_ADD;
    cbAtt.colorWriteMask      = VK_COLOR_COMPONENT_R_BIT | VK_COLOR_COMPONENT_G_BIT |
                                VK_COLOR_COMPONENT_B_BIT | VK_COLOR_COMPONENT_A_BIT;

    VkPipelineColorBlendStateCreateInfo cbState = { VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO };
    cbState.attachmentCount = 1;
    cbState.pAttachments    = &cbAtt;

    static const VkDynamicState dynStates[2] = {
      VK_DYNAMIC_STATE_VIEWPORT_WITH_COUNT,
      VK_DYNAMIC_STATE_SCISSOR_WITH_COUNT
    };
    VkPipelineDynamicStateCreateInfo dynState = { VK_STRUCTURE_TYPE_PIPELINE_DYNAMIC_STATE_CREATE_INFO };
    dynState.dynamicStateCount = 2;
    dynState.pDynamicStates    = dynStates;

    VkPipelineRenderingCreateInfo rendInfo = { VK_STRUCTURE_TYPE_PIPELINE_RENDERING_CREATE_INFO };
    rendInfo.colorAttachmentCount    = 1;
    rendInfo.pColorAttachmentFormats = &colorFormat;

    VkGraphicsPipelineCreateInfo gpInfo = { VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO };
    gpInfo.pNext               = &rendInfo;
    gpInfo.stageCount          = 2;
    gpInfo.pStages             = stages;
    gpInfo.pVertexInputState   = &viState;
    gpInfo.pInputAssemblyState = &iaState;
    gpInfo.pViewportState      = &vpState;
    gpInfo.pRasterizationState = &rsState;
    gpInfo.pMultisampleState   = &msState;
    gpInfo.pColorBlendState    = &cbState;
    gpInfo.pDynamicState       = &dynState;
    gpInfo.layout              = m_pipelineLayout;

    const VkResult vr = vkd->vkCreateGraphicsPipelines(
      vkd->device(), VK_NULL_HANDLE, 1, &gpInfo, nullptr, &m_pipeline);
    vkd->vkDestroyShaderModule(vkd->device(), vsMod, nullptr);
    vkd->vkDestroyShaderModule(vkd->device(), fsMod, nullptr);

    if (vr != VK_SUCCESS) {
      destroyResources();
      m_unavailable = true;
      return false;
    }

    m_colorFormat = colorFormat;
    return true;
#endif
  }

  void MobiroTouchHud::render(
    const Rc<DxvkDevice>&      device,
    const Rc<DxvkCommandList>& ctx,
    const Rc<DxvkImageView>&   dstView) {
#if !defined(DXVK_WSI_ANDROID)
    (void)device;
    (void)ctx;
    (void)dstView;
#else
    if (!device || !ctx || !dstView)
      return;
    if (!ensureResources(device, dstView->info().format))
      return;

    static auto pfnCopy = reinterpret_cast<PfnCopyVertices>(
      dlsym(RTLD_DEFAULT, "mobiro_touch_overlay_copy_vertices"));
    if (!pfnCopy)
      return;

    const size_t vtxCount = pfnCopy(m_mappedVbo, static_cast<size_t>(kMobiroHudVboBytes));
    if (vtxCount == 0)
      return;

    const VkExtent3D ext = dstView->mipLevelExtent(0);
    VkViewport vp = { 0.0f, 0.0f, float(ext.width), float(ext.height), 0.0f, 1.0f };
    VkRect2D   sc = { { 0, 0 }, { ext.width, ext.height } };
    VkDeviceSize offset = 0;
    VkDeviceSize vboSz  = kMobiroHudVboBytes;

    ctx->cmdSetViewport(1, &vp);
    ctx->cmdSetScissor(1, &sc);
    ctx->cmdBindPipeline(DxvkCmdBuffer::ExecBuffer, VK_PIPELINE_BIND_POINT_GRAPHICS, m_pipeline);
    ctx->cmdBindVertexBuffers(0, 1, &m_vbo, &offset, &vboSz, nullptr);
    ctx->cmdDraw(static_cast<uint32_t>(vtxCount), 1, 0, 0);
#endif
  }

} // namespace dxvk
