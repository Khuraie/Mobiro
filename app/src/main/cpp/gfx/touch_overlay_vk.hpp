#pragma once

#include "../input/touch_controller.hpp"
#include "turnip_loader.hpp"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <vector>

namespace mobiro::gfx {

// Flat 2D colored vertex in Vulkan NDC space ([-1..+1], top-left origin) for single-draw-call HUD pass.
struct HudVertex {
    float x = 0.0f;
    float y = 0.0f;
    float r = 1.0f;
    float g = 1.0f;
    float b = 1.0f;
    float a = 1.0f;
};
static_assert(sizeof(HudVertex) == 24, "HudVertex must be tightly packed (24 bytes)");

namespace spirv {

constexpr uint32_t kMagic = 0x07230203u;
constexpr uint32_t kVersion10 = 0x00010000u;
constexpr uint32_t op(uint16_t words, uint16_t opcode) {
    return (static_cast<uint32_t>(words) << 16) | static_cast<uint32_t>(opcode);
}

// Pre-assembled Vulkan 1.0 SPIR-V vertex shader:
//   layout(location=0) in vec2 inPos; layout(location=1) in vec4 inColor;
//   layout(location=0) out vec4 outColor;
//   void main() { gl_Position = vec4(inPos, 0.0, 1.0); outColor = inColor; }
inline constexpr uint32_t kHudVertSpv[] = {
    kMagic, kVersion10, 0u, 27u, 0u,
    op(2, 17), 1u,                                               // OpCapability Shader
    op(3, 14), 0u, 1u,                                           // OpMemoryModel Logical GLSL450
    op(9, 15), 0u, 19u, 0x6E69616Du, 0u, 15u, 16u, 17u, 18u,     // OpEntryPoint Vertex %19 "main" %15..%18
    op(5, 72), 6u, 0u, 11u, 0u,                                  // OpMemberDecorate %6 0 BuiltIn Position
    op(3, 71), 6u, 2u,                                           // OpDecorate %6 Block
    op(4, 71), 16u, 30u, 0u,                                     // OpDecorate %16 Location 0
    op(4, 71), 17u, 30u, 1u,                                     // OpDecorate %17 Location 1
    op(4, 71), 18u, 30u, 0u,                                     // OpDecorate %18 Location 0
    op(2, 19), 1u,                                               // %1 = OpTypeVoid
    op(3, 33), 2u, 1u,                                           // %2 = OpTypeFunction %1
    op(3, 22), 3u, 32u,                                          // %3 = OpTypeFloat 32
    op(4, 23), 4u, 3u, 2u,                                       // %4 = OpTypeVector %3 2
    op(4, 23), 5u, 3u, 4u,                                       // %5 = OpTypeVector %3 4
    op(3, 30), 6u, 5u,                                           // %6 = OpTypeStruct %5 (gl_PerVertex)
    op(4, 32), 7u, 3u, 6u,                                       // %7 = OpTypePointer Output %6
    op(4, 32), 8u, 3u, 5u,                                       // %8 = OpTypePointer Output %5
    op(4, 32), 9u, 1u, 4u,                                       // %9 = OpTypePointer Input %4
    op(4, 32), 10u, 1u, 5u,                                      // %10 = OpTypePointer Input %5
    op(4, 21), 11u, 32u, 1u,                                     // %11 = OpTypeInt 32 1
    op(4, 43), 11u, 12u, 0u,                                     // %12 = OpConstant %11 0
    op(4, 43), 3u, 13u, 0x00000000u,                             // %13 = OpConstant %3 0.0
    op(4, 43), 3u, 14u, 0x3F800000u,                             // %14 = OpConstant %3 1.0
    op(4, 59), 7u, 15u, 3u,                                      // %15 = OpVariable %7 Output
    op(4, 59), 9u, 16u, 1u,                                      // %16 = OpVariable %9 Input
    op(4, 59), 10u, 17u, 1u,                                     // %17 = OpVariable %10 Input
    op(4, 59), 8u, 18u, 3u,                                      // %18 = OpVariable %8 Output
    op(5, 54), 1u, 19u, 0u, 2u,                                  // %19 = OpFunction %1 None %2
    op(2, 248), 20u,                                             // %20 = OpLabel
    op(4, 61), 4u, 21u, 16u,                                     // %21 = OpLoad %4 %16
    op(5, 81), 3u, 22u, 21u, 0u,                                 // %22 = OpCompositeExtract %3 %21 0
    op(5, 81), 3u, 23u, 21u, 1u,                                 // %23 = OpCompositeExtract %3 %21 1
    op(7, 80), 5u, 24u, 22u, 23u, 13u, 14u,                      // %24 = OpCompositeConstruct %5 %22 %23 0.0 1.0
    op(5, 65), 8u, 25u, 15u, 12u,                                // %25 = OpAccessChain %8 %15 %12
    op(3, 62), 25u, 24u,                                         // OpStore %25 %24
    op(4, 61), 5u, 26u, 17u,                                     // %26 = OpLoad %5 %17
    op(3, 62), 18u, 26u,                                         // OpStore %18 %26
    op(1, 253),                                                  // OpReturn
    op(1, 56)                                                    // OpFunctionEnd
};

// Pre-assembled Vulkan 1.0 SPIR-V fragment shader:
//   layout(location=0) in vec4 inColor; layout(location=0) out vec4 outFragColor;
//   void main() { outFragColor = inColor; }
inline constexpr uint32_t kHudFragSpv[] = {
    kMagic, kVersion10, 0u, 12u, 0u,
    op(2, 17), 1u,                                               // OpCapability Shader
    op(3, 14), 0u, 1u,                                           // OpMemoryModel Logical GLSL450
    op(7, 15), 4u, 9u, 0x6E69616Du, 0u, 7u, 8u,                  // OpEntryPoint Fragment %9 "main" %7 %8
    op(3, 16), 9u, 7u,                                           // OpExecutionMode %9 OriginUpperLeft
    op(4, 71), 7u, 30u, 0u,                                      // OpDecorate %7 Location 0
    op(4, 71), 8u, 30u, 0u,                                      // OpDecorate %8 Location 0
    op(2, 19), 1u,                                               // %1 = OpTypeVoid
    op(3, 33), 2u, 1u,                                           // %2 = OpTypeFunction %1
    op(3, 22), 3u, 32u,                                          // %3 = OpTypeFloat 32
    op(4, 23), 4u, 3u, 4u,                                       // %4 = OpTypeVector %3 4
    op(4, 32), 5u, 1u, 4u,                                       // %5 = OpTypePointer Input %4
    op(4, 32), 6u, 3u, 4u,                                       // %6 = OpTypePointer Output %4
    op(4, 59), 5u, 7u, 1u,                                       // %7 = OpVariable %5 Input
    op(4, 59), 6u, 8u, 3u,                                       // %8 = OpVariable %6 Output
    op(5, 54), 1u, 9u, 0u, 2u,                                   // %9 = OpFunction %1 None %2
    op(2, 248), 10u,                                             // %10 = OpLabel
    op(4, 61), 4u, 11u, 7u,                                      // %11 = OpLoad %4 %7
    op(3, 62), 8u, 11u,                                          // OpStore %8 %11
    op(1, 253),                                                  // OpReturn
    op(1, 56)                                                    // OpFunctionEnd
};

inline bool validate_module(const uint32_t* words, size_t count) {
    if (!words || count < 6) return false;
    if (words[0] != kMagic || words[3] == 0) return false;
    bool has_entry = false;
    bool has_fn_end = false;
    size_t i = 5;
    while (i < count) {
        const uint32_t wcount = words[i] >> 16;
        const uint32_t opcode = words[i] & 0xFFFFu;
        if (wcount == 0 || i + wcount > count) return false;
        if (opcode == 15u) has_entry = true;
        if (opcode == 56u) has_fn_end = true;
        i += wcount;
    }
    return (i == count) && has_entry && has_fn_end;
}

} // namespace spirv

// Converts TouchController's normalized screen quads into a host-coherent Vulkan vertex stream
// with embedded Vulkan 1.0 SPIR-V shaders ready for single-draw in-swapchain compositing.
class TouchOverlayVk {
public:
    void set_enabled(bool enabled) { enabled_.store(enabled, std::memory_order_relaxed); }
    bool enabled() const { return enabled_.load(std::memory_order_relaxed); }

    void attach_vulkan_loader(PfnGetInstanceProcAddr gipa) { get_instance_proc_addr_ = gipa; }
    bool has_vulkan_loader() const { return get_instance_proc_addr_ != nullptr; }

    // Packs normalized [0..1] screen quads into Vulkan NDC triangles (6 vertices per quad).
    size_t pack_quads(const std::vector<input::HudQuad>& quads) {
        std::lock_guard<std::mutex> lk(mu_);
        vertices_.clear();
        if (!enabled() || quads.empty()) return 0;

        vertices_.reserve(quads.size() * 6);
        for (const auto& q : quads) {
            const float x0 = std::clamp(q.x0 * 2.0f - 1.0f, -1.0f, 1.0f);
            const float y0 = std::clamp(q.y0 * 2.0f - 1.0f, -1.0f, 1.0f);
            const float x1 = std::clamp(q.x1 * 2.0f - 1.0f, -1.0f, 1.0f);
            const float y1 = std::clamp(q.y1 * 2.0f - 1.0f, -1.0f, 1.0f);
            const float r  = std::clamp(q.r, 0.0f, 1.0f);
            const float g  = std::clamp(q.g, 0.0f, 1.0f);
            const float b  = std::clamp(q.b, 0.0f, 1.0f);
            const float a  = std::clamp(q.a, 0.0f, 1.0f);

            // Triangle 1 (TL, BL, BR)
            vertices_.push_back({x0, y0, r, g, b, a});
            vertices_.push_back({x0, y1, r, g, b, a});
            vertices_.push_back({x1, y1, r, g, b, a});
            // Triangle 2 (TL, BR, TR)
            vertices_.push_back({x0, y0, r, g, b, a});
            vertices_.push_back({x1, y1, r, g, b, a});
            vertices_.push_back({x1, y0, r, g, b, a});
        }
        return vertices_.size();
    }

    const std::vector<HudVertex>& vertices() const { return vertices_; }
    size_t vertex_bytes() const { return vertices_.size() * sizeof(HudVertex); }

    // Dynamic Vulkan draw-pass hook (zero compile-time LunarG SDK header dependency).
    // Bound once native DXVK swapchain command buffer + pipeline handles are attached.
    using PfnVkCmdBindPipeline = void (*)(void* cmd, uint32_t bind_point, uint64_t pipeline);
    using PfnVkCmdBindVertexBuffers = void (*)(void* cmd, uint32_t first, uint32_t count,
                                               const uint64_t* buffers, const uint64_t* offsets);
    using PfnVkCmdDraw = void (*)(void* cmd, uint32_t vtx_count, uint32_t inst_count,
                                  uint32_t first_vtx, uint32_t first_inst);
    using PfnGetDeviceProcAddr = void* (*)(void* device, const char* name);

    struct VertexInputAttrSpec {
        uint32_t location;
        uint32_t binding;
        uint32_t vk_format; // VK_FORMAT_R32G32_SFLOAT=103, VK_FORMAT_R32G32B32A32_SFLOAT=109
        uint32_t offset;
    };

    struct HudPipelineSpec {
        const uint32_t* vert_spv = spirv::kHudVertSpv;
        size_t vert_spv_bytes = sizeof(spirv::kHudVertSpv);
        const uint32_t* frag_spv = spirv::kHudFragSpv;
        size_t frag_spv_bytes = sizeof(spirv::kHudFragSpv);
        uint32_t vertex_stride = sizeof(HudVertex);
        VertexInputAttrSpec attrs[2] = {
            {0u, 0u, 103u, offsetof(HudVertex, x)},
            {1u, 0u, 109u, offsetof(HudVertex, r)}
        };
    };

    static HudPipelineSpec pipeline_spec() { return HudPipelineSpec{}; }

    struct VkDrawBindings {
        uint64_t pipeline = 0;
        uint64_t vertex_buffer = 0;
        void* mapped_vbo = nullptr;
        size_t mapped_capacity_bytes = 0;
        PfnVkCmdBindPipeline cmd_bind_pipeline = nullptr;
        PfnVkCmdBindVertexBuffers cmd_bind_vbo = nullptr;
        PfnVkCmdDraw cmd_draw = nullptr;
    };

    // Dynamically resolves vkCmdBindPipeline / vkCmdBindVertexBuffers / vkCmdDraw from a live VkDevice
    bool resolve_device_draw_procs(void* vk_device, PfnGetDeviceProcAddr gdpa) {
        if (!vk_device || !gdpa) return false;
        std::lock_guard<std::mutex> lk(mu_);
        bindings_.cmd_bind_pipeline = reinterpret_cast<PfnVkCmdBindPipeline>(gdpa(vk_device, "vkCmdBindPipeline"));
        bindings_.cmd_bind_vbo = reinterpret_cast<PfnVkCmdBindVertexBuffers>(gdpa(vk_device, "vkCmdBindVertexBuffers"));
        bindings_.cmd_draw = reinterpret_cast<PfnVkCmdDraw>(gdpa(vk_device, "vkCmdDraw"));
        return bindings_.cmd_bind_pipeline && bindings_.cmd_bind_vbo && bindings_.cmd_draw;
    }

    void attach_draw_bindings(const VkDrawBindings& b) {
        std::lock_guard<std::mutex> lk(mu_);
        bindings_ = b;
    }

    // Thread-safe copy of packed NDC vertices into a caller-mapped VBO; returns vertex count (0 if hidden/empty).
    size_t copy_vertices(void* dst_vbo, size_t max_bytes) const {
        if (!dst_vbo || !enabled()) return 0;
        std::lock_guard<std::mutex> lk(mu_);
        if (vertices_.empty()) return 0;
        const size_t bytes = vertices_.size() * sizeof(HudVertex);
        if (bytes > max_bytes) return 0;
        std::memcpy(dst_vbo, vertices_.data(), bytes);
        return vertices_.size();
    }

    // Uploads packed HUD vertices into the mapped host-coherent VBO and records a single vkCmdDraw.
    bool record_draw_commands(void* vk_cmd_buffer) const {
        if (!vk_cmd_buffer || !enabled()) return false;
        std::lock_guard<std::mutex> lk(mu_);
        if (vertices_.empty()) return false;
        if (!bindings_.pipeline || !bindings_.vertex_buffer || !bindings_.mapped_vbo ||
            !bindings_.cmd_bind_pipeline || !bindings_.cmd_bind_vbo || !bindings_.cmd_draw) {
            return false;
        }
        const size_t bytes = vertices_.size() * sizeof(HudVertex);
        if (bytes > bindings_.mapped_capacity_bytes) return false;

        std::memcpy(bindings_.mapped_vbo, vertices_.data(), bytes);
        const uint64_t offset = 0;
        bindings_.cmd_bind_pipeline(vk_cmd_buffer, /*VK_PIPELINE_BIND_POINT_GRAPHICS=*/0u, bindings_.pipeline);
        bindings_.cmd_bind_vbo(vk_cmd_buffer, 0u, 1u, &bindings_.vertex_buffer, &offset);
        bindings_.cmd_draw(vk_cmd_buffer, static_cast<uint32_t>(vertices_.size()), 1u, 0u, 0u);
        return true;
    }

private:
    mutable std::mutex mu_;
    std::atomic<bool> enabled_{true};
    PfnGetInstanceProcAddr get_instance_proc_addr_ = nullptr;
    std::vector<HudVertex> vertices_;
    VkDrawBindings bindings_{};
};

} // namespace mobiro::gfx
