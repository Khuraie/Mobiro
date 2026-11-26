#pragma once

#include "../input/touch_controller.hpp"
#include "turnip_loader.hpp"

#include <algorithm>
#include <atomic>
#include <cstdint>
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

// Converts TouchController's normalized screen quads into a host-coherent Vulkan vertex stream
// ready for single-draw in-swapchain compositing (no Android View hierarchy or extra SurfaceView).
// shortcut: SPIR-V pipeline creation attaches once native libdxvk_dxgi.so swapchain hook is bundled.
class TouchOverlayVk {
public:
    void set_enabled(bool enabled) { enabled_.store(enabled, std::memory_order_relaxed); }
    bool enabled() const { return enabled_.load(std::memory_order_relaxed); }

    void attach_vulkan_loader(PfnGetInstanceProcAddr gipa) { get_instance_proc_addr_ = gipa; }
    bool has_vulkan_loader() const { return get_instance_proc_addr_ != nullptr; }

    // Packs normalized [0..1] screen quads into Vulkan NDC triangles (6 vertices per quad).
    size_t pack_quads(const std::vector<input::HudQuad>& quads) {
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

private:
    std::atomic<bool> enabled_{true};
    PfnGetInstanceProcAddr get_instance_proc_addr_ = nullptr;
    std::vector<HudVertex> vertices_;
};

} // namespace mobiro::gfx
