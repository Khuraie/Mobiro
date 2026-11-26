#pragma once

#include "input_router.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <vector>

namespace mobiro::input {

enum class TouchAction : uint8_t { Down = 0, Move = 1, Up = 2, Cancel = 3 };

struct VirtualButtonDef {
    const char* label = "";
    float cx = 0.0f;       // Normalized [0..1] screen X
    float cy = 0.0f;       // Normalized [0..1] screen Y
    float radius = 0.055f; // Normalized hit radius (in Y-scaled screen units)
    uint16_t button_mask = 0; // XInputButton bitmask (0 if trigger)
    bool is_left_trigger = false;
    bool is_right_trigger = false;
};

// Flat quad ready for single-draw-call in-swapchain Vulkan overlay rendering
struct HudQuad {
    float x0 = 0, y0 = 0, x1 = 0, y1 = 0;
    float r = 1, g = 1, b = 1, a = 0.35f;
};

// Zero-debounce multi-touch controller translating Android touchscreen pointers directly
// into InputRouter's lock-free XInput state for Sekiro combat pacing.
class TouchController {
public:
    static constexpr size_t kMaxButtons = 13;

    TouchController() { reset_default_sekiro_layout(); }

    void set_viewport(float width, float height) {
        vw_ = (width > 1.0f) ? width : 1920.0f;
        vh_ = (height > 1.0f) ? height : 1080.0f;
    }

    void reset_default_sekiro_layout() {
        // Ergonomic landscape combat layout prioritizing instant L1 Deflect, R1 Attack & Healing Gourd (D-Pad Up)
        buttons_ = {{
            {"L1",  0.86f, 0.44f, 0.068f, kLeftShoulder,  false, false}, // Deflect / Guard
            {"R1",  0.76f, 0.58f, 0.068f, kRightShoulder, false, false}, // Attack
            {"B",   0.88f, 0.68f, 0.060f, kButtonB,       false, false}, // Dodge / Mikiri
            {"A",   0.78f, 0.80f, 0.055f, kButtonA,       false, false}, // Jump
            {"X",   0.66f, 0.72f, 0.050f, kButtonX,       false, false}, // Interact
            {"Y",   0.66f, 0.54f, 0.050f, kButtonY,       false, false}, // Cycle Prosthetic
            {"L2",  0.14f, 0.30f, 0.058f, 0,              true,  false}, // Grapple
            {"R2",  0.86f, 0.26f, 0.058f, 0,              false, true},  // Prosthetic Tool
            {"R3",  0.64f, 0.36f, 0.048f, kRightThumb,    false, false}, // Lock-On
            {"MNU", 0.50f, 0.08f, 0.045f, kStart,         false, false}, // Pause / Menu
            {"UP",  0.25f, 0.22f, 0.052f, kDpadUp,        false, false}, // Use Quick Item / Healing Gourd
            {"DN",  0.25f, 0.36f, 0.046f, kDpadDown,      false, false}, // Cycle Quick Item
            {"L3",  0.14f, 0.48f, 0.048f, kLeftThumb,     false, false}, // Crouch / Stealth
        }};
        release_all();
    }

    void on_pointer(int32_t pointer_id, TouchAction action, float px, float py, InputRouter& router) {
        const float nx = std::clamp(px / vw_, 0.0f, 1.0f);
        const float ny = std::clamp(py / vh_, 0.0f, 1.0f);

        if (action == TouchAction::Cancel) {
            release_all_and_sync(router);
            return;
        }

        if (action == TouchAction::Down) {
            // 1. Check virtual buttons first (zero-debounce edge press)
            int btn = hit_test_button(nx, ny);
            if (btn >= 0) {
                button_pointer_[btn] = pointer_id;
                apply_button(btn, true, router);
                return;
            }
            // 2. Left half -> floating movement thumbstick
            if (nx < 0.48f && left_stick_ptr_ == -1) {
                left_stick_ptr_ = pointer_id;
                left_origin_x_ = nx;
                left_origin_y_ = ny;
                left_curr_x_ = nx;
                left_curr_y_ = ny;
                router.set_left_stick(0.0f, 0.0f);
                return;
            }
            // 3. Right half -> relative camera look
            if (nx >= 0.48f && right_look_ptr_ == -1) {
                right_look_ptr_ = pointer_id;
                right_prev_x_ = nx;
                right_prev_y_ = ny;
                router.set_right_stick(0.0f, 0.0f);
            }
            return;
        }

        if (action == TouchAction::Move) {
            if (pointer_id == left_stick_ptr_) {
                left_curr_x_ = nx;
                left_curr_y_ = ny;
                const float aspect = vw_ / vh_;
                const float dx = ((nx - left_origin_x_) * aspect) / kStickMaxRadius;
                const float dy = -((ny - left_origin_y_)) / kStickMaxRadius; // Up is +Y in XInput
                router.set_left_stick(std::clamp(dx, -1.0f, 1.0f), std::clamp(dy, -1.0f, 1.0f));
            } else if (pointer_id == right_look_ptr_) {
                const float dx = (nx - right_prev_x_) * kCameraSensitivity;
                const float dy = -(ny - right_prev_y_) * kCameraSensitivity;
                right_prev_x_ = nx;
                right_prev_y_ = ny;
                router.set_right_stick(std::clamp(dx, -1.0f, 1.0f), std::clamp(dy, -1.0f, 1.0f), 0.02f);
            }
            return;
        }

        // TouchAction::Up
        for (size_t i = 0; i < kMaxButtons; ++i) {
            if (button_pointer_[i] == pointer_id) {
                button_pointer_[i] = -1;
                apply_button(static_cast<int>(i), false, router);
            }
        }
        if (pointer_id == left_stick_ptr_) {
            left_stick_ptr_ = -1;
            router.set_left_stick(0.0f, 0.0f);
        }
        if (pointer_id == right_look_ptr_) {
            right_look_ptr_ = -1;
            router.set_right_stick(0.0f, 0.0f);
        }
    }

    // Call once per frame if no Move arrived for camera pointer so right stick returns to rest
    void decay_camera_look(InputRouter& router) {
        if (right_look_ptr_ != -1) {
            router.set_right_stick(0.0f, 0.0f);
        }
    }

    // Emits screen-space HUD quads for in-swapchain Vulkan rendering
    std::vector<HudQuad> build_hud_quads() const {
        std::vector<HudQuad> quads;
        quads.reserve(kMaxButtons + 2);
        const float inv_aspect = vh_ / vw_;

        for (size_t i = 0; i < kMaxButtons; ++i) {
            const auto& b = buttons_[i];
            const bool active = (button_pointer_[i] != -1);
            const float rx = b.radius * inv_aspect;
            const float ry = b.radius;
            quads.push_back({
                b.cx - rx, b.cy - ry, b.cx + rx, b.cy + ry,
                active ? 1.0f : 0.85f,
                active ? 0.65f : 0.85f,
                active ? 0.15f : 0.85f,
                active ? 0.70f : 0.28f
            });
        }
        if (left_stick_ptr_ != -1) {
            const float rx = kStickMaxRadius * inv_aspect;
            const float ry = kStickMaxRadius;
            quads.push_back({left_origin_x_ - rx, left_origin_y_ - ry,
                             left_origin_x_ + rx, left_origin_y_ + ry, 0.8f, 0.8f, 0.8f, 0.20f});
            const float krx = 0.035f * inv_aspect;
            const float kry = 0.035f;
            quads.push_back({left_curr_x_ - krx, left_curr_y_ - kry,
                             left_curr_x_ + krx, left_curr_y_ + kry, 1.0f, 0.9f, 0.5f, 0.65f});
        }
        return quads;
    }

private:
    int hit_test_button(float nx, float ny) const {
        const float aspect = vw_ / vh_;
        for (size_t i = 0; i < kMaxButtons; ++i) {
            const auto& b = buttons_[i];
            const float dx = (nx - b.cx) * aspect;
            const float dy = (ny - b.cy);
            if ((dx * dx + dy * dy) <= (b.radius * b.radius)) {
                return static_cast<int>(i);
            }
        }
        return -1;
    }

    void apply_button(int idx, bool pressed, InputRouter& router) {
        const auto& b = buttons_[idx];
        if (b.button_mask != 0) {
            router.set_button(b.button_mask, pressed);
        } else if (b.is_left_trigger || b.is_right_trigger) {
            if (b.is_left_trigger)  lt_pressed_ = pressed;
            if (b.is_right_trigger) rt_pressed_ = pressed;
            router.set_triggers(lt_pressed_ ? 1.0f : 0.0f, rt_pressed_ ? 1.0f : 0.0f);
        }
    }

    void release_all() {
        button_pointer_.fill(-1);
        left_stick_ptr_ = -1;
        right_look_ptr_ = -1;
        lt_pressed_ = false;
        rt_pressed_ = false;
    }

    void release_all_and_sync(InputRouter& router) {
        for (size_t i = 0; i < kMaxButtons; ++i) {
            if (button_pointer_[i] != -1) {
                button_pointer_[i] = -1;
                apply_button(static_cast<int>(i), false, router);
            }
        }
        left_stick_ptr_ = -1;
        right_look_ptr_ = -1;
        router.set_left_stick(0.0f, 0.0f);
        router.set_right_stick(0.0f, 0.0f);
        router.set_triggers(0.0f, 0.0f);
    }

    static constexpr float kStickMaxRadius = 0.14f;
    static constexpr float kCameraSensitivity = 14.0f;

    float vw_ = 1920.0f;
    float vh_ = 1080.0f;
    std::array<VirtualButtonDef, kMaxButtons> buttons_{};
    std::array<int32_t, kMaxButtons> button_pointer_{};
    int32_t left_stick_ptr_ = -1;
    float left_origin_x_ = 0.0f, left_origin_y_ = 0.0f;
    float left_curr_x_ = 0.0f, left_curr_y_ = 0.0f;
    int32_t right_look_ptr_ = -1;
    float right_prev_x_ = 0.0f, right_prev_y_ = 0.0f;
    bool lt_pressed_ = false;
    bool rt_pressed_ = false;
};

} // namespace mobiro::input
