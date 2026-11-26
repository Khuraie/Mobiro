#pragma once

#include <atomic>
#include <cmath>
#include <cstdint>

namespace mobiro::input {

// Binary-compatible with Win32 XINPUT_GAMEPAD & XINPUT_STATE
#pragma pack(push, 1)
struct XInputGamepad {
    uint16_t wButtons = 0;
    uint8_t bLeftTrigger = 0;
    uint8_t bRightTrigger = 0;
    int16_t sThumbLX = 0;
    int16_t sThumbLY = 0;
    int16_t sThumbRX = 0;
    int16_t sThumbRY = 0;
};

struct XInputState {
    uint32_t dwPacketNumber = 0;
    XInputGamepad Gamepad{};
};
#pragma pack(pop)

// Standard XInput button bitmasks
enum XInputButton : uint16_t {
    kDpadUp        = 0x0001,
    kDpadDown      = 0x0002,
    kDpadLeft      = 0x0004,
    kDpadRight     = 0x0008,
    kStart         = 0x0010,
    kBack          = 0x0020,
    kLeftThumb     = 0x0040,
    kRightThumb    = 0x0080,
    kLeftShoulder  = 0x0100, // L1: Sekiro Deflect / Guard
    kRightShoulder = 0x0200, // R1: Sekiro Attack
    kButtonA       = 0x1000, // Jump
    kButtonB       = 0x2000, // Dodge / Step / Mikiri
    kButtonX       = 0x4000, // Interact / Pick up
    kButtonY       = 0x8000, // Cycle Prosthetic
};

// Lock-free seqlock-protected input router bridging Android GameActivity touch/HID events
// directly to XInputGetState with zero JNI hops and sub-millisecond latency.
class InputRouter {
public:
    static InputRouter& global() {
        static InputRouter inst;
        return inst;
    }

    // Apply radial deadzone + cubic response curve for virtual thumbstick or analog axes.
    static void map_stick_axis(float raw_x, float raw_y, float deadzone,
                               int16_t& out_x, int16_t& out_y) {
        const float mag = std::sqrt(raw_x * raw_x + raw_y * raw_y);
        if (mag <= deadzone || mag < 1e-6f) {
            out_x = 0;
            out_y = 0;
            return;
        }
        const float clamped = std::min(1.0f, mag);
        const float norm = (clamped - deadzone) / (1.0f - deadzone);
        // Subtle 70/30 linear-cubic blend preserves slow stealth walk while keeping sprint crisp
        const float curved = 0.7f * norm + 0.3f * (norm * norm * norm);
        const float scale = (curved / mag) * 32767.0f;

        const float sx = std::max(-32767.0f, std::min(32767.0f, raw_x * scale));
        const float sy = std::max(-32767.0f, std::min(32767.0f, raw_y * scale));
        out_x = static_cast<int16_t>(std::lround(sx));
        out_y = static_cast<int16_t>(std::lround(sy));
    }

    void set_button(uint16_t mask, bool pressed) {
        mutate([&](XInputGamepad& g) {
            if (pressed) g.wButtons |= mask;
            else         g.wButtons &= static_cast<uint16_t>(~mask);
        });
    }

    void set_left_stick(float nx, float ny, float deadzone = 0.12f) {
        int16_t sx = 0, sy = 0;
        map_stick_axis(nx, ny, deadzone, sx, sy);
        mutate([&](XInputGamepad& g) {
            g.sThumbLX = sx;
            g.sThumbLY = sy;
        });
    }

    void set_right_stick(float nx, float ny, float deadzone = 0.10f) {
        int16_t sx = 0, sy = 0;
        map_stick_axis(nx, ny, deadzone, sx, sy);
        mutate([&](XInputGamepad& g) {
            g.sThumbRX = sx;
            g.sThumbRY = sy;
        });
    }

    void set_triggers(float left_01, float right_01) {
        auto to_u8 = [](float v) -> uint8_t {
            float c = std::max(0.0f, std::min(1.0f, v));
            return static_cast<uint8_t>(std::lround(c * 255.0f));
        };
        mutate([&](XInputGamepad& g) {
            g.bLeftTrigger = to_u8(left_01);
            g.bRightTrigger = to_u8(right_01);
        });
    }

    // Lock-free wait-free reader for XInputGetState thunk
    XInputState snapshot() const {
        XInputState copy{};
        uint32_t s1 = 0, s2 = 0;
        do {
            s1 = seq_.load(std::memory_order_acquire);
            if (s1 & 1u) continue;
            copy = state_;
            s2 = seq_.load(std::memory_order_acquire);
        } while (s1 != s2 || (s1 & 1u));
        return copy;
    }

private:
    template <typename Fn>
    void mutate(Fn&& fn) {
        uint32_t s = seq_.load(std::memory_order_relaxed);
        seq_.store(s + 1, std::memory_order_release); // odd = write in progress
        fn(state_.Gamepad);
        ++state_.dwPacketNumber;
        seq_.store(s + 2, std::memory_order_release); // even = consistent
    }

    std::atomic<uint32_t> seq_{0};
    XInputState state_{};
};

} // namespace mobiro::input
