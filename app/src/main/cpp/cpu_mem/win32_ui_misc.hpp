#pragma once

#include <cstdint>
#include <deque>
#include <mutex>

namespace mobiro::win32 {

// Canonical Win32 RECT (16 bytes)
struct Win32Rect {
    int32_t left = 0;
    int32_t top = 0;
    int32_t right = 1920;
    int32_t bottom = 1080;
};
static_assert(sizeof(Win32Rect) == 16, "RECT must be 16 bytes");

// Canonical Win64 MSG (48 bytes)
struct Win64Msg {
    uint64_t hwnd = 0;
    uint32_t message = 0;
    uint32_t pad0 = 0;
    uint64_t wparam = 0;
    int64_t  lparam = 0;
    uint32_t time = 0;
    int32_t  pt_x = 0;
    int32_t  pt_y = 0;
    uint32_t pad1 = 0;
};
static_assert(sizeof(Win64Msg) == 48, "Win64 MSG must be 48 bytes");

// Minimal headless Win32 window/message queue bridging GameActivity's ANativeWindow
// without spinning up an X11 or Windows desktop shell.
class HeadlessWindowState {
public:
    static constexpr uint64_t kMainHwnd = 0x00010010ULL;
    static constexpr uint32_t kWmQuit = 0x0012u;

    void set_dimensions(int32_t w, int32_t h) {
        std::lock_guard<std::mutex> lk(mu_);
        if (w > 0) width_ = w;
        if (h > 0) height_ = h;
    }

    Win32Rect client_rect() const {
        std::lock_guard<std::mutex> lk(mu_);
        return {0, 0, width_, height_};
    }

    void post_message(const Win64Msg& msg) {
        std::lock_guard<std::mutex> lk(mu_);
        queue_.push_back(msg);
    }

    void post_quit(int32_t exit_code) {
        Win64Msg m{};
        m.hwnd = kMainHwnd;
        m.message = kWmQuit;
        m.wparam = static_cast<uint64_t>(static_cast<uint32_t>(exit_code));
        post_message(m);
    }

    bool peek_message(Win64Msg* out, bool remove) {
        std::lock_guard<std::mutex> lk(mu_);
        if (queue_.empty()) return false;
        if (out) *out = queue_.front();
        if (remove) queue_.pop_front();
        return true;
    }

    void clear() {
        std::lock_guard<std::mutex> lk(mu_);
        queue_.clear();
    }

private:
    mutable std::mutex mu_;
    int32_t width_ = 1920;
    int32_t height_ = 1080;
    std::deque<Win64Msg> queue_;
};

} // namespace mobiro::win32
