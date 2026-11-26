#pragma once

#include <atomic>
#include <cstdint>
#include <cstring>

namespace mobiro::win32 {

// Canonical Win64 MEMORYSTATUSEX (64 bytes)
struct MemoryStatusEx {
    uint32_t length = 64;
    uint32_t memory_load = 35;
    uint64_t total_phys = 8ULL * 1024 * 1024 * 1024;
    uint64_t avail_phys = 5ULL * 1024 * 1024 * 1024;
    uint64_t total_page_file = 8ULL * 1024 * 1024 * 1024;
    uint64_t avail_page_file = 5ULL * 1024 * 1024 * 1024;
    uint64_t total_virtual = 128ULL * 1024 * 1024 * 1024;
    uint64_t avail_virtual = 120ULL * 1024 * 1024 * 1024;
    uint64_t avail_extended_virtual = 0;
};
static_assert(sizeof(MemoryStatusEx) == 64, "MEMORYSTATUSEX must be 64 bytes");

// Minimal Win64 IDirectInput8 COM stub so Sekiro gracefully enumerates 0 DirectInput
// devices and uses Mobiro's zero-latency XInputGetState path exclusively.
struct IDirectInput8Vtbl {
    int32_t  (*QueryInterface)(void* self, const void* riid, void** ppv);
    uint32_t (*AddRef)(void* self);
    uint32_t (*Release)(void* self);
    int32_t  (*CreateDevice)(void* self, const void* rguid, void** out_dev, void* unk);
    int32_t  (*EnumDevices)(void* self, uint32_t dev_type, void* cb, void* ref, uint32_t flags);
    int32_t  (*GetDeviceStatus)(void* self, const void* rguid);
    int32_t  (*RunControlPanel)(void* self, void* hwnd, uint32_t flags);
    int32_t  (*Initialize)(void* self, void* hinst, uint32_t ver);
    int32_t  (*FindDevice)(void* self, const void* rguid, const void* name, void* out_guid);
};

struct IDirectInput8Com {
    const IDirectInput8Vtbl* lpVtbl = nullptr;
    std::atomic<uint32_t> ref_count{1};
};

namespace di8_detail {
inline int32_t qi(void* self, const void*, void** ppv) {
    if (!ppv) return static_cast<int32_t>(0x80004003u);
    *ppv = self;
    static_cast<IDirectInput8Com*>(self)->ref_count.fetch_add(1, std::memory_order_relaxed);
    return 0;
}
inline uint32_t add_ref(void* self) {
    return static_cast<IDirectInput8Com*>(self)->ref_count.fetch_add(1, std::memory_order_relaxed) + 1;
}
inline uint32_t release(void* self) {
    auto* obj = static_cast<IDirectInput8Com*>(self);
    const uint32_t rem = obj->ref_count.fetch_sub(1, std::memory_order_acq_rel) - 1;
    if (rem == 0) delete obj;
    return rem;
}
inline int32_t create_device(void*, const void*, void** out, void*) {
    if (out) *out = nullptr;
    return static_cast<int32_t>(0x80040154u); // DIERR_DEVICENOTREG
}
inline int32_t enum_devices(void*, uint32_t, void*, void*, uint32_t) { return 0; } // DI_OK (0 devices)
inline int32_t get_status(void*, const void*) { return 1; } // DI_NOTATTACHED
inline int32_t run_cpl(void*, void*, uint32_t) { return 0; }
inline int32_t initialize(void*, void*, uint32_t) { return 0; }
inline int32_t find_device(void*, const void*, const void*, void*) { return static_cast<int32_t>(0x80070002u); }

inline const IDirectInput8Vtbl kVtbl = {
    qi, add_ref, release, create_device, enum_devices, get_status, run_cpl, initialize, find_device
};
} // namespace di8_detail

inline int32_t create_dinput8_com(void** out_di) {
    if (!out_di) return static_cast<int32_t>(0x80070057u);
    auto* obj = new IDirectInput8Com();
    obj->lpVtbl = &di8_detail::kVtbl;
    *out_di = obj;
    return 0; // DI_OK
}

} // namespace mobiro::win32
