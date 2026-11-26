#pragma once

#include "guest_arena.hpp"
#include "win32_file_sync.hpp"
#include "win32_module_mgr.hpp"
#include "win32_proc_sync.hpp"
#include "win32_thread_wait.hpp"
#include "win32_ui_misc.hpp"
#include "win64_teb.hpp"
#include "../validator/vfs_mapper.hpp"

#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>

#ifdef MOBIRO_HAVE_BOX64
extern "C" {
typedef struct x64emu_s x64emu_t;
uint64_t* mobiro_box64_reg_ptr(x64emu_t* emu, int reg_id);
float mobiro_box64_xmm_f32(const x64emu_t* emu, int xmm_idx);
uintptr_t mobiro_box64_teb(const x64emu_t* emu);
int mobiro_box64_call_fn(uintptr_t fn_va,
                         uint64_t rcx,
                         uint64_t rdx,
                         uint64_t r8,
                         uintptr_t stack_base,
                         uint32_t stack_size,
                         uintptr_t teb_va,
                         uint64_t return_sentinel,
                         uint64_t* out_rax);
}
#else
// Minimal ABI-compatible register frame used when building without the upstream Box64 static core
struct MobiroX64Emu {
    uint64_t rax = 0, rcx = 0, rdx = 0, rbx = 0;
    uint64_t rsp = 0, rbp = 0, rsi = 0, rdi = 0;
    uint64_t r8 = 0, r9 = 0, r10 = 0, r11 = 0;
    uint64_t xmm[4] = {}; // Low 64 bits of XMM0..XMM3 (Win64 scalar float/double args)
    uint64_t rip = 0;
    uint64_t gs_base = 0; // Win64 TEB pointer
};
using x64emu_t = MobiroX64Emu;
#endif

namespace mobiro::cpu {

// Unified Win64 register & XMM accessors (works identically with Box64 C shim and host tests)
inline uint64_t& emu_reg_rax(x64emu_t* e) {
#ifdef MOBIRO_HAVE_BOX64
    return *mobiro_box64_reg_ptr(e, 0);
#else
    return e->rax;
#endif
}
inline uint64_t emu_reg_rcx(const x64emu_t* e) {
#ifdef MOBIRO_HAVE_BOX64
    return *mobiro_box64_reg_ptr(const_cast<x64emu_t*>(e), 1);
#else
    return e->rcx;
#endif
}
inline uint64_t emu_reg_rdx(const x64emu_t* e) {
#ifdef MOBIRO_HAVE_BOX64
    return *mobiro_box64_reg_ptr(const_cast<x64emu_t*>(e), 2);
#else
    return e->rdx;
#endif
}
inline uint64_t emu_reg_rsp(const x64emu_t* e) {
#ifdef MOBIRO_HAVE_BOX64
    return *mobiro_box64_reg_ptr(const_cast<x64emu_t*>(e), 4);
#else
    return e->rsp;
#endif
}
inline uint64_t emu_reg_r8(const x64emu_t* e) {
#ifdef MOBIRO_HAVE_BOX64
    return *mobiro_box64_reg_ptr(const_cast<x64emu_t*>(e), 8);
#else
    return e->r8;
#endif
}
inline uint64_t emu_reg_r9(const x64emu_t* e) {
#ifdef MOBIRO_HAVE_BOX64
    return *mobiro_box64_reg_ptr(const_cast<x64emu_t*>(e), 9);
#else
    return e->r9;
#endif
}
inline float emu_xmm_f32(const x64emu_t* e, int idx) {
    if (!e || idx < 0 || idx >= 4) return 0.0f;
#ifdef MOBIRO_HAVE_BOX64
    return mobiro_box64_xmm_f32(e, idx);
#else
    float f = 0.0f;
    uint32_t bits = static_cast<uint32_t>(e->xmm[idx] & 0xFFFFFFFFu);
    std::memcpy(&f, &bits, sizeof(f));
    return f;
#endif
}
#ifndef MOBIRO_HAVE_BOX64
inline void emu_set_xmm_f32(x64emu_t* e, int idx, float v) {
    if (!e || idx < 0 || idx >= 4) return;
    uint32_t bits = 0;
    std::memcpy(&bits, &v, sizeof(bits));
    e->xmm[idx] = bits;
}
#endif
inline uintptr_t emu_teb_va(const x64emu_t* e) {
    if (!e) return 0;
#ifdef MOBIRO_HAVE_BOX64
    return mobiro_box64_teb(e);
#else
    return static_cast<uintptr_t>(e->gs_base);
#endif
}

using NativeThunkFn = void (*)(x64emu_t* emu);

// Stub emitted into an RW trampoline table. Box64 Dynarec matches 0xCC 'M' 'B'
// and emits an inline AArch64 BLR directly to thunk_ptr (MS x64 -> AAPCS64).
#pragma pack(push, 1)
struct NativeBridgeStub {
    uint8_t trap_cc = 0xCC;
    uint8_t magic[2] = {'M', 'B'};
    uint64_t thunk_ptr = 0;
    uint8_t ret_op = 0xC3;
};
#pragma pack(pop)

class Box64Bridge {
public:
    bool initialize(mem::GuestArena* arena, validator::VfsMapper* vfs);
    void shutdown();

    void register_thunk(const std::string& dll_lower, const std::string& symbol, NativeThunkFn fn);
    uintptr_t resolve_import(const std::string& dll_lower, const std::string& symbol);

    // Invoke a registered thunk directly (used by Box64 trap dispatch and unit tests)
    bool invoke_thunk(const std::string& dll_lower, const std::string& symbol, x64emu_t* emu) const;

    size_t registered_count() const { return thunks_.size(); }

    bool has_dll_thunks(const std::string& dll_lower) const {
        const std::string prefix = win32::ModuleRegistry::basename_lower(dll_lower) + "!";
        for (const auto& [k, _] : thunks_) {
            if (k.rfind(prefix, 0) == 0) return true;
        }
        return false;
    }

    static Box64Bridge* instance() { return g_instance_; }
    mem::GuestArena* arena() const { return arena_; }
    validator::VfsMapper* vfs() const { return vfs_; }
    win32::FileHandleTable& files() { return files_; }
    win32::SrwLockTable& srw_locks() { return srw_locks_; }
    win32::CriticalSectionTable& crit_sections() { return crit_sections_; }
    win32::GuestHeap& heap() { return heap_; }
    win32::EventTable& events() { return events_; }
    win32::SehUnwindRegistry& seh() { return seh_; }
    win32::AddressWaitTable& addr_wait() { return addr_wait_; }
    win32::GuestThreadTable& threads() { return threads_; }
    win32::ModuleRegistry& modules() { return modules_; }
    win32::HeadlessWindowState& window() { return window_; }
    void set_main_module_base(uintptr_t base) { main_module_base_ = base; }
    uintptr_t main_module_base() const { return main_module_base_; }
    void set_main_teb(Win64Teb* teb) { main_teb_ = teb; }
    Win64Teb* main_teb() const { return main_teb_; }
    void set_main_thread_env(const Win64ThreadEnv* tenv) {
        main_thread_env_ = tenv;
        if (tenv && tenv->teb) main_teb_ = tenv->teb;
    }
    const Win64ThreadEnv* main_thread_env() const { return main_thread_env_; }
    uint32_t alloc_tls_slot() {
        uint32_t idx = next_tls_slot_++;
        return (idx < 64) ? idx : 0xFFFFFFFFu;
    }

private:
    void register_default_win32_thunks();

    mem::GuestArena* arena_ = nullptr;
    validator::VfsMapper* vfs_ = nullptr;
    win32::FileHandleTable files_;
    win32::SrwLockTable srw_locks_;
    win32::CriticalSectionTable crit_sections_;
    win32::GuestHeap heap_;
    win32::EventTable events_;
    win32::SehUnwindRegistry seh_;
    win32::AddressWaitTable addr_wait_;
    win32::GuestThreadTable threads_;
    win32::ModuleRegistry modules_;
    win32::HeadlessWindowState window_;
    uintptr_t main_module_base_ = 0;
    Win64Teb* main_teb_ = nullptr;
    const Win64ThreadEnv* main_thread_env_ = nullptr;
    uint32_t next_tls_slot_ = 0;
    NativeBridgeStub* stub_pool_ = nullptr;
    size_t stub_count_ = 0;
    static constexpr size_t kMaxStubs = 4096;
    std::unordered_map<std::string, NativeThunkFn> thunks_;
    static inline Box64Bridge* g_instance_ = nullptr;
};

} // namespace mobiro::cpu
