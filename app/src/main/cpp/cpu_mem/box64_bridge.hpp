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
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#ifdef MOBIRO_HAVE_BOX64
extern "C" {
typedef struct x64emu_s x64emu_t;
uint64_t* mobiro_box64_reg_ptr(x64emu_t* emu, int reg_id);
float mobiro_box64_xmm_f32(const x64emu_t* emu, int xmm_idx);
uintptr_t mobiro_box64_teb(const x64emu_t* emu);
void mobiro_box64_ensure_init(void);
void mobiro_box64_set_prot(uintptr_t addr, size_t size, int mobiro_prot);
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

inline void sync_box64_exec_region(const void* ptr, size_t bytes) {
#ifdef MOBIRO_HAVE_BOX64
    if (ptr && bytes) {
        mobiro_box64_set_prot(reinterpret_cast<uintptr_t>(ptr), bytes,
                              mem::kProtRead | mem::kProtWrite | mem::kProtExec);
    }
#else
    (void)ptr;
    (void)bytes;
#endif
}

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

// Box64 wrapper_t-compatible trampoline invoked directly by Box64's ARM64 Dynarec
// and x64Int3 interpreter for every NativeBridgeStub (IAT thunks + D3D11 COM slots).
extern "C" inline void mobiro_native_thunk_wrapper(x64emu_t* emu, uintptr_t fn_ptr) {
    if (fn_ptr) {
        reinterpret_cast<NativeThunkFn>(fn_ptr)(emu);
    }
}

// Binary-compatible with upstream Box64's 32-byte `onebridge_t` (`src/tools/bridge_private.h`).
// Box64 ARM64 Dynarec (`dynarec_arm64_00.c`) and `x64Int3` natively match `0xCC 'S' 'C'` and
// dispatch `wrapper_ptr(emu, thunk_ptr)` followed by `0xC3` RET with zero Box64 patches.
#pragma pack(push, 1)
struct alignas(32) NativeBridgeStub {
    uint8_t  trap_cc = 0xCC;        // +0x00: INT3
    uint8_t  magic[2] = {'S', 'C'}; // +0x01: Box64 IsBridgeSignature('S', 'C')
    uint64_t wrapper_ptr = 0;       // +0x03: Box64 wrapper_t (&mobiro_native_thunk_wrapper)
    uint64_t thunk_ptr = 0;         // +0x0B: NativeThunkFn
    uint8_t  ret_op = 0xC3;         // +0x13: RET
    uint16_t ret_n = 0;             // +0x14: N for C2 ret
    uint8_t  is_func = 0;           // +0x16
    uint64_t name_or_func = 0;      // +0x17: optional debug name
    uint8_t  pad = 0;               // +0x1F
};
#pragma pack(pop)
static_assert(sizeof(NativeBridgeStub) == 32);
static_assert(offsetof(NativeBridgeStub, wrapper_ptr) == 3);
static_assert(offsetof(NativeBridgeStub, thunk_ptr) == 11);
static_assert(offsetof(NativeBridgeStub, ret_op) == 19);

class Box64Bridge {
public:
    bool initialize(mem::GuestArena* arena, validator::VfsMapper* vfs);
    void shutdown();

    void register_thunk(const std::string& dll_lower, const std::string& symbol, NativeThunkFn fn);
    uintptr_t resolve_import(const std::string& dll_lower, const std::string& symbol);
    // Allocates a safe logging onebridge_t stub for an unresolved import so calling it logs & returns 0 instead of SIGSEGV
    uintptr_t resolve_unresolved_trap(const std::string& dll_lower, const std::string& symbol);
    void record_unresolved_call(const char* sym_name);
    std::vector<std::string> called_unresolved_imports() const;

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
    win32::ConditionVariableTable& cond_vars() { return cond_vars_; }
    win32::GuestHeap& heap() { return heap_; }
    win32::EventTable& events() { return events_; }
    win32::SehUnwindRegistry& seh() { return seh_; }
    win32::AddressWaitTable& addr_wait() { return addr_wait_; }
    win32::GuestThreadTable& threads() { return threads_; }
    win32::ModuleRegistry& modules() { return modules_; }
    win32::HeadlessWindowState& window() { return window_; }
    StaticTlsRegistry& static_tls() { return static_tls_; }
    const StaticTlsRegistry& static_tls() const { return static_tls_; }
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
    win32::ConditionVariableTable cond_vars_;
    win32::GuestHeap heap_;
    win32::EventTable events_;
    win32::SehUnwindRegistry seh_;
    win32::AddressWaitTable addr_wait_;
    win32::GuestThreadTable threads_;
    win32::ModuleRegistry modules_;
    win32::HeadlessWindowState window_;
    StaticTlsRegistry static_tls_;
    uintptr_t main_module_base_ = 0;
    Win64Teb* main_teb_ = nullptr;
    const Win64ThreadEnv* main_thread_env_ = nullptr;
    uint32_t next_tls_slot_ = 0;
    NativeBridgeStub* stub_pool_ = nullptr;
    size_t stub_count_ = 0;
    static constexpr size_t kMaxStubs = 4096;
    std::unordered_map<std::string, NativeThunkFn> thunks_;
    mutable std::mutex unresolved_mu_;
    std::deque<std::string> interned_unresolved_;
    std::unordered_map<std::string, uintptr_t> unresolved_stub_cache_;
    std::vector<std::string> called_unresolved_;
    static inline Box64Bridge* g_instance_ = nullptr;
};

} // namespace mobiro::cpu
