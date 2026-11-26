#pragma once

#include "guest_arena.hpp"
#include "win32_file_sync.hpp"
#include "win32_proc_sync.hpp"
#include "win64_teb.hpp"
#include "../validator/vfs_mapper.hpp"

#include <cstdint>
#include <string>
#include <unordered_map>

#ifdef MOBIRO_HAVE_BOX64
extern "C" {
#include "box64context.h"
#include "x64emu.h"
}
#else
// Minimal ABI-compatible register frame used when building without the upstream Box64 submodule
struct MobiroX64Emu {
    uint64_t rax = 0, rcx = 0, rdx = 0, rbx = 0;
    uint64_t rsp = 0, rbp = 0, rsi = 0, rdi = 0;
    uint64_t r8 = 0, r9 = 0, r10 = 0, r11 = 0;
    uint64_t rip = 0;
    uint64_t gs_base = 0; // Win64 TEB pointer
};
using x64emu_t = MobiroX64Emu;
#endif

namespace mobiro::cpu {

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
    bool initialize(mem::GuestArena* arena, const validator::VfsMapper* vfs);
    void shutdown();

    void register_thunk(const std::string& dll_lower, const std::string& symbol, NativeThunkFn fn);
    uintptr_t resolve_import(const std::string& dll_lower, const std::string& symbol);

    // Invoke a registered thunk directly (used by Box64 trap dispatch and unit tests)
    bool invoke_thunk(const std::string& dll_lower, const std::string& symbol, x64emu_t* emu) const;

    size_t registered_count() const { return thunks_.size(); }

    static Box64Bridge* instance() { return g_instance_; }
    mem::GuestArena* arena() const { return arena_; }
    const validator::VfsMapper* vfs() const { return vfs_; }
    win32::FileHandleTable& files() { return files_; }
    win32::SrwLockTable& srw_locks() { return srw_locks_; }
    win32::GuestHeap& heap() { return heap_; }
    win32::EventTable& events() { return events_; }
    win32::SehUnwindRegistry& seh() { return seh_; }
    void set_main_module_base(uintptr_t base) { main_module_base_ = base; }
    uintptr_t main_module_base() const { return main_module_base_; }
    void set_main_teb(Win64Teb* teb) { main_teb_ = teb; }
    Win64Teb* main_teb() const { return main_teb_; }
    uint32_t alloc_tls_slot() {
        uint32_t idx = next_tls_slot_++;
        return (idx < 64) ? idx : 0xFFFFFFFFu;
    }

private:
    void register_default_win32_thunks();

    mem::GuestArena* arena_ = nullptr;
    const validator::VfsMapper* vfs_ = nullptr;
    win32::FileHandleTable files_;
    win32::SrwLockTable srw_locks_;
    win32::GuestHeap heap_;
    win32::EventTable events_;
    win32::SehUnwindRegistry seh_;
    uintptr_t main_module_base_ = 0;
    Win64Teb* main_teb_ = nullptr;
    uint32_t next_tls_slot_ = 0;
    NativeBridgeStub* stub_pool_ = nullptr;
    size_t stub_count_ = 0;
    static constexpr size_t kMaxStubs = 4096;
    std::unordered_map<std::string, NativeThunkFn> thunks_;
    static inline Box64Bridge* g_instance_ = nullptr;
};

} // namespace mobiro::cpu
