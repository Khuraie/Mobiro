#pragma once

#include "guest_arena.hpp"

#include <cstdint>
#include <cstring>

namespace mobiro::cpu {

// Minimal canonical Win64 PEB layout (offsets match x64 Windows ABI)
struct Win64Peb {
    uint8_t  reserved0[0x10]{};
    uint64_t image_base_address = 0;   // +0x10
    uint64_t ldr = 0;                  // +0x18
    uint64_t process_parameters = 0;   // +0x20
    uint8_t  reserved1[0x08]{};
    uint64_t process_heap = 0;         // +0x30
    uint8_t  reserved2[0x80]{};
    uint32_t number_of_processors = 8; // +0xB8
    uint32_t nt_global_flag = 0;       // +0xBC
};
static_assert(offsetof(Win64Peb, image_base_address) == 0x10);
static_assert(offsetof(Win64Peb, process_heap) == 0x30);
static_assert(offsetof(Win64Peb, number_of_processors) == 0xB8);

// Minimal canonical Win64 TEB / NT_TIB layout accessed via GS:[offset]
struct Win64Teb {
    uint64_t exception_list = 0;       // GS:[0x00]
    uint64_t stack_base = 0;           // GS:[0x08]
    uint64_t stack_limit = 0;          // GS:[0x10]
    uint64_t sub_system_tib = 0;       // GS:[0x18]
    uint64_t fiber_data = 0;           // GS:[0x20]
    uint64_t arbitrary_user_ptr = 0;   // GS:[0x28]
    uint64_t self_ptr = 0;             // GS:[0x30] -> points to this Win64Teb
    uint64_t env_ptr = 0;              // GS:[0x38]
    uint64_t unique_process = 0;       // GS:[0x40]
    uint64_t unique_thread = 0;        // GS:[0x48]
    uint64_t active_rpc = 0;           // GS:[0x50]
    uint64_t tls_array_ptr = 0;        // GS:[0x58]
    uint64_t peb_ptr = 0;              // GS:[0x60] -> points to Win64Peb
    uint32_t last_error = 0;           // GS:[0x68]
    uint32_t count_owned_locks = 0;    // GS:[0x6C]
    uint8_t  reserved[0x1410]{};
    uint64_t tls_slots[64]{};          // GS:[0x1480] standard 64 Win32 TLS slots
};
static_assert(offsetof(Win64Teb, self_ptr) == 0x30);
static_assert(offsetof(Win64Teb, unique_thread) == 0x48);
static_assert(offsetof(Win64Teb, peb_ptr) == 0x60);
static_assert(offsetof(Win64Teb, last_error) == 0x68);
static_assert(offsetof(Win64Teb, tls_slots) == 0x1480);

struct Win64ThreadEnv {
    Win64Peb* peb = nullptr;
    Win64Teb* teb = nullptr;
    uintptr_t stack_base = 0;
    uintptr_t stack_limit = 0;
    uintptr_t process_heap = 0;

    bool init_main_thread(mem::GuestArena& arena,
                          uintptr_t image_base,
                          uint32_t cpu_count,
                          uint64_t pid,
                          uint64_t tid,
                          size_t stack_size = 2 * 1024 * 1024) {
        const uintptr_t ctrl_va = arena.virtual_alloc(
            0, 65536, mem::kProtRead | mem::kProtWrite, true);
        if (!ctrl_va) return false;

        const uintptr_t stack_va = arena.virtual_alloc(
            0, stack_size, mem::kProtRead | mem::kProtWrite, true);
        if (!stack_va) return false;

        const uintptr_t heap_va = arena.virtual_alloc(
            0, 16 * 1024 * 1024, mem::kProtRead | mem::kProtWrite, true);
        if (!heap_va) return false;

        peb = reinterpret_cast<Win64Peb*>(ctrl_va);
        teb = reinterpret_cast<Win64Teb*>(ctrl_va + 4096);
        std::memset(peb, 0, sizeof(Win64Peb));
        std::memset(teb, 0, sizeof(Win64Teb));

        peb->image_base_address = image_base;
        peb->process_heap = heap_va;
        peb->number_of_processors = cpu_count ? cpu_count : 8;

        stack_limit = stack_va;
        stack_base = stack_va + stack_size;
        process_heap = heap_va;

        teb->stack_base = stack_base;
        teb->stack_limit = stack_limit;
        teb->self_ptr = reinterpret_cast<uintptr_t>(teb);
        teb->unique_process = pid;
        teb->unique_thread = tid;
        teb->peb_ptr = reinterpret_cast<uintptr_t>(peb);
        teb->tls_array_ptr = reinterpret_cast<uintptr_t>(&teb->tls_slots[0]);
        return true;
    }
};

} // namespace mobiro::cpu
