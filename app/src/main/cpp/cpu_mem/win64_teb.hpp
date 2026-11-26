#pragma once

#include "guest_arena.hpp"

#include <cstdint>
#include <cstring>

#include <mutex>
#include <vector>

namespace mobiro::cpu {

// Tracks PE64 IMAGE_TLS_DIRECTORY64 templates for sekiro.exe and auto-loaded BYOF DLLs
// so every Win64 thread gets isolated per-module `.tls` storage behind GS:[0x58].
struct StaticTlsTemplate {
    uintptr_t raw_start_va = 0;
    size_t raw_size = 0;
    size_t zero_fill = 0;
};

class StaticTlsRegistry {
public:
    static constexpr size_t kMaxModules = 32;

    uint32_t register_module(uintptr_t raw_start_va, size_t raw_size, size_t zero_fill) {
        std::lock_guard<std::mutex> lk(mu_);
        if (modules_.size() >= kMaxModules) return static_cast<uint32_t>(kMaxModules - 1);
        const uint32_t idx = static_cast<uint32_t>(modules_.size());
        modules_.push_back({raw_start_va, raw_size, zero_fill});
        return idx;
    }

    size_t module_count() const {
        std::lock_guard<std::mutex> lk(mu_);
        return modules_.size();
    }

    std::vector<StaticTlsTemplate> snapshot() const {
        std::lock_guard<std::mutex> lk(mu_);
        return modules_;
    }

    void clear() {
        std::lock_guard<std::mutex> lk(mu_);
        modules_.clear();
    }

private:
    mutable std::mutex mu_;
    std::vector<StaticTlsTemplate> modules_;
};

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
    uint64_t tls_array_ptr = 0;        // GS:[0x58] -> points to static_tls_ptrs[] (Win64 implicit TLS)
    uint64_t peb_ptr = 0;              // GS:[0x60] -> points to Win64Peb
    uint32_t last_error = 0;           // GS:[0x68]
    uint32_t count_owned_locks = 0;    // GS:[0x6C]
    uint8_t  reserved[0x1410]{};
    uint64_t tls_slots[64]{};          // GS:[0x1480] standard 64 dynamic Win32 TlsAlloc slots
    uint64_t static_tls_ptrs[StaticTlsRegistry::kMaxModules]{}; // Per-module __declspec(thread) pointers
};
static_assert(offsetof(Win64Teb, self_ptr) == 0x30);
static_assert(offsetof(Win64Teb, unique_thread) == 0x48);
static_assert(offsetof(Win64Teb, tls_array_ptr) == 0x58);
static_assert(offsetof(Win64Teb, peb_ptr) == 0x60);
static_assert(offsetof(Win64Teb, last_error) == 0x68);
static_assert(offsetof(Win64Teb, tls_slots) == 0x1480);

struct Win64ThreadEnv {
    Win64Peb* peb = nullptr;
    Win64Teb* teb = nullptr;
    uintptr_t stack_base = 0;
    uintptr_t stack_limit = 0;
    uintptr_t process_heap = 0;
    uintptr_t tls_pool_va = 0;
    size_t    tls_pool_bytes = 0;

    // Populates isolated per-module static `.tls` copies for GS:[0x58] (sekiro.exe, fmodex64, etc.)
    void populate_static_tls(const StaticTlsRegistry* reg) {
        if (!teb || !tls_pool_va || tls_pool_bytes < 256) return;
        teb->tls_array_ptr = reinterpret_cast<uintptr_t>(&teb->static_tls_ptrs[0]);
        uintptr_t cursor = tls_pool_va;
        const uintptr_t limit = tls_pool_va + tls_pool_bytes;
        const auto mods = reg ? reg->snapshot() : std::vector<StaticTlsTemplate>{};
        for (size_t i = 0; i < StaticTlsRegistry::kMaxModules; ++i) {
            if (i < mods.size()) {
                const size_t total = std::max<size_t>(16, (mods[i].raw_size + mods[i].zero_fill + 15) & ~size_t(15));
                if (cursor + total <= limit) {
                    auto* dst = reinterpret_cast<uint8_t*>(cursor);
                    std::memset(dst, 0, total);
                    if (mods[i].raw_start_va && mods[i].raw_size) {
                        std::memcpy(dst, reinterpret_cast<const void*>(mods[i].raw_start_va), mods[i].raw_size);
                    }
                    teb->static_tls_ptrs[i] = cursor;
                    cursor += total;
                    continue;
                }
            }
            // Fallback safe 16-byte zero block so uninitialized module indices never NULL-deref
            if (cursor + 16 <= limit) {
                std::memset(reinterpret_cast<void*>(cursor), 0, 16);
                teb->static_tls_ptrs[i] = cursor;
                cursor += 16;
            }
        }
    }

    bool init_main_thread(mem::GuestArena& arena,
                          uintptr_t image_base,
                          uint32_t cpu_count,
                          uint64_t pid,
                          uint64_t tid,
                          size_t stack_size = 2 * 1024 * 1024,
                          const StaticTlsRegistry* static_tls = nullptr) {
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
        tls_pool_va = ctrl_va + 16384;
        tls_pool_bytes = 65536 - 16384;

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
        populate_static_tls(static_tls);
        return true;
    }

    // Worker threads only need their own TEB + stack + isolated static `.tls` copy.
    bool init_worker_thread(mem::GuestArena& arena,
                            uintptr_t image_base,
                            uint32_t cpu_count,
                            uint64_t pid,
                            uint64_t tid,
                            size_t stack_size = 512 * 1024,
                            const StaticTlsRegistry* static_tls = nullptr) {
        const uintptr_t ctrl_va = arena.virtual_alloc(
            0, 65536, mem::kProtRead | mem::kProtWrite, true);
        if (!ctrl_va) return false;

        const uintptr_t stack_va = arena.virtual_alloc(
            0, stack_size, mem::kProtRead | mem::kProtWrite, true);
        if (!stack_va) return false;

        peb = reinterpret_cast<Win64Peb*>(ctrl_va);
        teb = reinterpret_cast<Win64Teb*>(ctrl_va + 4096);
        std::memset(peb, 0, sizeof(Win64Peb));
        std::memset(teb, 0, sizeof(Win64Teb));
        tls_pool_va = ctrl_va + 16384;
        tls_pool_bytes = 65536 - 16384;

        peb->image_base_address = image_base;
        peb->number_of_processors = cpu_count ? cpu_count : 8;

        stack_limit = stack_va;
        stack_base = stack_va + stack_size;

        teb->stack_base = stack_base;
        teb->stack_limit = stack_limit;
        teb->self_ptr = reinterpret_cast<uintptr_t>(teb);
        teb->unique_process = pid;
        teb->unique_thread = tid;
        teb->peb_ptr = reinterpret_cast<uintptr_t>(peb);
        populate_static_tls(static_tls);
        return true;
    }
};

} // namespace mobiro::cpu
