#include "box64_bridge.hpp"
#include "guest_executor.hpp"
#include "pe_loader.hpp"
#include "win32_ext_shims.hpp"
#include "../audio/xaudio2_com.hpp"
#include "../gfx/d3d11_com_bridge.hpp"
#include "../gfx/dxvk_interop.hpp"
#include "../input/input_router.hpp"

#include <chrono>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <random>
#include <thread>

#if defined(__linux__) || defined(__ANDROID__)
#include <sys/mman.h>
#endif
#if defined(__ANDROID__)
#include <android/log.h>
#endif

namespace mobiro::cpu {

namespace {

inline uint64_t& reg_rax(x64emu_t* e) { return emu_reg_rax(e); }
inline uint64_t reg_rcx(x64emu_t* e) { return emu_reg_rcx(e); }
inline uint64_t reg_rdx(x64emu_t* e) { return emu_reg_rdx(e); }
inline uint64_t reg_r8(x64emu_t* e) { return emu_reg_r8(e); }
inline uint64_t reg_r9(x64emu_t* e) { return emu_reg_r9(e); }
inline uint64_t stack_arg(x64emu_t* e, size_t win64_arg_index_from_5) {
    // Win64 stack layout at thunk entry: [RSP+0x00]=retaddr, [0x08..0x20]=shadow space, [0x28]=arg5
    auto* sp = reinterpret_cast<const uint64_t*>(emu_reg_rsp(e));
    if (!sp) return 0;
    return sp[5 + win64_arg_index_from_5];
}
inline Win64Teb* current_teb(x64emu_t* e) {
    if (const uintptr_t va = emu_teb_va(e)) return reinterpret_cast<Win64Teb*>(va);
    auto* b = Box64Bridge::instance();
    return b ? b->main_teb() : nullptr;
}

// --- Memory ---

void thunk_VirtualAlloc(x64emu_t* emu) {
    auto* bridge = Box64Bridge::instance();
    if (!bridge || !bridge->arena()) {
        reg_rax(emu) = 0;
        return;
    }
    const uintptr_t addr = static_cast<uintptr_t>(reg_rcx(emu));
    const size_t size = static_cast<size_t>(reg_rdx(emu));
    const uint32_t alloc_type = static_cast<uint32_t>(reg_r8(emu));
    const uint32_t win_prot = static_cast<uint32_t>(reg_r9(emu));

    const int prot = mem::GuestArena::from_win32_protect(win_prot);
    const bool commit = (alloc_type & 0x1000u) != 0; // MEM_COMMIT
    reg_rax(emu) = bridge->arena()->virtual_alloc(addr, size, prot, commit);
}

void thunk_VirtualFree(x64emu_t* emu) {
    auto* bridge = Box64Bridge::instance();
    if (!bridge || !bridge->arena()) {
        reg_rax(emu) = 0;
        return;
    }
    const uintptr_t addr = static_cast<uintptr_t>(reg_rcx(emu));
    const size_t size = static_cast<size_t>(reg_rdx(emu));
    reg_rax(emu) = bridge->arena()->virtual_decommit(addr, size) ? 1ULL : 0ULL;
}

void thunk_VirtualProtect(x64emu_t* emu) {
    auto* bridge = Box64Bridge::instance();
    if (!bridge || !bridge->arena()) {
        reg_rax(emu) = 0;
        return;
    }
    const uintptr_t addr = static_cast<uintptr_t>(reg_rcx(emu));
    const size_t size = static_cast<size_t>(reg_rdx(emu));
    const uint32_t new_prot = static_cast<uint32_t>(reg_r8(emu));
    auto* old_prot_out = reinterpret_cast<uint32_t*>(reg_r9(emu));
    if (old_prot_out) *old_prot_out = 0x04; // PAGE_READWRITE
    reg_rax(emu) = bridge->arena()->protect(addr, size, mem::GuestArena::from_win32_protect(new_prot)) ? 1ULL : 0ULL;
}

// --- VFS-Backed File I/O ---

void thunk_CreateFileW(x64emu_t* emu) {
    auto* bridge = Box64Bridge::instance();
    if (!bridge) {
        reg_rax(emu) = win32::FileHandleTable::kInvalidHandle;
        return;
    }
    const auto* wpath = reinterpret_cast<const uint16_t*>(reg_rcx(emu));
    const uint32_t desired_access = static_cast<uint32_t>(reg_rdx(emu));
    const uint32_t creation_disp = static_cast<uint32_t>(stack_arg(emu, 0));
    const std::string path = win32::utf16le_to_utf8(wpath);
    const bool wants_write = (desired_access & 0x40000000u) != 0; // GENERIC_WRITE
    if (wants_write) {
        const bool truncate = (creation_disp == 2u || creation_disp == 5u); // CREATE_ALWAYS / TRUNCATE_EXISTING
        reg_rax(emu) = bridge->files().open_write(bridge->vfs(), path, truncate);
    } else {
        reg_rax(emu) = bridge->files().open_read(bridge->vfs(), path);
    }
}

void thunk_CreateFileA(x64emu_t* emu) {
    auto* bridge = Box64Bridge::instance();
    const auto* apath = reinterpret_cast<const char*>(reg_rcx(emu));
    if (!bridge || !apath) {
        reg_rax(emu) = win32::FileHandleTable::kInvalidHandle;
        return;
    }
    const uint32_t desired_access = static_cast<uint32_t>(reg_rdx(emu));
    const uint32_t creation_disp = static_cast<uint32_t>(stack_arg(emu, 0));
    const bool wants_write = (desired_access & 0x40000000u) != 0;
    if (wants_write) {
        const bool truncate = (creation_disp == 2u || creation_disp == 5u);
        reg_rax(emu) = bridge->files().open_write(bridge->vfs(), apath, truncate);
    } else {
        reg_rax(emu) = bridge->files().open_read(bridge->vfs(), apath);
    }
}

void thunk_WriteFile(x64emu_t* emu) {
    auto* bridge = Box64Bridge::instance();
    if (!bridge) { reg_rax(emu) = 0; return; }
    const uint64_t handle = reg_rcx(emu);
    const void* buf = reinterpret_cast<const void*>(reg_rdx(emu));
    const uint32_t nbytes = static_cast<uint32_t>(reg_r8(emu));
    auto* out_written = reinterpret_cast<uint32_t*>(reg_r9(emu));
    const auto* ov = reinterpret_cast<const win32::Win64Overlapped*>(stack_arg(emu, 0));
    reg_rax(emu) = bridge->files().write_file(handle, buf, nbytes, out_written, ov) ? 1ULL : 0ULL;
}

void thunk_FlushFileBuffers(x64emu_t* emu) {
    auto* bridge = Box64Bridge::instance();
    reg_rax(emu) = (bridge && bridge->files().flush_file(reg_rcx(emu))) ? 1ULL : 0ULL;
}

void thunk_ReadFile(x64emu_t* emu) {
    auto* bridge = Box64Bridge::instance();
    if (!bridge) { reg_rax(emu) = 0; return; }
    const uint64_t handle = reg_rcx(emu);
    void* buf = reinterpret_cast<void*>(reg_rdx(emu));
    const uint32_t nbytes = static_cast<uint32_t>(reg_r8(emu));
    auto* out_read = reinterpret_cast<uint32_t*>(reg_r9(emu));
    const auto* ov = reinterpret_cast<const win32::Win64Overlapped*>(stack_arg(emu, 0));
    reg_rax(emu) = bridge->files().read_file(handle, buf, nbytes, out_read, ov) ? 1ULL : 0ULL;
}

void thunk_SetFilePointerEx(x64emu_t* emu) {
    auto* bridge = Box64Bridge::instance();
    if (!bridge) { reg_rax(emu) = 0; return; }
    const uint64_t handle = reg_rcx(emu);
    const int64_t dist = static_cast<int64_t>(reg_rdx(emu));
    auto* new_pos = reinterpret_cast<int64_t*>(reg_r8(emu));
    const uint32_t method = static_cast<uint32_t>(reg_r9(emu));
    reg_rax(emu) = bridge->files().seek_file(handle, dist, method, new_pos) ? 1ULL : 0ULL;
}

void thunk_GetFileSizeEx(x64emu_t* emu) {
    auto* bridge = Box64Bridge::instance();
    if (!bridge) { reg_rax(emu) = 0; return; }
    const uint64_t handle = reg_rcx(emu);
    auto* out_sz = reinterpret_cast<int64_t*>(reg_rdx(emu));
    reg_rax(emu) = bridge->files().get_file_size(handle, out_sz) ? 1ULL : 0ULL;
}

void thunk_CloseHandle(x64emu_t* emu) {
    auto* bridge = Box64Bridge::instance();
    if (!bridge) { reg_rax(emu) = 0; return; }
    const uint64_t h = reg_rcx(emu);
    if (bridge->events().is_event_handle(h)) {
        reg_rax(emu) = bridge->events().close(h) ? 1ULL : 0ULL;
    } else if (bridge->threads().is_thread_handle(h)) {
        reg_rax(emu) = bridge->threads().close(h) ? 1ULL : 0ULL;
    } else {
        reg_rax(emu) = bridge->files().close_handle(h) ? 1ULL : 0ULL;
    }
}

// --- Process Heap (MSVC CRT / malloc backing) ---

void thunk_GetProcessHeap(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    reg_rax(emu) = b ? b->heap().handle() : 0ULL;
}

void thunk_HeapAlloc(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    if (!b) { reg_rax(emu) = 0; return; }
    const uint32_t flags = static_cast<uint32_t>(reg_rdx(emu));
    const size_t bytes = static_cast<size_t>(reg_r8(emu));
    reg_rax(emu) = b->heap().alloc(bytes, (flags & 0x08u) != 0); // HEAP_ZERO_MEMORY
}

void thunk_HeapReAlloc(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    if (!b) { reg_rax(emu) = 0; return; }
    const uint32_t flags = static_cast<uint32_t>(reg_rdx(emu));
    const uintptr_t old_ptr = static_cast<uintptr_t>(reg_r8(emu));
    const size_t bytes = static_cast<size_t>(reg_r9(emu));
    reg_rax(emu) = b->heap().realloc(old_ptr, bytes, (flags & 0x08u) != 0);
}

void thunk_HeapFree(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    if (!b) { reg_rax(emu) = 0; return; }
    reg_rax(emu) = b->heap().free(static_cast<uintptr_t>(reg_r8(emu))) ? 1ULL : 0ULL;
}

void thunk_HeapSize(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    if (!b) { reg_rax(emu) = ~0ULL; return; }
    reg_rax(emu) = b->heap().size_of(static_cast<uintptr_t>(reg_r8(emu)));
}

// --- Events & Wait ---

void thunk_CreateEventW(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    if (!b) { reg_rax(emu) = 0; return; }
    const bool manual_reset = reg_rdx(emu) != 0;
    const bool initial_state = reg_r8(emu) != 0;
    reg_rax(emu) = b->events().create_event(manual_reset, initial_state);
}

void thunk_SetEvent(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    reg_rax(emu) = (b && b->events().set_event(reg_rcx(emu))) ? 1ULL : 0ULL;
}

void thunk_ResetEvent(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    reg_rax(emu) = (b && b->events().reset_event(reg_rcx(emu))) ? 1ULL : 0ULL;
}

void thunk_WaitForSingleObject(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    if (!b) { reg_rax(emu) = win32::EventTable::kWaitFailed; return; }
    const uint64_t h = reg_rcx(emu);
    const uint32_t ms = static_cast<uint32_t>(reg_rdx(emu));
    if (b->threads().is_thread_handle(h)) {
        reg_rax(emu) = b->threads().wait_single(h, ms);
    } else {
        reg_rax(emu) = b->events().wait_single(h, ms);
    }
}

void thunk_CreateThread(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    if (!b || !b->arena()) { reg_rax(emu) = 0; return; }
    const uintptr_t start_pc = static_cast<uintptr_t>(reg_r8(emu));
    const uintptr_t param = static_cast<uintptr_t>(reg_r9(emu));
    auto* out_tid = reinterpret_cast<uint32_t*>(stack_arg(emu, 1)); // arg6: lpThreadId
    reg_rax(emu) = b->threads().create_thread(
        b->arena(), b->main_module_base(), start_pc, param, out_tid);
}

void thunk_WaitOnAddress(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    if (!b) { reg_rax(emu) = 0; return; }
    const auto* addr = reinterpret_cast<const volatile void*>(reg_rcx(emu));
    const auto* cmp  = reinterpret_cast<const void*>(reg_rdx(emu));
    const size_t sz  = static_cast<size_t>(reg_r8(emu));
    const uint32_t ms = static_cast<uint32_t>(reg_r9(emu));
    reg_rax(emu) = b->addr_wait().wait_on_address(addr, cmp, sz, ms) ? 1ULL : 0ULL;
}

void thunk_WakeByAddressSingle(x64emu_t* emu) {
    if (auto* b = Box64Bridge::instance()) {
        b->addr_wait().wake_single(reinterpret_cast<const void*>(reg_rcx(emu)));
    }
}

void thunk_WakeByAddressAll(x64emu_t* emu) {
    if (auto* b = Box64Bridge::instance()) {
        b->addr_wait().wake_all(reinterpret_cast<const void*>(reg_rcx(emu)));
    }
}

// --- Audio (XAudio2.7 & XAudio2.9 COM -> Android AAudio low-latency bridge) ---

void thunk_XAudio2Create_27(x64emu_t* emu) {
    auto** out_xa2 = reinterpret_cast<void**>(reg_rcx(emu));
    const int32_t hr = mobiro::audio::create_xaudio2_com(out_xa2, /*legacy_2_7=*/true);
    reg_rax(emu) = static_cast<uint64_t>(static_cast<uint32_t>(hr));
}

void thunk_XAudio2Create_29(x64emu_t* emu) {
    auto** out_xa2 = reinterpret_cast<void**>(reg_rcx(emu));
    const int32_t hr = mobiro::audio::create_xaudio2_com(out_xa2, /*legacy_2_7=*/false);
    reg_rax(emu) = static_cast<uint64_t>(static_cast<uint32_t>(hr));
}

// --- Critical Sections, Time, Sleep & MSVC CRT Startup ---

void thunk_InitializeCriticalSection(x64emu_t* emu) {
    if (auto* b = Box64Bridge::instance()) b->crit_sections().initialize(static_cast<uintptr_t>(reg_rcx(emu)));
    reg_rax(emu) = 1ULL; // Also serves InitializeCriticalSectionAndSpinCount / Ex (returns BOOL TRUE)
}
void thunk_EnterCriticalSection(x64emu_t* emu) {
    if (auto* b = Box64Bridge::instance()) b->crit_sections().enter(static_cast<uintptr_t>(reg_rcx(emu)));
}
void thunk_TryEnterCriticalSection(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    reg_rax(emu) = (b && b->crit_sections().try_enter(static_cast<uintptr_t>(reg_rcx(emu)))) ? 1ULL : 0ULL;
}
void thunk_LeaveCriticalSection(x64emu_t* emu) {
    if (auto* b = Box64Bridge::instance()) b->crit_sections().leave(static_cast<uintptr_t>(reg_rcx(emu)));
}
void thunk_DeleteCriticalSection(x64emu_t* emu) {
    if (auto* b = Box64Bridge::instance()) b->crit_sections().destroy(static_cast<uintptr_t>(reg_rcx(emu)));
}

void thunk_GetSystemTimeAsFileTime(x64emu_t* emu) {
    auto* out = reinterpret_cast<uint64_t*>(reg_rcx(emu));
    if (!out) return;
    constexpr uint64_t kEpochDiff100ns = 116444736000000000ULL; // 1601-01-01 -> 1970-01-01
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const uint64_t ticks = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(now).count() / 100);
    *out = ticks + kEpochDiff100ns;
}

void thunk_GetTickCount64(x64emu_t* emu) {
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    reg_rax(emu) = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

void thunk_Sleep(x64emu_t* emu) {
    const uint32_t ms = static_cast<uint32_t>(reg_rcx(emu));
    if (ms == 0) std::this_thread::yield();
    else std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

void thunk_SwitchToThread(x64emu_t* emu) {
    std::this_thread::yield();
    reg_rax(emu) = 1ULL;
}

void thunk_GetCommandLineW(x64emu_t* emu) {
    static const uint16_t kCmdW[] = {'"','S','e','k','i','r','o','.','e','x','e','"', 0};
    reg_rax(emu) = reinterpret_cast<uintptr_t>(kCmdW);
}

void thunk_GetCommandLineA(x64emu_t* emu) {
    static const char kCmdA[] = "\"Sekiro.exe\"";
    reg_rax(emu) = reinterpret_cast<uintptr_t>(kCmdA);
}

void thunk_GetStartupInfoW(x64emu_t* emu) {
    auto* out = reinterpret_cast<uint8_t*>(reg_rcx(emu));
    if (!out) return;
    std::memset(out, 0, 104); // sizeof(STARTUPINFOW) on Win64
    const uint32_t cb = 104;
    std::memcpy(out, &cb, sizeof(cb));
}

void thunk_IsProcessorFeaturePresent(x64emu_t* emu) {
    const uint32_t feat = static_cast<uint32_t>(reg_rcx(emu));
    // Advertise standard x86_64 baseline features translated by Box64 Dynarec
    switch (feat) {
        case 6:  // PF_XMMI_INSTRUCTIONS_AVAILABLE (SSE)
        case 8:  // PF_RDTSC_INSTRUCTION_AVAILABLE
        case 10: // PF_XMMI64_INSTRUCTIONS_AVAILABLE (SSE2)
        case 13: // PF_SSE3_INSTRUCTIONS_AVAILABLE
        case 14: // PF_COMPARE_EXCHANGE128
        case 23: // PF_FASTFAIL_AVAILABLE
        case 36: // PF_SSSE3_INSTRUCTIONS_AVAILABLE
        case 37: // PF_SSE4_1_INSTRUCTIONS_AVAILABLE
        case 38: // PF_SSE4_2_INSTRUCTIONS_AVAILABLE
            reg_rax(emu) = 1ULL;
            return;
        default:
            reg_rax(emu) = 0ULL;
            return;
    }
}

// --- Error state, SystemInfo & SEH Unwind ---

void thunk_GetLastError(x64emu_t* emu) {
    auto* teb = current_teb(emu);
    reg_rax(emu) = teb ? teb->last_error : 0ULL;
}

void thunk_SetLastError(x64emu_t* emu) {
    auto* teb = current_teb(emu);
    if (teb) teb->last_error = static_cast<uint32_t>(reg_rcx(emu));
}

void thunk_GetSystemInfo(x64emu_t* emu) {
    auto* out = reinterpret_cast<win32::Win64SystemInfo*>(reg_rcx(emu));
    if (!out) return;
    win32::Win64SystemInfo si{};
    if (auto* teb = current_teb(emu)) {
        if (teb->peb_ptr) {
            const auto* peb = reinterpret_cast<const Win64Peb*>(teb->peb_ptr);
            si.number_of_processors = peb->number_of_processors;
            si.active_processor_mask = (peb->number_of_processors >= 64)
                ? ~0ULL
                : ((1ULL << peb->number_of_processors) - 1ULL);
        }
    }
    *out = si;
}

void thunk_RtlLookupFunctionEntry(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    if (!b) { reg_rax(emu) = 0; return; }
    const uintptr_t control_pc = static_cast<uintptr_t>(reg_rcx(emu));
    auto* out_image_base = reinterpret_cast<uintptr_t*>(reg_rdx(emu));
    const auto* entry = b->seh().lookup(control_pc, out_image_base);
    reg_rax(emu) = reinterpret_cast<uintptr_t>(entry);
}

// --- Sync, Timing, TLS & Process Metadata ---

void thunk_InitializeSRWLock(x64emu_t* emu) {
    auto* p = reinterpret_cast<uint64_t*>(reg_rcx(emu));
    if (p) *p = 0;
}
void thunk_AcquireSRWLockExclusive(x64emu_t* emu) {
    if (auto* b = Box64Bridge::instance()) b->srw_locks().acquire_exclusive(static_cast<uintptr_t>(reg_rcx(emu)));
}
void thunk_ReleaseSRWLockExclusive(x64emu_t* emu) {
    if (auto* b = Box64Bridge::instance()) b->srw_locks().release_exclusive(static_cast<uintptr_t>(reg_rcx(emu)));
}
void thunk_AcquireSRWLockShared(x64emu_t* emu) {
    if (auto* b = Box64Bridge::instance()) b->srw_locks().acquire_shared(static_cast<uintptr_t>(reg_rcx(emu)));
}
void thunk_ReleaseSRWLockShared(x64emu_t* emu) {
    if (auto* b = Box64Bridge::instance()) b->srw_locks().release_shared(static_cast<uintptr_t>(reg_rcx(emu)));
}

void thunk_QueryPerformanceCounter(x64emu_t* emu) {
    auto* out = reinterpret_cast<int64_t*>(reg_rcx(emu));
    if (!out) { reg_rax(emu) = 0; return; }
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    *out = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count() / 100; // 10 MHz QPC ticks
    reg_rax(emu) = 1;
}

void thunk_QueryPerformanceFrequency(x64emu_t* emu) {
    auto* out = reinterpret_cast<int64_t*>(reg_rcx(emu));
    if (!out) { reg_rax(emu) = 0; return; }
    *out = 10'000'000LL; // 10 MHz standard Windows QPC frequency
    reg_rax(emu) = 1;
}

void thunk_TlsAlloc(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    reg_rax(emu) = b ? b->alloc_tls_slot() : 0xFFFFFFFFULL;
}

void thunk_TlsSetValue(x64emu_t* emu) {
    auto* teb = current_teb(emu);
    const uint32_t idx = static_cast<uint32_t>(reg_rcx(emu));
    if (!teb || idx >= 64) { reg_rax(emu) = 0; return; }
    teb->tls_slots[idx] = reg_rdx(emu);
    reg_rax(emu) = 1;
}

void thunk_TlsGetValue(x64emu_t* emu) {
    auto* teb = current_teb(emu);
    const uint32_t idx = static_cast<uint32_t>(reg_rcx(emu));
    reg_rax(emu) = (teb && idx < 64) ? teb->tls_slots[idx] : 0ULL;
}

void thunk_GetCurrentThreadId(x64emu_t* emu) {
    auto* teb = current_teb(emu);
    reg_rax(emu) = teb ? teb->unique_thread : 1ULL;
}

void thunk_GetCurrentProcessId(x64emu_t* emu) {
    auto* teb = current_teb(emu);
    reg_rax(emu) = teb ? teb->unique_process : 1000ULL;
}

uintptr_t load_library_common(Box64Bridge* b, const std::string& name, x64emu_t* emu) {
    if (!b || name.empty()) return 0;
    if (const uintptr_t existing = b->modules().find_module(name)) return existing;

    // 1. Try loading a guest x86_64 DLL from the BYOF directory
    std::string host_path;
    if (b->vfs() && b->arena() && b->vfs()->resolve(name, host_path)) {
        auto img = PeLoader::load_pe64(host_path, *b->arena(), *b, /*force_relocate=*/true);
        if (img.ok) {
            if (img.pdata_va && img.pdata_size) {
                b->seh().register_image(img.mapped_base, img.pdata_va, img.pdata_size);
            }
            b->modules().register_guest_module(
                name, img.mapped_base, img.image_size,
                std::move(img.exports_by_name), std::move(img.exports_by_ordinal));
            if (const auto* tenv = b->main_thread_env()) {
                GuestExecutor::run_tls_callbacks(img, *tenv);
                if (img.entry_point) {
                    GuestExecutor::call_guest_fn(img.entry_point, img.mapped_base, 1ULL, 0ULL, *tenv);
                }
            }
            return img.mapped_base;
        }
    }

    // 2. Fall back to synthetic HMODULE for built-in native-thunked Win32 DLLs
    if (b->has_dll_thunks(name)) {
        return b->modules().get_or_register_native(name);
    }

    if (auto* teb = current_teb(emu)) teb->last_error = 126u; // ERROR_MOD_NOT_FOUND
    return 0;
}

void thunk_GetModuleHandleW(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    if (!b) { reg_rax(emu) = 0; return; }
    const uint64_t name_ptr = reg_rcx(emu);
    if (name_ptr == 0) {
        reg_rax(emu) = b->main_module_base();
        return;
    }
    const std::string name = win32::utf16le_to_utf8(reinterpret_cast<const uint16_t*>(name_ptr));
    if (const uintptr_t found = b->modules().find_module(name)) {
        reg_rax(emu) = found;
        return;
    }
    reg_rax(emu) = b->has_dll_thunks(name) ? b->modules().get_or_register_native(name) : 0ULL;
}

void thunk_GetModuleHandleA(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    if (!b) { reg_rax(emu) = 0; return; }
    const auto* name_ptr = reinterpret_cast<const char*>(reg_rcx(emu));
    if (!name_ptr) {
        reg_rax(emu) = b->main_module_base();
        return;
    }
    if (const uintptr_t found = b->modules().find_module(name_ptr)) {
        reg_rax(emu) = found;
        return;
    }
    reg_rax(emu) = b->has_dll_thunks(name_ptr) ? b->modules().get_or_register_native(name_ptr) : 0ULL;
}

void thunk_LoadLibraryW(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    const std::string name = win32::utf16le_to_utf8(reinterpret_cast<const uint16_t*>(reg_rcx(emu)));
    reg_rax(emu) = load_library_common(b, name, emu);
}

void thunk_LoadLibraryA(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    const auto* s = reinterpret_cast<const char*>(reg_rcx(emu));
    reg_rax(emu) = s ? load_library_common(b, s, emu) : 0ULL;
}

void thunk_FreeLibrary(x64emu_t* emu) {
    reg_rax(emu) = (reg_rcx(emu) != 0) ? 1ULL : 0ULL;
}

void thunk_GetProcAddress(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    if (!b) { reg_rax(emu) = 0; return; }
    const uintptr_t hmod = static_cast<uintptr_t>(reg_rcx(emu));
    const auto* sym_ptr = reinterpret_cast<const char*>(reg_rdx(emu));
    if (!hmod || !sym_ptr) { reg_rax(emu) = 0; return; }

    if (win32::ModuleRegistry::is_native_handle(hmod)) {
        std::string dll_name;
        if (!b->modules().native_name_for_handle(hmod, dll_name)) {
            reg_rax(emu) = 0;
            return;
        }
        const uintptr_t raw = reinterpret_cast<uintptr_t>(sym_ptr);
        const std::string sym = (raw < 0x10000ULL) ? ("#" + std::to_string(raw)) : std::string(sym_ptr);
        reg_rax(emu) = b->resolve_import(dll_name, sym);
        return;
    }
    reg_rax(emu) = b->modules().resolve_guest_export(hmod, sym_ptr);
}

// --- Headless user32 Window & Message Pump ---

void thunk_RegisterClassEx(x64emu_t* emu) { reg_rax(emu) = 0xC001ULL; }
void thunk_CreateWindowEx(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    if (b) {
        auto surf = mobiro::gfx::DxvkInterop::global().surface();
        if (surf.width > 0 && surf.height > 0) {
            b->window().set_dimensions(surf.width, surf.height);
        }
    }
    reg_rax(emu) = win32::HeadlessWindowState::kMainHwnd;
}
void thunk_ReturnTrue(x64emu_t* emu) { reg_rax(emu) = 1ULL; }
void thunk_ReturnZero(x64emu_t* emu) { reg_rax(emu) = 0ULL; }
void thunk_GetClientRect(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    auto* out = reinterpret_cast<win32::Win32Rect*>(reg_rdx(emu));
    if (!b || !out) { reg_rax(emu) = 0; return; }
    *out = b->window().client_rect();
    reg_rax(emu) = 1ULL;
}
void thunk_GetSystemMetrics(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    const int idx = static_cast<int>(reg_rcx(emu));
    const auto r = b ? b->window().client_rect() : win32::Win32Rect{};
    if (idx == 0) reg_rax(emu) = static_cast<uint64_t>(r.right);       // SM_CXSCREEN
    else if (idx == 1) reg_rax(emu) = static_cast<uint64_t>(r.bottom); // SM_CYSCREEN
    else reg_rax(emu) = 0ULL;
}
void thunk_PeekMessage(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    auto* out = reinterpret_cast<win32::Win64Msg*>(reg_rcx(emu));
    const uint32_t remove_flag = static_cast<uint32_t>(stack_arg(emu, 0)); // arg5: wRemoveMsg
    reg_rax(emu) = (b && b->window().peek_message(out, (remove_flag & 1u) != 0)) ? 1ULL : 0ULL;
}
void thunk_PostQuitMessage(x64emu_t* emu) {
    if (auto* b = Box64Bridge::instance()) {
        b->window().post_quit(static_cast<int32_t>(reg_rcx(emu)));
    }
}

// --- shell32 / ole32 / winmm / bcrypt ---

void thunk_SHGetKnownFolderPath(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    auto** out_path = reinterpret_cast<uint16_t**>(reg_r9(emu));
    if (!b || !out_path) { reg_rax(emu) = 0x80070057ULL; return; }
    static const uint16_t kAppData[] = {
        'C',':','\\','U','s','e','r','s','\\','M','o','b','i','r','o','\\',
        'A','p','p','D','a','t','a','\\','R','o','a','m','i','n','g', 0
    };
    const uintptr_t mem = b->heap().alloc(sizeof(kAppData), true);
    if (!mem) { reg_rax(emu) = 0x8007000EULL; return; } // E_OUTOFMEMORY
    std::memcpy(reinterpret_cast<void*>(mem), kAppData, sizeof(kAppData));
    *out_path = reinterpret_cast<uint16_t*>(mem);
    reg_rax(emu) = 0ULL; // S_OK
}

void thunk_SHGetFolderPathW(x64emu_t* emu) {
    auto* out_buf = reinterpret_cast<uint16_t*>(stack_arg(emu, 0)); // arg5: pszPath (MAX_PATH)
    if (!out_buf) { reg_rax(emu) = 0x80070057ULL; return; }
    static const uint16_t kAppData[] = {
        'C',':','\\','U','s','e','r','s','\\','M','o','b','i','r','o','\\',
        'A','p','p','D','a','t','a','\\','R','o','a','m','i','n','g', 0
    };
    std::memcpy(out_buf, kAppData, sizeof(kAppData));
    reg_rax(emu) = 0ULL; // S_OK
}

void thunk_CoTaskMemAlloc(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    reg_rax(emu) = b ? b->heap().alloc(static_cast<size_t>(reg_rcx(emu)), false) : 0ULL;
}

void thunk_CoTaskMemFree(x64emu_t* emu) {
    if (auto* b = Box64Bridge::instance()) b->heap().free(static_cast<uintptr_t>(reg_rcx(emu)));
}

void thunk_timeGetTime(x64emu_t* emu) {
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    reg_rax(emu) = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

void thunk_BCryptGenRandom(x64emu_t* emu) {
    auto* buf = reinterpret_cast<uint8_t*>(reg_rdx(emu));
    const uint32_t len = static_cast<uint32_t>(reg_r8(emu));
    if (!buf && len > 0) { reg_rax(emu) = 0xC000000DULL; return; } // STATUS_INVALID_PARAMETER
    std::random_device rd;
    for (uint32_t i = 0; i < len; ) {
        const uint32_t v = rd();
        for (int b = 0; b < 4 && i < len; ++b, ++i) {
            buf[i] = static_cast<uint8_t>((v >> (b * 8)) & 0xFFu);
        }
    }
    reg_rax(emu) = 0ULL; // STATUS_SUCCESS
}

// --- Extended Win32 FS / Locale / Memory / Process / Registry / DirectInput8 ---

void thunk_GetFileAttributesW(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    const std::string path = win32::utf16le_to_utf8(reinterpret_cast<const uint16_t*>(reg_rcx(emu)));
    std::string host;
    if (!b || !b->vfs() || !b->vfs()->resolve(path, host)) {
        reg_rax(emu) = 0xFFFFFFFFULL; // INVALID_FILE_ATTRIBUTES
        return;
    }
    std::error_code ec;
    reg_rax(emu) = std::filesystem::is_directory(host, ec) ? 0x10ULL : 0x80ULL;
}

void thunk_GetFileAttributesA(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    const auto* s = reinterpret_cast<const char*>(reg_rcx(emu));
    std::string host;
    if (!b || !b->vfs() || !s || !b->vfs()->resolve(s, host)) {
        reg_rax(emu) = 0xFFFFFFFFULL;
        return;
    }
    std::error_code ec;
    reg_rax(emu) = std::filesystem::is_directory(host, ec) ? 0x10ULL : 0x80ULL;
}

void thunk_CreateDirectoryW(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    const std::string path = win32::utf16le_to_utf8(reinterpret_cast<const uint16_t*>(reg_rcx(emu)));
    std::string host;
    if (!b || !b->vfs() || !b->vfs()->resolve_for_write(path, host)) {
        reg_rax(emu) = 0ULL;
        return;
    }
    std::error_code ec;
    std::filesystem::create_directories(host, ec);
    reg_rax(emu) = ec ? 0ULL : 1ULL;
}

void thunk_GetModuleFileNameW(x64emu_t* emu) {
    auto* dst = reinterpret_cast<uint16_t*>(reg_rdx(emu));
    const uint32_t cap = static_cast<uint32_t>(reg_r8(emu));
    static const uint16_t kExeW[] = {
        'C',':','\\','S','e','k','i','r','o','\\','S','e','k','i','r','o','.','e','x','e', 0
    };
    constexpr uint32_t kLen = 20;
    if (!dst || cap == 0) { reg_rax(emu) = 0; return; }
    const uint32_t n = std::min<uint32_t>(kLen, cap - 1);
    std::memcpy(dst, kExeW, n * sizeof(uint16_t));
    dst[n] = 0;
    reg_rax(emu) = n;
}

void thunk_GetModuleFileNameA(x64emu_t* emu) {
    auto* dst = reinterpret_cast<char*>(reg_rdx(emu));
    const uint32_t cap = static_cast<uint32_t>(reg_r8(emu));
    static const char kExeA[] = "C:\\Sekiro\\Sekiro.exe";
    constexpr uint32_t kLen = 20;
    if (!dst || cap == 0) { reg_rax(emu) = 0; return; }
    const uint32_t n = std::min<uint32_t>(kLen, cap - 1);
    std::memcpy(dst, kExeA, n);
    dst[n] = '\0';
    reg_rax(emu) = n;
}

void thunk_MultiByteToWideChar(x64emu_t* emu) {
    const auto* src = reinterpret_cast<const uint8_t*>(reg_r8(emu));
    const int cb = static_cast<int>(reg_r9(emu));
    auto* dst = reinterpret_cast<uint16_t*>(stack_arg(emu, 0));
    const int cch = static_cast<int>(stack_arg(emu, 1));
    if (!src) { reg_rax(emu) = 0; return; }
    const size_t slen = (cb < 0) ? (std::strlen(reinterpret_cast<const char*>(src)) + 1) : static_cast<size_t>(cb);
    std::vector<uint16_t> tmp;
    tmp.reserve(slen);
    for (size_t i = 0; i < slen; ++i) {
        const uint8_t c = src[i];
        if (c < 0x80) {
            tmp.push_back(c);
        } else if ((c & 0xE0) == 0xC0 && i + 1 < slen) {
            tmp.push_back(static_cast<uint16_t>(((c & 0x1F) << 6) | (src[i + 1] & 0x3F)));
            ++i;
        } else if ((c & 0xF0) == 0xE0 && i + 2 < slen) {
            tmp.push_back(static_cast<uint16_t>(
                ((c & 0x0F) << 12) | ((src[i + 1] & 0x3F) << 6) | (src[i + 2] & 0x3F)));
            i += 2;
        } else {
            tmp.push_back(c);
        }
    }
    if (cch == 0 || !dst) { reg_rax(emu) = tmp.size(); return; }
    const size_t n = std::min<size_t>(tmp.size(), static_cast<size_t>(cch));
    std::memcpy(dst, tmp.data(), n * sizeof(uint16_t));
    reg_rax(emu) = n;
}

void thunk_WideCharToMultiByte(x64emu_t* emu) {
    const auto* src = reinterpret_cast<const uint16_t*>(reg_r8(emu));
    const int cch = static_cast<int>(reg_r9(emu));
    auto* dst = reinterpret_cast<char*>(stack_arg(emu, 0));
    const int cb = static_cast<int>(stack_arg(emu, 1));
    if (!src) { reg_rax(emu) = 0; return; }
    size_t wlen = 0;
    if (cch < 0) {
        while (src[wlen] != 0) ++wlen;
        ++wlen;
    } else {
        wlen = static_cast<size_t>(cch);
    }
    std::string out;
    out.reserve(wlen);
    for (size_t i = 0; i < wlen; ++i) {
        const uint16_t c = src[i];
        if (c < 0x80) {
            out.push_back(static_cast<char>(c));
        } else if (c < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (c >> 6)));
            out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xE0 | (c >> 12)));
            out.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        }
    }
    if (cb == 0 || !dst) { reg_rax(emu) = out.size(); return; }
    const size_t n = std::min<size_t>(out.size(), static_cast<size_t>(cb));
    std::memcpy(dst, out.data(), n);
    reg_rax(emu) = n;
}

void thunk_GlobalMemoryStatusEx(x64emu_t* emu) {
    auto* out = reinterpret_cast<win32::MemoryStatusEx*>(reg_rcx(emu));
    if (!out || out->length < sizeof(win32::MemoryStatusEx)) { reg_rax(emu) = 0; return; }
    win32::MemoryStatusEx ms{};
    *out = ms;
    reg_rax(emu) = 1ULL;
}

void thunk_EncodeDecodePointer(x64emu_t* emu) {
    constexpr uint64_t kCookie = 0x5A3C96A51E2D3B4FULL;
    reg_rax(emu) = reg_rcx(emu) ^ kCookie;
}

void thunk_SetThreadAffinityMask(x64emu_t* emu) { reg_rax(emu) = 0xFFULL; }
void thunk_RegNotFound(x64emu_t* emu) { reg_rax(emu) = 2ULL; } // ERROR_FILE_NOT_FOUND

void thunk_DirectInput8Create(x64emu_t* emu) {
    auto** out_di = reinterpret_cast<void**>(reg_r9(emu));
    const int32_t hr = win32::create_dinput8_com(out_di);
    reg_rax(emu) = static_cast<uint64_t>(static_cast<uint32_t>(hr));
}

// --- M11: Condition Variables, Semaphores, WaitForMultipleObjects & MSVC CRT/ntdll ---

void thunk_InitializeConditionVariable(x64emu_t* emu) {
    auto* p = reinterpret_cast<uint64_t*>(reg_rcx(emu));
    if (p) *p = 0;
}

void thunk_SleepConditionVariableSRW(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    if (!b) { reg_rax(emu) = 0; return; }
    const bool shared = (static_cast<uint32_t>(reg_r9(emu)) & 1u) != 0; // CONDITION_VARIABLE_LOCKMODE_SHARED
    const bool ok = b->cond_vars().sleep_srw(
        static_cast<uintptr_t>(reg_rcx(emu)), b->srw_locks(),
        static_cast<uintptr_t>(reg_rdx(emu)), static_cast<uint32_t>(reg_r8(emu)), shared);
    if (!ok) {
        if (auto* teb = current_teb(emu)) teb->last_error = 1460u; // ERROR_TIMEOUT
    }
    reg_rax(emu) = ok ? 1ULL : 0ULL;
}

void thunk_SleepConditionVariableCS(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    if (!b) { reg_rax(emu) = 0; return; }
    const bool ok = b->cond_vars().sleep_cs(
        static_cast<uintptr_t>(reg_rcx(emu)), b->crit_sections(),
        static_cast<uintptr_t>(reg_rdx(emu)), static_cast<uint32_t>(reg_r8(emu)));
    if (!ok) {
        if (auto* teb = current_teb(emu)) teb->last_error = 1460u;
    }
    reg_rax(emu) = ok ? 1ULL : 0ULL;
}

void thunk_WakeConditionVariable(x64emu_t* emu) {
    if (auto* b = Box64Bridge::instance()) b->cond_vars().wake_one(static_cast<uintptr_t>(reg_rcx(emu)));
}

void thunk_WakeAllConditionVariable(x64emu_t* emu) {
    if (auto* b = Box64Bridge::instance()) b->cond_vars().wake_all(static_cast<uintptr_t>(reg_rcx(emu)));
}

void thunk_CreateSemaphore(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    if (!b) { reg_rax(emu) = 0; return; }
    reg_rax(emu) = b->events().create_semaphore(
        static_cast<int32_t>(reg_rdx(emu)), static_cast<int32_t>(reg_r8(emu)));
}

void thunk_ReleaseSemaphore(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    if (!b) { reg_rax(emu) = 0; return; }
    auto* prev = reinterpret_cast<int32_t*>(reg_r8(emu));
    reg_rax(emu) = b->events().release_semaphore(
        reg_rcx(emu), static_cast<int32_t>(reg_rdx(emu)), prev) ? 1ULL : 0ULL;
}

void thunk_WaitForMultipleObjects(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    const uint32_t count = static_cast<uint32_t>(reg_rcx(emu));
    const auto* handles = reinterpret_cast<const uint64_t*>(reg_rdx(emu));
    const bool wait_all = (reg_r8(emu) != 0);
    const uint32_t timeout_ms = static_cast<uint32_t>(reg_r9(emu));
    if (!b || !handles || count == 0 || count > 64) {
        reg_rax(emu) = win32::EventTable::kWaitFailed;
        return;
    }
    if (wait_all) {
        for (uint32_t i = 0; i < count; ++i) {
            const uint32_t r = b->threads().is_thread_handle(handles[i])
                ? b->threads().wait_single(handles[i], timeout_ms)
                : b->events().wait_single(handles[i], timeout_ms);
            if (r != win32::EventTable::kWaitObject0) { reg_rax(emu) = r; return; }
        }
        reg_rax(emu) = win32::EventTable::kWaitObject0;
        return;
    }
    const auto deadline = (timeout_ms == win32::EventTable::kInfinite)
        ? std::chrono::steady_clock::time_point::max()
        : (std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms));
    for (;;) {
        for (uint32_t i = 0; i < count; ++i) {
            const uint32_t r = b->threads().is_thread_handle(handles[i])
                ? b->threads().wait_single(handles[i], 0)
                : b->events().wait_single(handles[i], 0);
            if (r == win32::EventTable::kWaitObject0) { reg_rax(emu) = i; return; }
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            reg_rax(emu) = win32::EventTable::kWaitTimeout;
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

void thunk_GetCurrentProcess(x64emu_t* emu) { reg_rax(emu) = ~0ULL; }
void thunk_GetCurrentThread(x64emu_t* emu)  { reg_rax(emu) = ~1ULL; }
void thunk_GetStdHandle(x64emu_t* emu)      { reg_rax(emu) = 0x10ULL + (reg_rcx(emu) & 0xFFULL); }
void thunk_GetFileType(x64emu_t* emu)       { reg_rax(emu) = 2ULL; } // FILE_TYPE_CHAR
void thunk_GetACP(x64emu_t* emu)            { reg_rax(emu) = 65001ULL; } // CP_UTF8
void thunk_GetCPInfo(x64emu_t* emu) {
    auto* out = reinterpret_cast<uint8_t*>(reg_rdx(emu));
    if (!out) { reg_rax(emu) = 0; return; }
    std::memset(out, 0, 20); // sizeof(CPINFO)
    const uint32_t max_char = 4;
    std::memcpy(out, &max_char, 4);
    out[4] = '?';
    reg_rax(emu) = 1ULL;
}
void thunk_GetEnvironmentStringsW(x64emu_t* emu) {
    static const uint16_t kEmptyEnv[2] = {0, 0};
    reg_rax(emu) = reinterpret_cast<uintptr_t>(kEmptyEnv);
}
void thunk_GetEnvironmentVariableW(x64emu_t* emu) {
    if (auto* teb = current_teb(emu)) teb->last_error = 203u; // ERROR_ENVVAR_NOT_FOUND
    reg_rax(emu) = 0ULL;
}
void thunk_GetModuleHandleExW(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    auto* out_mod = reinterpret_cast<uintptr_t*>(reg_r8(emu));
    if (!b || !out_mod) { reg_rax(emu) = 0; return; }
    const uint32_t flags = static_cast<uint32_t>(reg_rcx(emu));
    const uint64_t name_or_addr = reg_rdx(emu);
    if ((flags & 0x04u) != 0 || name_or_addr == 0) { // GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
        *out_mod = b->main_module_base();
        reg_rax(emu) = (*out_mod != 0) ? 1ULL : 0ULL;
        return;
    }
    const std::string name = win32::utf16le_to_utf8(reinterpret_cast<const uint16_t*>(name_or_addr));
    uintptr_t h = b->modules().find_module(name);
    if (!h && b->has_dll_thunks(name)) h = b->modules().get_or_register_native(name);
    *out_mod = h;
    reg_rax(emu) = (h != 0) ? 1ULL : 0ULL;
}
void thunk_GetProcessAffinityMask(x64emu_t* emu) {
    auto* proc_mask = reinterpret_cast<uint64_t*>(reg_rdx(emu));
    auto* sys_mask  = reinterpret_cast<uint64_t*>(reg_r8(emu));
    if (proc_mask) *proc_mask = 0xFFULL;
    if (sys_mask)  *sys_mask  = 0xFFULL;
    reg_rax(emu) = 1ULL;
}
void thunk_DeleteFileW(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    const std::string path = win32::utf16le_to_utf8(reinterpret_cast<const uint16_t*>(reg_rcx(emu)));
    std::string host;
    // Only deletes inside writable save overlay (never mutates read-only BYOF directory)
    if (!b || !b->vfs() || !b->vfs()->resolve_for_write(path, host)) { reg_rax(emu) = 0; return; }
    std::error_code ec;
    const bool removed = std::filesystem::remove(host, ec);
    b->vfs()->erase_overlay_entry(path);
    reg_rax(emu) = removed ? 1ULL : 0ULL;
}
void thunk_MoveFileExW(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    const std::string src_p = win32::utf16le_to_utf8(reinterpret_cast<const uint16_t*>(reg_rcx(emu)));
    const std::string dst_p = win32::utf16le_to_utf8(reinterpret_cast<const uint16_t*>(reg_rdx(emu)));
    std::string src_h, dst_h;
    if (!b || !b->vfs() || !b->vfs()->resolve(src_p, src_h) || !b->vfs()->resolve_for_write(dst_p, dst_h)) {
        reg_rax(emu) = 0;
        return;
    }
    std::error_code ec;
    std::filesystem::rename(src_h, dst_h, ec);
    if (ec) {
        ec.clear();
        std::filesystem::copy_file(src_h, dst_h, std::filesystem::copy_options::overwrite_existing, ec);
    } else {
        b->vfs()->erase_overlay_entry(src_p);
    }
    reg_rax(emu) = ec ? 0ULL : 1ULL;
}
void thunk_GetCurrentDirectoryW(x64emu_t* emu) {
    const uint32_t cap = static_cast<uint32_t>(reg_rcx(emu));
    auto* dst = reinterpret_cast<uint16_t*>(reg_rdx(emu));
    static const uint16_t kDirW[] = {'C',':','\\','S','e','k','i','r','o', 0};
    constexpr uint32_t kLen = 9;
    if (!dst || cap <= kLen) { reg_rax(emu) = kLen + 1; return; }
    std::memcpy(dst, kDirW, (kLen + 1) * sizeof(uint16_t));
    reg_rax(emu) = kLen;
}
void thunk_GetTempPathW(x64emu_t* emu) {
    const uint32_t cap = static_cast<uint32_t>(reg_rcx(emu));
    auto* dst = reinterpret_cast<uint16_t*>(reg_rdx(emu));
    static const uint16_t kTmpW[] = {'C',':','\\','T','e','m','p','\\', 0};
    constexpr uint32_t kLen = 8;
    if (!dst || cap <= kLen) { reg_rax(emu) = kLen + 1; return; }
    std::memcpy(dst, kTmpW, (kLen + 1) * sizeof(uint16_t));
    reg_rax(emu) = kLen;
}

// --- M13: Mutexes, Display/Monitor Info, Locale & FindFirstFileW ---

void thunk_CreateMutex(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    if (!b) { reg_rax(emu) = 0; return; }
    // Model non-recursive Win32 mutex cleanly as a binary semaphore (initial = !bInitialOwner)
    const bool initial_owner = (reg_rdx(emu) != 0);
    reg_rax(emu) = b->events().create_semaphore(initial_owner ? 0 : 1, 1);
}

void thunk_ReleaseMutex(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    reg_rax(emu) = (b && b->events().release_semaphore(reg_rcx(emu), 1, nullptr)) ? 1ULL : 0ULL;
}

void thunk_DuplicateHandle(x64emu_t* emu) {
    auto* out_h = reinterpret_cast<uint64_t*>(reg_r9(emu));
    if (!out_h) { reg_rax(emu) = 0; return; }
    *out_h = reg_rdx(emu); // Share same table handle id
    reg_rax(emu) = 1ULL;
}

void thunk_MonitorFromWindow(x64emu_t* emu) { reg_rax(emu) = 1ULL; } // Primary HMONITOR

void thunk_GetMonitorInfoW(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    auto* out = reinterpret_cast<uint8_t*>(reg_rdx(emu));
    if (!b || !out) { reg_rax(emu) = 0; return; }
    uint32_t cb = 0;
    std::memcpy(&cb, out, 4);
    if (cb < 40) { reg_rax(emu) = 0; return; }
    const auto r = b->window().client_rect();
    std::memcpy(out + 4, &r, sizeof(r));   // rcMonitor
    std::memcpy(out + 20, &r, sizeof(r));  // rcWork
    const uint32_t flags = 1u;             // MONITORINFOF_PRIMARY
    std::memcpy(out + 36, &flags, 4);
    if (cb >= 104) {
        static const uint16_t kDisp[] = {'\\','\\','.','\\','D','I','S','P','L','A','Y','1', 0};
        std::memcpy(out + 40, kDisp, sizeof(kDisp));
    }
    reg_rax(emu) = 1ULL;
}

void thunk_EnumDisplaySettingsW(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    auto* dm = reinterpret_cast<uint8_t*>(reg_r8(emu));
    if (!b || !dm) { reg_rax(emu) = 0; return; }
    const auto r = b->window().client_rect();
    const uint32_t bpp = 32, w = static_cast<uint32_t>(r.right), h = static_cast<uint32_t>(r.bottom), hz = 60;
    // DEVMODEW offsets: dmBitsPerPel=168, dmPelsWidth=172, dmPelsHeight=176, dmDisplayFrequency=184
    std::memcpy(dm + 168, &bpp, 4);
    std::memcpy(dm + 172, &w, 4);
    std::memcpy(dm + 176, &h, 4);
    std::memcpy(dm + 184, &hz, 4);
    reg_rax(emu) = 1ULL;
}

void thunk_FindFirstFileW(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    const std::string pattern = win32::utf16le_to_utf8(reinterpret_cast<const uint16_t*>(reg_rcx(emu)));
    auto* out = reinterpret_cast<uint8_t*>(reg_rdx(emu));
    std::string host;
    if (!b || !b->vfs() || !out || !b->vfs()->resolve(pattern, host)) {
        if (auto* teb = current_teb(emu)) teb->last_error = 2u; // ERROR_FILE_NOT_FOUND
        reg_rax(emu) = win32::FileHandleTable::kInvalidHandle;
        return;
    }
    std::memset(out, 0, 592); // sizeof(WIN32_FIND_DATAW)
    std::error_code ec;
    const uint32_t attrs = std::filesystem::is_directory(host, ec) ? 0x10u : 0x80u;
    std::memcpy(out, &attrs, 4);
    const uint64_t fsz = std::filesystem::is_regular_file(host, ec)
        ? static_cast<uint64_t>(std::filesystem::file_size(host, ec)) : 0ULL;
    const uint32_t sz_hi = static_cast<uint32_t>(fsz >> 32);
    const uint32_t sz_lo = static_cast<uint32_t>(fsz & 0xFFFFFFFFu);
    std::memcpy(out + 28, &sz_hi, 4);
    std::memcpy(out + 32, &sz_lo, 4);
    const std::string fname = std::filesystem::path(host).filename().string();
    auto* cfile = reinterpret_cast<uint16_t*>(out + 44);
    const size_t n = std::min<size_t>(fname.size(), 259);
    for (size_t i = 0; i < n; ++i) cfile[i] = static_cast<uint8_t>(fname[i]);
    cfile[n] = 0;
    reg_rax(emu) = 0x00090001ULL; // Synthetic single-entry find handle
}

void thunk_FindNextFileW(x64emu_t* emu) {
    if (auto* teb = current_teb(emu)) teb->last_error = 18u; // ERROR_NO_MORE_FILES
    reg_rax(emu) = 0ULL;
}

// --- M14: Native ARM64 NEON-backed CRT & ntdll bulk memory/string thunks ---

void thunk_memcpy(x64emu_t* emu) {
    void* dst = reinterpret_cast<void*>(reg_rcx(emu));
    const void* src = reinterpret_cast<const void*>(reg_rdx(emu));
    const size_t n = static_cast<size_t>(reg_r8(emu));
    if (dst && src && n) std::memcpy(dst, src, n);
    reg_rax(emu) = reg_rcx(emu);
}

void thunk_memmove(x64emu_t* emu) {
    void* dst = reinterpret_cast<void*>(reg_rcx(emu));
    const void* src = reinterpret_cast<const void*>(reg_rdx(emu));
    const size_t n = static_cast<size_t>(reg_r8(emu));
    if (dst && src && n) std::memmove(dst, src, n);
    reg_rax(emu) = reg_rcx(emu);
}

void thunk_memset(x64emu_t* emu) {
    void* dst = reinterpret_cast<void*>(reg_rcx(emu));
    const int val = static_cast<int>(reg_rdx(emu) & 0xFFu);
    const size_t n = static_cast<size_t>(reg_r8(emu));
    if (dst && n) std::memset(dst, val, n);
    reg_rax(emu) = reg_rcx(emu);
}

void thunk_memcmp(x64emu_t* emu) {
    const void* a = reinterpret_cast<const void*>(reg_rcx(emu));
    const void* b = reinterpret_cast<const void*>(reg_rdx(emu));
    const size_t n = static_cast<size_t>(reg_r8(emu));
    const int cmp = (a && b && n) ? std::memcmp(a, b, n) : 0;
    reg_rax(emu) = static_cast<uint64_t>(static_cast<int64_t>(cmp));
}

void thunk_RtlZeroMemory(x64emu_t* emu) {
    void* dst = reinterpret_cast<void*>(reg_rcx(emu));
    const size_t n = static_cast<size_t>(reg_rdx(emu));
    if (dst && n) std::memset(dst, 0, n);
    reg_rax(emu) = 0ULL;
}

void thunk_RtlFillMemory(x64emu_t* emu) {
    void* dst = reinterpret_cast<void*>(reg_rcx(emu));
    const size_t n = static_cast<size_t>(reg_rdx(emu));
    const int val = static_cast<int>(reg_r8(emu) & 0xFFu);
    if (dst && n) std::memset(dst, val, n);
    reg_rax(emu) = 0ULL;
}

void thunk_strlen(x64emu_t* emu) {
    const char* s = reinterpret_cast<const char*>(reg_rcx(emu));
    reg_rax(emu) = s ? static_cast<uint64_t>(std::strlen(s)) : 0ULL;
}

void thunk_wcslen(x64emu_t* emu) {
    const auto* s = reinterpret_cast<const uint16_t*>(reg_rcx(emu));
    size_t len = 0;
    if (s) {
        while (s[len] != 0) ++len;
    }
    reg_rax(emu) = static_cast<uint64_t>(len);
}

void thunk_strcmp(x64emu_t* emu) {
    const char* a = reinterpret_cast<const char*>(reg_rcx(emu));
    const char* b = reinterpret_cast<const char*>(reg_rdx(emu));
    const int cmp = (a && b) ? std::strcmp(a, b) : 0;
    reg_rax(emu) = static_cast<uint64_t>(static_cast<int64_t>(cmp));
}

void thunk_strncmp(x64emu_t* emu) {
    const char* a = reinterpret_cast<const char*>(reg_rcx(emu));
    const char* b = reinterpret_cast<const char*>(reg_rdx(emu));
    const size_t n = static_cast<size_t>(reg_r8(emu));
    const int cmp = (a && b && n) ? std::strncmp(a, b, n) : 0;
    reg_rax(emu) = static_cast<uint64_t>(static_cast<int64_t>(cmp));
}

// --- M16: Sekiro / MSVC CRT / Oodle / Bink2 InitOnce, SList, Time, Query & XInputCaps shims ---

std::mutex g_slist_mu;

void thunk_InitializeSListHead(x64emu_t* emu) {
    auto* hdr = reinterpret_cast<uint64_t*>(reg_rcx(emu));
    if (hdr) { hdr[0] = 0; hdr[1] = 0; }
    reg_rax(emu) = 0ULL;
}

void thunk_InterlockedPushEntrySList(x64emu_t* emu) {
    auto* hdr = reinterpret_cast<uint64_t*>(reg_rcx(emu));
    auto* entry = reinterpret_cast<uint64_t*>(reg_rdx(emu));
    if (!hdr || !entry) { reg_rax(emu) = 0ULL; return; }
    std::lock_guard<std::mutex> lk(g_slist_mu);
    const uint64_t prev = hdr[0];
    entry[0] = prev;
    hdr[0] = reinterpret_cast<uint64_t>(entry);
    ++hdr[1];
    reg_rax(emu) = prev;
}

void thunk_InterlockedPopEntrySList(x64emu_t* emu) {
    auto* hdr = reinterpret_cast<uint64_t*>(reg_rcx(emu));
    if (!hdr) { reg_rax(emu) = 0ULL; return; }
    std::lock_guard<std::mutex> lk(g_slist_mu);
    auto* head = reinterpret_cast<uint64_t*>(hdr[0]);
    if (!head) { reg_rax(emu) = 0ULL; return; }
    hdr[0] = head[0];
    if (hdr[1] > 0) --hdr[1];
    reg_rax(emu) = reinterpret_cast<uint64_t>(head);
}

void thunk_InterlockedFlushSList(x64emu_t* emu) {
    auto* hdr = reinterpret_cast<uint64_t*>(reg_rcx(emu));
    if (!hdr) { reg_rax(emu) = 0ULL; return; }
    std::lock_guard<std::mutex> lk(g_slist_mu);
    const uint64_t head = hdr[0];
    hdr[0] = 0;
    hdr[1] = 0;
    reg_rax(emu) = head;
}

void thunk_QueryDepthSList(x64emu_t* emu) {
    auto* hdr = reinterpret_cast<const uint64_t*>(reg_rcx(emu));
    if (!hdr) { reg_rax(emu) = 0ULL; return; }
    std::lock_guard<std::mutex> lk(g_slist_mu);
    reg_rax(emu) = hdr[1] & 0xFFFFULL;
}

std::mutex g_init_once_mu;
std::condition_variable g_init_once_cv;

void thunk_InitOnceInitialize(x64emu_t* emu) {
    auto* once = reinterpret_cast<uint64_t*>(reg_rcx(emu));
    if (once) *once = 0ULL;
    reg_rax(emu) = 0ULL;
}

// BOOL InitOnceBeginInitialize(LPINIT_ONCE, DWORD dwFlags, PBOOL fPending, LPVOID* lpContext)
void thunk_InitOnceBeginInitialize(x64emu_t* emu) {
    auto* once = reinterpret_cast<uint64_t*>(reg_rcx(emu));
    const uint32_t flags = static_cast<uint32_t>(reg_rdx(emu));
    auto* pending = reinterpret_cast<uint32_t*>(reg_r8(emu));
    auto** ctx = reinterpret_cast<void**>(reg_r9(emu));
    if (!once || !pending) { reg_rax(emu) = 0ULL; return; }

    std::unique_lock<std::mutex> lk(g_init_once_mu);
    while ((*once & 3ULL) == 1ULL) { // in-progress
        if (flags & 1u) { *pending = 0; reg_rax(emu) = 0ULL; return; } // INIT_ONCE_CHECK_ONLY
        g_init_once_cv.wait(lk);
    }
    if ((*once & 3ULL) == 2ULL) { // completed
        *pending = 0;
        if (ctx) *ctx = reinterpret_cast<void*>(*once & ~3ULL);
        reg_rax(emu) = 1ULL;
        return;
    }
    if (flags & 1u) { *pending = 0; reg_rax(emu) = 0ULL; return; }
    *once = 1ULL;
    *pending = 1;
    reg_rax(emu) = 1ULL;
}

// BOOL InitOnceComplete(LPINIT_ONCE, DWORD dwFlags, LPVOID lpContext)
void thunk_InitOnceComplete(x64emu_t* emu) {
    auto* once = reinterpret_cast<uint64_t*>(reg_rcx(emu));
    const uint32_t flags = static_cast<uint32_t>(reg_rdx(emu));
    const uint64_t ctx = reg_r8(emu);
    if (!once) { reg_rax(emu) = 0ULL; return; }
    {
        std::lock_guard<std::mutex> lk(g_init_once_mu);
        if (flags & 4u) { // INIT_ONCE_INIT_FAILED
            *once = 0ULL;
        } else {
            *once = (ctx & ~3ULL) | 2ULL;
        }
    }
    g_init_once_cv.notify_all();
    reg_rax(emu) = 1ULL;
}

void thunk_GetSystemOrLocalTime(x64emu_t* emu) {
    auto* st = reinterpret_cast<uint16_t*>(reg_rcx(emu));
    if (!st) { reg_rax(emu) = 0ULL; return; }
    const auto now = std::chrono::system_clock::now();
    const std::time_t tt = std::chrono::system_clock::to_time_t(now);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count() % 1000;
    std::tm tm_val{};
#if defined(_WIN32)
    gmtime_s(&tm_val, &tt);
#else
    gmtime_r(&tt, &tm_val);
#endif
    st[0] = static_cast<uint16_t>(tm_val.tm_year + 1900);
    st[1] = static_cast<uint16_t>(tm_val.tm_mon + 1);
    st[2] = static_cast<uint16_t>(tm_val.tm_wday);
    st[3] = static_cast<uint16_t>(tm_val.tm_mday);
    st[4] = static_cast<uint16_t>(tm_val.tm_hour);
    st[5] = static_cast<uint16_t>(tm_val.tm_min);
    st[6] = static_cast<uint16_t>(tm_val.tm_sec);
    st[7] = static_cast<uint16_t>(ms < 0 ? 0 : ms);
    reg_rax(emu) = 0ULL;
}

void thunk_GetTickCount32(x64emu_t* emu) {
    thunk_GetTickCount64(emu);
    reg_rax(emu) &= 0xFFFFFFFFULL;
}

void thunk_GetFileInformationByHandle(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    const uint64_t h = reg_rcx(emu);
    auto* info = reinterpret_cast<uint8_t*>(reg_rdx(emu));
    if (!b || !info) { reg_rax(emu) = 0ULL; return; }
    int64_t sz = 0;
    if (!b->files().get_file_size(h, &sz)) { reg_rax(emu) = 0ULL; return; }
    std::memset(info, 0, 52);
    const uint32_t attrs = 0x80u; // FILE_ATTRIBUTE_NORMAL
    const uint32_t sz_hi = static_cast<uint32_t>(static_cast<uint64_t>(sz) >> 32);
    const uint32_t sz_lo = static_cast<uint32_t>(static_cast<uint64_t>(sz) & 0xFFFFFFFFULL);
    const uint32_t nlinks = 1u;
    std::memcpy(info + 0, &attrs, 4);
    std::memcpy(info + 32, &sz_hi, 4);
    std::memcpy(info + 36, &sz_lo, 4);
    std::memcpy(info + 40, &nlinks, 4);
    reg_rax(emu) = 1ULL;
}

void thunk_VirtualQuery(x64emu_t* emu) {
    const uint64_t addr = reg_rcx(emu) & ~0xFFFULL;
    auto* mbi = reinterpret_cast<uint64_t*>(reg_rdx(emu));
    const size_t len = static_cast<size_t>(reg_r8(emu));
    if (!mbi || len < 48) { reg_rax(emu) = 0ULL; return; }
    std::memset(mbi, 0, 48);
    mbi[0] = addr;             // BaseAddress
    mbi[1] = addr;             // AllocationBase
    mbi[2] = 0x04ULL;          // AllocationProtect = PAGE_READWRITE
    mbi[3] = 0x10000ULL;       // RegionSize (64 KiB)
    const uint32_t state = 0x1000u;   // MEM_COMMIT
    const uint32_t prot  = 0x04u;     // PAGE_READWRITE
    const uint32_t type  = 0x20000u;  // MEM_PRIVATE
    auto* mbi32 = reinterpret_cast<uint32_t*>(mbi + 4);
    mbi32[0] = state;
    mbi32[1] = prot;
    mbi32[2] = type;
    reg_rax(emu) = 48ULL;
}

void thunk_GetLocaleEnUs(x64emu_t* emu) { reg_rax(emu) = 0x0409ULL; } // en-US LCID / LANGID

void thunk_XInputGetCapabilities(x64emu_t* emu) {
    const uint32_t user_idx = static_cast<uint32_t>(reg_rcx(emu));
    auto* caps = reinterpret_cast<uint8_t*>(reg_r8(emu));
    if (user_idx != 0 || !caps) {
        reg_rax(emu) = 1167ULL; // ERROR_DEVICE_NOT_CONNECTED
        return;
    }
    std::memset(caps, 0, 20);
    caps[0] = 1u; // XINPUT_DEVTYPE_GAMEPAD
    caps[1] = 1u; // XINPUT_DEVSUBTYPE_GAMEPAD
    reg_rax(emu) = 0ULL; // ERROR_SUCCESS
}

// --- Input ---

void thunk_XInputGetState(x64emu_t* emu) {
    const uint32_t user_idx = static_cast<uint32_t>(reg_rcx(emu));
    auto* out = reinterpret_cast<mobiro::input::XInputState*>(reg_rdx(emu));
    if (user_idx != 0 || !out) {
        reg_rax(emu) = 1167ULL; // ERROR_DEVICE_NOT_CONNECTED
        return;
    }
    *out = mobiro::input::InputRouter::global().snapshot();
    reg_rax(emu) = 0ULL; // ERROR_SUCCESS
}

void thunk_XInputSetState(x64emu_t* emu) {
    const uint32_t user_idx = static_cast<uint32_t>(reg_rcx(emu));
    reg_rax(emu) = (user_idx == 0) ? 0ULL : 1167ULL;
}

// --- Graphics (MS x64 ABI -> Native ARM64 DXVK Interop) ---

// HRESULT D3D11CreateDevice(
//   RCX: pAdapter, RDX: DriverType, R8: Software, R9: Flags,
//   [RSP+0x28]: pFeatureLevels, [RSP+0x30]: FeatureLevels, [RSP+0x38]: SDKVersion,
//   [RSP+0x40]: ppDevice, [RSP+0x48]: pFeatureLevel, [RSP+0x50]: ppImmediateContext)
void thunk_D3D11CreateDevice(x64emu_t* emu) {
    auto& com                = mobiro::gfx::D3D11ComBridge::global();
    auto* adapter            = reinterpret_cast<void*>(com.unwrap_arg(reg_rcx(emu)));
    const auto driver_type   = static_cast<uint32_t>(reg_rdx(emu));
    auto* software           = reinterpret_cast<void*>(reg_r8(emu));
    const auto flags         = static_cast<uint32_t>(reg_r9(emu));
    const auto* feat_levels  = reinterpret_cast<const uint32_t*>(stack_arg(emu, 0));
    const auto num_levels    = static_cast<uint32_t>(stack_arg(emu, 1));
    const auto sdk_version   = static_cast<uint32_t>(stack_arg(emu, 2));
    auto** out_device        = reinterpret_cast<void**>(stack_arg(emu, 3));
    auto* out_level          = reinterpret_cast<uint32_t*>(stack_arg(emu, 4));
    auto** out_context       = reinterpret_cast<void**>(stack_arg(emu, 5));

    const auto& dxvk = mobiro::gfx::DxvkInterop::global();
    const int32_t hr = dxvk.call_d3d11_create_device(
        adapter, driver_type, software, flags,
        feat_levels, num_levels, sdk_version,
        out_device, out_level, out_context);
    if (hr == 0 && dxvk.auto_wrap_com()) {
        if (out_device && *out_device) {
            *out_device = com.wrap(*out_device, mobiro::gfx::d3d11_abi::ComIfaceId::D3D11Device);
        }
        if (out_context && *out_context) {
            *out_context = com.wrap(*out_context, mobiro::gfx::d3d11_abi::ComIfaceId::D3D11DeviceContext);
        }
    }
    reg_rax(emu) = static_cast<uint64_t>(static_cast<uint32_t>(hr));
}

// HRESULT D3D11CreateDeviceAndSwapChain (12 args: 4 regs + 8 stack args)
void thunk_D3D11CreateDeviceAndSwapChain(x64emu_t* emu) {
    auto& com                = mobiro::gfx::D3D11ComBridge::global();
    auto* adapter            = reinterpret_cast<void*>(com.unwrap_arg(reg_rcx(emu)));
    const auto driver_type   = static_cast<uint32_t>(reg_rdx(emu));
    auto* software           = reinterpret_cast<void*>(reg_r8(emu));
    const auto flags         = static_cast<uint32_t>(reg_r9(emu));
    const auto* feat_levels  = reinterpret_cast<const uint32_t*>(stack_arg(emu, 0));
    const auto num_levels    = static_cast<uint32_t>(stack_arg(emu, 1));
    const auto sdk_version   = static_cast<uint32_t>(stack_arg(emu, 2));
    const auto* sc_desc      = reinterpret_cast<const void*>(stack_arg(emu, 3));
    auto** out_swap_chain    = reinterpret_cast<void**>(stack_arg(emu, 4));
    auto** out_device        = reinterpret_cast<void**>(stack_arg(emu, 5));
    auto* out_level          = reinterpret_cast<uint32_t*>(stack_arg(emu, 6));
    auto** out_context       = reinterpret_cast<void**>(stack_arg(emu, 7));

    const auto& dxvk = mobiro::gfx::DxvkInterop::global();
    const int32_t hr = dxvk.call_d3d11_create_device_and_swap_chain(
        adapter, driver_type, software, flags,
        feat_levels, num_levels, sdk_version,
        sc_desc, out_swap_chain, out_device, out_level, out_context);
    if (hr == 0 && dxvk.auto_wrap_com()) {
        if (out_swap_chain && *out_swap_chain) {
            *out_swap_chain = com.wrap(*out_swap_chain, mobiro::gfx::d3d11_abi::ComIfaceId::DXGISwapChain);
        }
        if (out_device && *out_device) {
            *out_device = com.wrap(*out_device, mobiro::gfx::d3d11_abi::ComIfaceId::D3D11Device);
        }
        if (out_context && *out_context) {
            *out_context = com.wrap(*out_context, mobiro::gfx::d3d11_abi::ComIfaceId::D3D11DeviceContext);
        }
    }
    reg_rax(emu) = static_cast<uint64_t>(static_cast<uint32_t>(hr));
}

// HRESULT CreateDXGIFactory1(RCX: REFIID riid, RDX: void** ppFactory)
void thunk_CreateDXGIFactory1(x64emu_t* emu) {
    const auto* riid  = reinterpret_cast<const void*>(reg_rcx(emu));
    auto** out_factory = reinterpret_cast<void**>(reg_rdx(emu));
    const auto& dxvk = mobiro::gfx::DxvkInterop::global();
    const int32_t hr = dxvk.call_create_dxgi_factory1(riid, out_factory);
    if (hr == 0 && dxvk.auto_wrap_com() && out_factory && *out_factory) {
        *out_factory = mobiro::gfx::D3D11ComBridge::global().wrap(
            *out_factory, mobiro::gfx::d3d11_abi::ComIfaceId::DXGIFactory1);
    }
    reg_rax(emu) = static_cast<uint64_t>(static_cast<uint32_t>(hr));
}

} // namespace

bool Box64Bridge::initialize(mem::GuestArena* arena, validator::VfsMapper* vfs) {
    arena_ = arena;
    vfs_ = vfs;
    g_instance_ = this;
    next_tls_slot_ = 0;

#if defined(__linux__) || defined(__ANDROID__)
    stub_pool_ = static_cast<NativeBridgeStub*>(
        mmap(nullptr, kMaxStubs * sizeof(NativeBridgeStub),
             PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    if (stub_pool_ == MAP_FAILED) {
        stub_pool_ = nullptr;
        return false;
    }
#else
    stub_pool_ = new NativeBridgeStub[kMaxStubs];
#endif
    stub_count_ = 0;
    heap_.initialize(arena_, 32 * 1024 * 1024);
    threads_.set_env_dispatch_callback(
        [](uintptr_t start_pc, uintptr_t param, const Win64ThreadEnv& env) -> uint32_t {
            auto r = GuestExecutor::call_guest_fn(start_pc, param, 0ULL, 0ULL, env);
            return static_cast<uint32_t>(r.exit_rax);
        });
    register_default_win32_thunks();
    return true;
}

void Box64Bridge::shutdown() {
    threads_.join_all();
    files_.close_all();
    srw_locks_.clear();
    crit_sections_.clear();
    cond_vars_.clear();
    events_.clear();
    modules_.clear();
    window_.clear();
    heap_.reset();
    {
        std::lock_guard<std::mutex> lk(unresolved_mu_);
        interned_unresolved_.clear();
        unresolved_stub_cache_.clear();
        called_unresolved_.clear();
    }
    if (stub_pool_) {
#if defined(__linux__) || defined(__ANDROID__)
        munmap(stub_pool_, kMaxStubs * sizeof(NativeBridgeStub));
#else
        delete[] stub_pool_;
#endif
        stub_pool_ = nullptr;
    }
    thunks_.clear();
    if (g_instance_ == this) g_instance_ = nullptr;
}

void Box64Bridge::register_thunk(const std::string& dll_lower, const std::string& symbol, NativeThunkFn fn) {
    thunks_[validator::VfsMapper::normalize(dll_lower) + "!" + symbol] = fn;
}

uintptr_t Box64Bridge::resolve_import(const std::string& dll_lower, const std::string& symbol) {
    auto it = thunks_.find(validator::VfsMapper::normalize(dll_lower) + "!" + symbol);
    if (it == thunks_.end() || !stub_pool_ || stub_count_ >= kMaxStubs) return 0;

    NativeBridgeStub& stub = stub_pool_[stub_count_++];
    stub = NativeBridgeStub{};
    stub.wrapper_ptr = reinterpret_cast<uint64_t>(&mobiro_native_thunk_wrapper);
    stub.thunk_ptr = reinterpret_cast<uint64_t>(it->second);
    return reinterpret_cast<uintptr_t>(&stub);
}

extern "C" void mobiro_unresolved_import_wrapper(x64emu_t* emu, uintptr_t name_ptr) {
    const char* name = reinterpret_cast<const char*>(name_ptr);
    if (auto* b = Box64Bridge::instance()) {
        b->record_unresolved_call(name);
    }
#if defined(__ANDROID__)
    __android_log_print(ANDROID_LOG_WARN, "Mobiro", "Unresolved Win32 import called: %s (returning 0)",
                        name ? name : "<unknown>");
#endif
    if (emu) emu_reg_rax(emu) = 0ULL;
}

uintptr_t Box64Bridge::resolve_unresolved_trap(const std::string& dll_lower, const std::string& symbol) {
    if (!stub_pool_) return 0;
    const std::string key = validator::VfsMapper::normalize(dll_lower) + "!" + symbol;
    std::lock_guard<std::mutex> lk(unresolved_mu_);
    if (auto it = unresolved_stub_cache_.find(key); it != unresolved_stub_cache_.end()) {
        return it->second;
    }
    if (stub_count_ >= kMaxStubs) return 0;

    interned_unresolved_.push_back(key);
    const char* stable_name = interned_unresolved_.back().c_str();
    NativeBridgeStub& stub = stub_pool_[stub_count_++];
    stub = NativeBridgeStub{};
    stub.wrapper_ptr = reinterpret_cast<uint64_t>(&mobiro_unresolved_import_wrapper);
    stub.thunk_ptr = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(stable_name));
    stub.name_or_func = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(stable_name));
    const uintptr_t addr = reinterpret_cast<uintptr_t>(&stub);
    unresolved_stub_cache_[key] = addr;
    return addr;
}

void Box64Bridge::record_unresolved_call(const char* sym_name) {
    if (!sym_name) return;
    std::lock_guard<std::mutex> lk(unresolved_mu_);
    for (const auto& s : called_unresolved_) {
        if (s == sym_name) return;
    }
    called_unresolved_.emplace_back(sym_name);
}

std::vector<std::string> Box64Bridge::called_unresolved_imports() const {
    std::lock_guard<std::mutex> lk(unresolved_mu_);
    return called_unresolved_;
}

bool Box64Bridge::invoke_thunk(const std::string& dll_lower, const std::string& symbol, x64emu_t* emu) const {
    auto it = thunks_.find(validator::VfsMapper::normalize(dll_lower) + "!" + symbol);
    if (it == thunks_.end() || !emu) return false;
    it->second(emu);
    return true;
}

void Box64Bridge::register_default_win32_thunks() {
    // Memory
    register_thunk("kernel32.dll", "VirtualAlloc", &thunk_VirtualAlloc);
    register_thunk("kernel32.dll", "VirtualFree", &thunk_VirtualFree);
    register_thunk("kernel32.dll", "VirtualProtect", &thunk_VirtualProtect);

    // File I/O
    register_thunk("kernel32.dll", "CreateFileW", &thunk_CreateFileW);
    register_thunk("kernel32.dll", "CreateFileA", &thunk_CreateFileA);
    register_thunk("kernel32.dll", "ReadFile", &thunk_ReadFile);
    register_thunk("kernel32.dll", "WriteFile", &thunk_WriteFile);
    register_thunk("kernel32.dll", "FlushFileBuffers", &thunk_FlushFileBuffers);
    register_thunk("kernel32.dll", "SetFilePointerEx", &thunk_SetFilePointerEx);
    register_thunk("kernel32.dll", "GetFileSizeEx", &thunk_GetFileSizeEx);
    register_thunk("kernel32.dll", "CloseHandle", &thunk_CloseHandle);

    // Sync, Timing, TLS & Process
    register_thunk("kernel32.dll", "InitializeSRWLock", &thunk_InitializeSRWLock);
    register_thunk("kernel32.dll", "AcquireSRWLockExclusive", &thunk_AcquireSRWLockExclusive);
    register_thunk("kernel32.dll", "ReleaseSRWLockExclusive", &thunk_ReleaseSRWLockExclusive);
    register_thunk("kernel32.dll", "AcquireSRWLockShared", &thunk_AcquireSRWLockShared);
    register_thunk("kernel32.dll", "ReleaseSRWLockShared", &thunk_ReleaseSRWLockShared);
    register_thunk("kernel32.dll", "QueryPerformanceCounter", &thunk_QueryPerformanceCounter);
    register_thunk("kernel32.dll", "QueryPerformanceFrequency", &thunk_QueryPerformanceFrequency);
    register_thunk("kernel32.dll", "TlsAlloc", &thunk_TlsAlloc);
    register_thunk("kernel32.dll", "TlsSetValue", &thunk_TlsSetValue);
    register_thunk("kernel32.dll", "TlsGetValue", &thunk_TlsGetValue);
    register_thunk("kernel32.dll", "GetCurrentThreadId", &thunk_GetCurrentThreadId);
    register_thunk("kernel32.dll", "GetCurrentProcessId", &thunk_GetCurrentProcessId);
    register_thunk("kernel32.dll", "GetModuleHandleW", &thunk_GetModuleHandleW);
    register_thunk("kernel32.dll", "GetModuleHandleA", &thunk_GetModuleHandleA);
    register_thunk("kernel32.dll", "LoadLibraryW", &thunk_LoadLibraryW);
    register_thunk("kernel32.dll", "LoadLibraryA", &thunk_LoadLibraryA);
    register_thunk("kernel32.dll", "LoadLibraryExW", &thunk_LoadLibraryW);
    register_thunk("kernel32.dll", "LoadLibraryExA", &thunk_LoadLibraryA);
    register_thunk("kernel32.dll", "GetProcAddress", &thunk_GetProcAddress);
    register_thunk("kernel32.dll", "FreeLibrary", &thunk_FreeLibrary);
    register_thunk("kernel32.dll", "GetLastError", &thunk_GetLastError);
    register_thunk("kernel32.dll", "SetLastError", &thunk_SetLastError);
    register_thunk("kernel32.dll", "GetSystemInfo", &thunk_GetSystemInfo);

    // Heap & Events
    register_thunk("kernel32.dll", "GetProcessHeap", &thunk_GetProcessHeap);
    register_thunk("kernel32.dll", "HeapAlloc", &thunk_HeapAlloc);
    register_thunk("kernel32.dll", "HeapReAlloc", &thunk_HeapReAlloc);
    register_thunk("kernel32.dll", "HeapFree", &thunk_HeapFree);
    register_thunk("kernel32.dll", "HeapSize", &thunk_HeapSize);
    register_thunk("kernel32.dll", "CreateEventW", &thunk_CreateEventW);
    register_thunk("kernel32.dll", "CreateEventA", &thunk_CreateEventW);
    register_thunk("kernel32.dll", "SetEvent", &thunk_SetEvent);
    register_thunk("kernel32.dll", "ResetEvent", &thunk_ResetEvent);
    register_thunk("kernel32.dll", "WaitForSingleObject", &thunk_WaitForSingleObject);
    register_thunk("kernel32.dll", "CreateThread", &thunk_CreateThread);
    register_thunk("api-ms-win-core-synch-l1-2-0.dll", "WaitOnAddress", &thunk_WaitOnAddress);
    register_thunk("api-ms-win-core-synch-l1-2-0.dll", "WakeByAddressSingle", &thunk_WakeByAddressSingle);
    register_thunk("api-ms-win-core-synch-l1-2-0.dll", "WakeByAddressAll", &thunk_WakeByAddressAll);
    register_thunk("kernelbase.dll", "WaitOnAddress", &thunk_WaitOnAddress);
    register_thunk("kernelbase.dll", "WakeByAddressSingle", &thunk_WakeByAddressSingle);
    register_thunk("kernelbase.dll", "WakeByAddressAll", &thunk_WakeByAddressAll);

    // Critical Sections, Timing & MSVC CRT Startup
    register_thunk("kernel32.dll", "InitializeCriticalSection", &thunk_InitializeCriticalSection);
    register_thunk("kernel32.dll", "InitializeCriticalSectionAndSpinCount", &thunk_InitializeCriticalSection);
    register_thunk("kernel32.dll", "InitializeCriticalSectionEx", &thunk_InitializeCriticalSection);
    register_thunk("kernel32.dll", "EnterCriticalSection", &thunk_EnterCriticalSection);
    register_thunk("kernel32.dll", "TryEnterCriticalSection", &thunk_TryEnterCriticalSection);
    register_thunk("kernel32.dll", "LeaveCriticalSection", &thunk_LeaveCriticalSection);
    register_thunk("kernel32.dll", "DeleteCriticalSection", &thunk_DeleteCriticalSection);
    register_thunk("kernel32.dll", "GetSystemTimeAsFileTime", &thunk_GetSystemTimeAsFileTime);
    register_thunk("kernel32.dll", "GetTickCount64", &thunk_GetTickCount64);
    register_thunk("kernel32.dll", "Sleep", &thunk_Sleep);
    register_thunk("kernel32.dll", "SwitchToThread", &thunk_SwitchToThread);
    register_thunk("kernel32.dll", "GetCommandLineW", &thunk_GetCommandLineW);
    register_thunk("kernel32.dll", "GetCommandLineA", &thunk_GetCommandLineA);
    register_thunk("kernel32.dll", "GetStartupInfoW", &thunk_GetStartupInfoW);
    register_thunk("kernel32.dll", "IsProcessorFeaturePresent", &thunk_IsProcessorFeaturePresent);

    // Audio
    register_thunk("xaudio2_7.dll", "XAudio2Create", &thunk_XAudio2Create_27);
    register_thunk("xaudio2_9.dll", "XAudio2Create", &thunk_XAudio2Create_29);

    // SEH Unwind (ntdll + kernel32 forwarder)
    register_thunk("kernel32.dll", "RtlLookupFunctionEntry", &thunk_RtlLookupFunctionEntry);
    register_thunk("ntdll.dll", "RtlLookupFunctionEntry", &thunk_RtlLookupFunctionEntry);

    // Input
    register_thunk("xinput1_4.dll", "XInputGetState", &thunk_XInputGetState);
    register_thunk("xinput1_3.dll", "XInputGetState", &thunk_XInputGetState);
    register_thunk("xinput1_4.dll", "XInputSetState", &thunk_XInputSetState);
    register_thunk("xinput1_3.dll", "XInputSetState", &thunk_XInputSetState);

    // Graphics
    register_thunk("d3d11.dll", "D3D11CreateDevice", &thunk_D3D11CreateDevice);
    register_thunk("d3d11.dll", "D3D11CreateDeviceAndSwapChain", &thunk_D3D11CreateDeviceAndSwapChain);
    register_thunk("dxgi.dll", "CreateDXGIFactory1", &thunk_CreateDXGIFactory1);
    register_thunk("dxgi.dll", "CreateDXGIFactory2", &thunk_CreateDXGIFactory1);

    // Headless Window / Message Pump (user32)
    register_thunk("user32.dll", "RegisterClassExW", &thunk_RegisterClassEx);
    register_thunk("user32.dll", "RegisterClassExA", &thunk_RegisterClassEx);
    register_thunk("user32.dll", "CreateWindowExW", &thunk_CreateWindowEx);
    register_thunk("user32.dll", "CreateWindowExA", &thunk_CreateWindowEx);
    register_thunk("user32.dll", "ShowWindow", &thunk_ReturnTrue);
    register_thunk("user32.dll", "UpdateWindow", &thunk_ReturnTrue);
    register_thunk("user32.dll", "SetWindowPos", &thunk_ReturnTrue);
    register_thunk("user32.dll", "MoveWindow", &thunk_ReturnTrue);
    register_thunk("user32.dll", "AdjustWindowRectEx", &thunk_ReturnTrue);
    register_thunk("user32.dll", "SetForegroundWindow", &thunk_ReturnTrue);
    register_thunk("user32.dll", "SetFocus", &thunk_CreateWindowEx);
    register_thunk("user32.dll", "ShowCursor", &thunk_ReturnZero);
    register_thunk("user32.dll", "ClipCursor", &thunk_ReturnTrue);
    register_thunk("user32.dll", "GetClientRect", &thunk_GetClientRect);
    register_thunk("user32.dll", "GetWindowRect", &thunk_GetClientRect);
    register_thunk("user32.dll", "GetSystemMetrics", &thunk_GetSystemMetrics);
    register_thunk("user32.dll", "PeekMessageW", &thunk_PeekMessage);
    register_thunk("user32.dll", "PeekMessageA", &thunk_PeekMessage);
    register_thunk("user32.dll", "TranslateMessage", &thunk_ReturnZero);
    register_thunk("user32.dll", "DispatchMessageW", &thunk_ReturnZero);
    register_thunk("user32.dll", "DispatchMessageA", &thunk_ReturnZero);
    register_thunk("user32.dll", "DefWindowProcW", &thunk_ReturnZero);
    register_thunk("user32.dll", "DefWindowProcA", &thunk_ReturnZero);
    register_thunk("user32.dll", "PostQuitMessage", &thunk_PostQuitMessage);

    // Shell / COM / Multimedia Timer / Entropy
    register_thunk("shell32.dll", "SHGetKnownFolderPath", &thunk_SHGetKnownFolderPath);
    register_thunk("shell32.dll", "SHGetFolderPathW", &thunk_SHGetFolderPathW);
    register_thunk("ole32.dll", "CoInitialize", &thunk_ReturnZero);
    register_thunk("ole32.dll", "CoInitializeEx", &thunk_ReturnZero);
    register_thunk("ole32.dll", "CoUninitialize", &thunk_ReturnZero);
    register_thunk("ole32.dll", "CoTaskMemAlloc", &thunk_CoTaskMemAlloc);
    register_thunk("ole32.dll", "CoTaskMemFree", &thunk_CoTaskMemFree);
    register_thunk("winmm.dll", "timeGetTime", &thunk_timeGetTime);
    register_thunk("winmm.dll", "timeBeginPeriod", &thunk_ReturnZero);
    register_thunk("winmm.dll", "timeEndPeriod", &thunk_ReturnZero);
    register_thunk("bcrypt.dll", "BCryptGenRandom", &thunk_BCryptGenRandom);

    // Extended Win32 FS, Encoding, Memory, Process, Registry & DirectInput8
    register_thunk("kernel32.dll", "GetFileAttributesW", &thunk_GetFileAttributesW);
    register_thunk("kernel32.dll", "GetFileAttributesA", &thunk_GetFileAttributesA);
    register_thunk("kernel32.dll", "CreateDirectoryW", &thunk_CreateDirectoryW);
    register_thunk("kernel32.dll", "GetModuleFileNameW", &thunk_GetModuleFileNameW);
    register_thunk("kernel32.dll", "GetModuleFileNameA", &thunk_GetModuleFileNameA);
    register_thunk("kernel32.dll", "MultiByteToWideChar", &thunk_MultiByteToWideChar);
    register_thunk("kernel32.dll", "WideCharToMultiByte", &thunk_WideCharToMultiByte);
    register_thunk("kernel32.dll", "GlobalMemoryStatusEx", &thunk_GlobalMemoryStatusEx);
    register_thunk("kernel32.dll", "EncodePointer", &thunk_EncodeDecodePointer);
    register_thunk("kernel32.dll", "DecodePointer", &thunk_EncodeDecodePointer);
    register_thunk("kernel32.dll", "IsDebuggerPresent", &thunk_ReturnZero);
    register_thunk("kernel32.dll", "OutputDebugStringA", &thunk_ReturnZero);
    register_thunk("kernel32.dll", "OutputDebugStringW", &thunk_ReturnZero);
    register_thunk("kernel32.dll", "SetThreadPriority", &thunk_ReturnTrue);
    register_thunk("kernel32.dll", "SetThreadAffinityMask", &thunk_SetThreadAffinityMask);
    register_thunk("kernel32.dll", "FlsAlloc", &thunk_TlsAlloc);
    register_thunk("kernel32.dll", "FlsSetValue", &thunk_TlsSetValue);
    register_thunk("kernel32.dll", "FlsGetValue", &thunk_TlsGetValue);
    register_thunk("kernel32.dll", "FlsFree", &thunk_ReturnTrue);
    register_thunk("kernel32.dll", "SetUnhandledExceptionFilter", &thunk_ReturnZero);
    register_thunk("advapi32.dll", "RegOpenKeyExW", &thunk_RegNotFound);
    register_thunk("advapi32.dll", "RegOpenKeyExA", &thunk_RegNotFound);
    register_thunk("advapi32.dll", "RegQueryValueExW", &thunk_RegNotFound);
    register_thunk("advapi32.dll", "RegQueryValueExA", &thunk_RegNotFound);
    register_thunk("advapi32.dll", "RegCloseKey", &thunk_ReturnZero);
    register_thunk("dinput8.dll", "DirectInput8Create", &thunk_DirectInput8Create);

    // M11: Condition Variables, Semaphores, WaitForMultipleObjects, MSVC CRT & ntdll
    register_thunk("kernel32.dll", "InitializeConditionVariable", &thunk_InitializeConditionVariable);
    register_thunk("kernel32.dll", "SleepConditionVariableSRW", &thunk_SleepConditionVariableSRW);
    register_thunk("kernel32.dll", "SleepConditionVariableCS", &thunk_SleepConditionVariableCS);
    register_thunk("kernel32.dll", "WakeConditionVariable", &thunk_WakeConditionVariable);
    register_thunk("kernel32.dll", "WakeAllConditionVariable", &thunk_WakeAllConditionVariable);
    register_thunk("ntdll.dll", "RtlInitializeSRWLock", &thunk_InitializeSRWLock);
    register_thunk("ntdll.dll", "RtlAcquireSRWLockExclusive", &thunk_AcquireSRWLockExclusive);
    register_thunk("ntdll.dll", "RtlReleaseSRWLockExclusive", &thunk_ReleaseSRWLockExclusive);
    register_thunk("ntdll.dll", "RtlAcquireSRWLockShared", &thunk_AcquireSRWLockShared);
    register_thunk("ntdll.dll", "RtlReleaseSRWLockShared", &thunk_ReleaseSRWLockShared);
    register_thunk("ntdll.dll", "RtlSleepConditionVariableSRW", &thunk_SleepConditionVariableSRW);
    register_thunk("ntdll.dll", "RtlWakeConditionVariable", &thunk_WakeConditionVariable);
    register_thunk("ntdll.dll", "RtlWakeAllConditionVariable", &thunk_WakeAllConditionVariable);
    register_thunk("kernel32.dll", "CreateSemaphoreW", &thunk_CreateSemaphore);
    register_thunk("kernel32.dll", "CreateSemaphoreA", &thunk_CreateSemaphore);
    register_thunk("kernel32.dll", "ReleaseSemaphore", &thunk_ReleaseSemaphore);
    register_thunk("kernel32.dll", "WaitForMultipleObjects", &thunk_WaitForMultipleObjects);
    register_thunk("kernel32.dll", "GetCurrentProcess", &thunk_GetCurrentProcess);
    register_thunk("kernel32.dll", "GetCurrentThread", &thunk_GetCurrentThread);
    register_thunk("kernel32.dll", "GetProcessAffinityMask", &thunk_GetProcessAffinityMask);
    register_thunk("kernel32.dll", "GetStdHandle", &thunk_GetStdHandle);
    register_thunk("kernel32.dll", "GetFileType", &thunk_GetFileType);
    register_thunk("kernel32.dll", "GetConsoleMode", &thunk_ReturnZero);
    register_thunk("kernel32.dll", "WriteConsoleW", &thunk_ReturnTrue);
    register_thunk("kernel32.dll", "WriteConsoleA", &thunk_ReturnTrue);
    register_thunk("kernel32.dll", "GetACP", &thunk_GetACP);
    register_thunk("kernel32.dll", "GetOEMCP", &thunk_GetACP);
    register_thunk("kernel32.dll", "IsValidCodePage", &thunk_ReturnTrue);
    register_thunk("kernel32.dll", "GetCPInfo", &thunk_GetCPInfo);
    register_thunk("kernel32.dll", "GetEnvironmentStringsW", &thunk_GetEnvironmentStringsW);
    register_thunk("kernel32.dll", "FreeEnvironmentStringsW", &thunk_ReturnTrue);
    register_thunk("kernel32.dll", "GetEnvironmentVariableW", &thunk_GetEnvironmentVariableW);
    register_thunk("kernel32.dll", "GetEnvironmentVariableA", &thunk_GetEnvironmentVariableW);
    register_thunk("kernel32.dll", "GetModuleHandleExW", &thunk_GetModuleHandleExW);
    register_thunk("kernel32.dll", "GetSystemTimePreciseAsFileTime", &thunk_GetSystemTimeAsFileTime);
    register_thunk("kernel32.dll", "HeapSetInformation", &thunk_ReturnTrue);
    register_thunk("kernel32.dll", "HeapQueryInformation", &thunk_ReturnZero);
    register_thunk("kernel32.dll", "DeleteFileW", &thunk_DeleteFileW);
    register_thunk("kernel32.dll", "MoveFileExW", &thunk_MoveFileExW);
    register_thunk("kernel32.dll", "GetCurrentDirectoryW", &thunk_GetCurrentDirectoryW);
    register_thunk("kernel32.dll", "SetCurrentDirectoryW", &thunk_ReturnTrue);
    register_thunk("kernel32.dll", "GetTempPathW", &thunk_GetTempPathW);
    register_thunk("kernel32.dll", "ExitProcess", &thunk_ReturnZero);
    register_thunk("kernel32.dll", "TerminateProcess", &thunk_ReturnTrue);
    register_thunk("ws2_32.dll", "WSAStartup", &thunk_ReturnZero);
    register_thunk("ws2_32.dll", "WSACleanup", &thunk_ReturnZero);

    // M13: Mutexes, Display/Monitor Info, FindFirstFileW & DPI/Thread helpers
    register_thunk("kernel32.dll", "CreateMutexW", &thunk_CreateMutex);
    register_thunk("kernel32.dll", "CreateMutexA", &thunk_CreateMutex);
    register_thunk("kernel32.dll", "ReleaseMutex", &thunk_ReleaseMutex);
    register_thunk("kernel32.dll", "DuplicateHandle", &thunk_DuplicateHandle);
    register_thunk("kernel32.dll", "SetThreadDescription", &thunk_ReturnZero);
    register_thunk("kernel32.dll", "FindFirstFileW", &thunk_FindFirstFileW);
    register_thunk("kernel32.dll", "FindNextFileW", &thunk_FindNextFileW);
    register_thunk("kernel32.dll", "FindClose", &thunk_ReturnTrue);
    register_thunk("user32.dll", "MonitorFromWindow", &thunk_MonitorFromWindow);
    register_thunk("user32.dll", "GetMonitorInfoW", &thunk_GetMonitorInfoW);
    register_thunk("user32.dll", "EnumDisplaySettingsW", &thunk_EnumDisplaySettingsW);
    register_thunk("user32.dll", "SetProcessDPIAware", &thunk_ReturnTrue);
    register_thunk("user32.dll", "GetKeyState", &thunk_ReturnZero);
    register_thunk("user32.dll", "GetAsyncKeyState", &thunk_ReturnZero);

    // M14: Native ARM64 NEON-backed CRT & ntdll bulk memory/string thunks
    const char* crt_dlls[] = {
        "vcruntime140.dll", "ucrtbase.dll", "msvcrt.dll", "api-ms-win-crt-string-l1-1-0.dll"
    };
    for (const char* dll : crt_dlls) {
        register_thunk(dll, "memcpy", &thunk_memcpy);
        register_thunk(dll, "memmove", &thunk_memmove);
        register_thunk(dll, "memset", &thunk_memset);
        register_thunk(dll, "memcmp", &thunk_memcmp);
        register_thunk(dll, "strlen", &thunk_strlen);
        register_thunk(dll, "wcslen", &thunk_wcslen);
        register_thunk(dll, "strcmp", &thunk_strcmp);
        register_thunk(dll, "strncmp", &thunk_strncmp);
    }
    register_thunk("ntdll.dll", "RtlCopyMemory", &thunk_memcpy);
    register_thunk("ntdll.dll", "RtlMoveMemory", &thunk_memmove);
    register_thunk("ntdll.dll", "RtlZeroMemory", &thunk_RtlZeroMemory);
    register_thunk("ntdll.dll", "RtlFillMemory", &thunk_RtlFillMemory);
    register_thunk("kernel32.dll", "RtlCopyMemory", &thunk_memcpy);
    register_thunk("kernel32.dll", "RtlMoveMemory", &thunk_memmove);
    register_thunk("kernel32.dll", "RtlZeroMemory", &thunk_RtlZeroMemory);
    register_thunk("kernel32.dll", "RtlFillMemory", &thunk_RtlFillMemory);

    // M16: InitOnce (MSVC std::call_once), SList, Time/Locale, VirtualQuery, FileInfo & XInputCaps
    register_thunk("kernel32.dll", "InitializeSListHead", &thunk_InitializeSListHead);
    register_thunk("kernel32.dll", "InterlockedPushEntrySList", &thunk_InterlockedPushEntrySList);
    register_thunk("kernel32.dll", "InterlockedPopEntrySList", &thunk_InterlockedPopEntrySList);
    register_thunk("kernel32.dll", "InterlockedFlushSList", &thunk_InterlockedFlushSList);
    register_thunk("kernel32.dll", "QueryDepthSList", &thunk_QueryDepthSList);
    register_thunk("ntdll.dll", "RtlInitializeSListHead", &thunk_InitializeSListHead);
    register_thunk("ntdll.dll", "RtlInterlockedPushEntrySList", &thunk_InterlockedPushEntrySList);
    register_thunk("ntdll.dll", "RtlInterlockedPopEntrySList", &thunk_InterlockedPopEntrySList);
    register_thunk("ntdll.dll", "RtlInterlockedFlushSList", &thunk_InterlockedFlushSList);
    register_thunk("ntdll.dll", "RtlQueryDepthSList", &thunk_QueryDepthSList);
    register_thunk("kernel32.dll", "InitOnceInitialize", &thunk_InitOnceInitialize);
    register_thunk("kernel32.dll", "InitOnceBeginInitialize", &thunk_InitOnceBeginInitialize);
    register_thunk("kernel32.dll", "InitOnceComplete", &thunk_InitOnceComplete);
    register_thunk("kernel32.dll", "GetSystemTime", &thunk_GetSystemOrLocalTime);
    register_thunk("kernel32.dll", "GetLocalTime", &thunk_GetSystemOrLocalTime);
    register_thunk("kernel32.dll", "GetTickCount", &thunk_GetTickCount32);
    register_thunk("kernel32.dll", "GetFileInformationByHandle", &thunk_GetFileInformationByHandle);
    register_thunk("kernel32.dll", "SetEndOfFile", &thunk_ReturnTrue);
    register_thunk("kernel32.dll", "VirtualQuery", &thunk_VirtualQuery);
    register_thunk("kernel32.dll", "GetUserDefaultLCID", &thunk_GetLocaleEnUs);
    register_thunk("kernel32.dll", "GetUserDefaultUILanguage", &thunk_GetLocaleEnUs);
    register_thunk("kernel32.dll", "GetCurrentProcessorNumber", &thunk_ReturnZero);
    register_thunk("kernel32.dll", "SetThreadIdealProcessor", &thunk_ReturnZero);
    register_thunk("kernel32.dll", "GetLogicalProcessorInformation", &thunk_ReturnZero);
    register_thunk("kernel32.dll", "GetLogicalProcessorInformationEx", &thunk_ReturnZero);
    register_thunk("xinput1_4.dll", "XInputGetCapabilities", &thunk_XInputGetCapabilities);
    register_thunk("xinput1_3.dll", "XInputGetCapabilities", &thunk_XInputGetCapabilities);
}

} // namespace mobiro::cpu
