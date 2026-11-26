#include "box64_bridge.hpp"
#include "../input/input_router.hpp"

#include <chrono>
#include <cstring>

#if defined(__linux__) || defined(__ANDROID__)
#include <sys/mman.h>
#endif

namespace mobiro::cpu {

namespace {

inline uint64_t& reg_rax(x64emu_t* e) {
#ifdef MOBIRO_HAVE_BOX64
    return e->regs[_AX].q[0];
#else
    return e->rax;
#endif
}
inline uint64_t reg_rcx(x64emu_t* e) {
#ifdef MOBIRO_HAVE_BOX64
    return e->regs[_CX].q[0];
#else
    return e->rcx;
#endif
}
inline uint64_t reg_rdx(x64emu_t* e) {
#ifdef MOBIRO_HAVE_BOX64
    return e->regs[_DX].q[0];
#else
    return e->rdx;
#endif
}
inline uint64_t reg_r8(x64emu_t* e) {
#ifdef MOBIRO_HAVE_BOX64
    return e->regs[_R8].q[0];
#else
    return e->r8;
#endif
}
inline uint64_t reg_r9(x64emu_t* e) {
#ifdef MOBIRO_HAVE_BOX64
    return e->regs[_R9].q[0];
#else
    return e->r9;
#endif
}
inline uint64_t stack_arg(x64emu_t* e, size_t win64_arg_index_from_5) {
    // Win64 stack layout at thunk entry: [RSP+0x00]=retaddr, [0x08..0x20]=shadow space, [0x28]=arg5
#ifdef MOBIRO_HAVE_BOX64
    auto* sp = reinterpret_cast<const uint64_t*>(e->regs[_SP].q[0]);
#else
    auto* sp = reinterpret_cast<const uint64_t*>(e->rsp);
#endif
    if (!sp) return 0;
    return sp[5 + win64_arg_index_from_5];
}
inline Win64Teb* current_teb(x64emu_t* e) {
#ifndef MOBIRO_HAVE_BOX64
    if (e && e->gs_base) return reinterpret_cast<Win64Teb*>(e->gs_base);
#endif
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
    const std::string path = win32::utf16le_to_utf8(wpath);
    reg_rax(emu) = bridge->files().open_read(bridge->vfs(), path);
}

void thunk_CreateFileA(x64emu_t* emu) {
    auto* bridge = Box64Bridge::instance();
    const auto* apath = reinterpret_cast<const char*>(reg_rcx(emu));
    if (!bridge || !apath) {
        reg_rax(emu) = win32::FileHandleTable::kInvalidHandle;
        return;
    }
    reg_rax(emu) = bridge->files().open_read(bridge->vfs(), apath);
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
    reg_rax(emu) = b->events().wait_single(reg_rcx(emu), static_cast<uint32_t>(reg_rdx(emu)));
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

void thunk_GetModuleHandleW(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    const uint64_t name_ptr = reg_rcx(emu);
    // NULL returns main executable HMODULE (ImageBase)
    reg_rax(emu) = (name_ptr == 0 && b) ? b->main_module_base() : 0ULL;
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

// --- Graphics (Native ARM64 DXVK placeholders until M2 submodule link) ---

void thunk_D3D11CreateDevice(x64emu_t* emu) {
    // shortcut: returns E_NOTIMPL until native ARM64 DXVK submodule is built and linked in M2.
    reg_rax(emu) = 0x80004001ULL;
}

void thunk_CreateDXGIFactory1(x64emu_t* emu) {
    // shortcut: returns E_NOTIMPL until native ARM64 DXVK submodule is built and linked in M2.
    reg_rax(emu) = 0x80004001ULL;
}

} // namespace

bool Box64Bridge::initialize(mem::GuestArena* arena, const validator::VfsMapper* vfs) {
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
    register_default_win32_thunks();
    return true;
}

void Box64Bridge::shutdown() {
    files_.close_all();
    srw_locks_.clear();
    events_.clear();
    heap_.reset();
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
    stub.thunk_ptr = reinterpret_cast<uint64_t>(it->second);
    return reinterpret_cast<uintptr_t>(&stub);
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
    register_thunk("dxgi.dll", "CreateDXGIFactory1", &thunk_CreateDXGIFactory1);
}

} // namespace mobiro::cpu
