#include "box64_bridge.hpp"
#include "../input/input_router.hpp"

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

// Win32 VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
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

    int posix_prot = 0;
#if defined(__linux__) || defined(__ANDROID__)
    // Translate Win32 PAGE_* constants into POSIX PROT_* (never host PROT_EXEC)
    switch (win_prot & 0xFF) {
        case 0x01: posix_prot = PROT_NONE; break;               // PAGE_NOACCESS
        case 0x02: posix_prot = PROT_READ; break;               // PAGE_READONLY
        case 0x04: posix_prot = PROT_READ | PROT_WRITE; break;  // PAGE_READWRITE
        case 0x20: posix_prot = PROT_READ; break;               // PAGE_EXECUTE_READ
        case 0x40: posix_prot = PROT_READ | PROT_WRITE; break;  // PAGE_EXECUTE_READWRITE
        default:   posix_prot = PROT_READ | PROT_WRITE; break;
    }
#else
    (void)win_prot;
#endif
    const bool commit = (alloc_type & 0x1000u) != 0; // MEM_COMMIT
    reg_rax(emu) = bridge->arena()->virtual_alloc(addr, size, posix_prot, commit);
}

// Win32 VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
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

// XInputGetState(DWORD dwUserIndex, XINPUT_STATE* pState)
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

// XInputSetState(DWORD dwUserIndex, XINPUT_VIBRATION* pVibration)
void thunk_XInputSetState(x64emu_t* emu) {
    const uint32_t user_idx = static_cast<uint32_t>(reg_rcx(emu));
    reg_rax(emu) = (user_idx == 0) ? 0ULL : 1167ULL;
}

// D3D11 / DXGI thunks route to native ARM64 DXVK once libdxvk_d3d11.so is linked.
void thunk_D3D11CreateDevice(x64emu_t* emu) {
    // shortcut: returns E_NOTIMPL until native ARM64 DXVK submodule is built and linked.
    reg_rax(emu) = 0x80004001ULL; // E_NOTIMPL
}

void thunk_CreateDXGIFactory1(x64emu_t* emu) {
    // shortcut: returns E_NOTIMPL until native ARM64 DXVK submodule is built and linked.
    reg_rax(emu) = 0x80004001ULL; // E_NOTIMPL
}

} // namespace

bool Box64Bridge::initialize(mem::GuestArena* arena, const validator::VfsMapper* vfs) {
    arena_ = arena;
    vfs_ = vfs;
    g_instance_ = this;

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
    register_default_win32_thunks();
    return true;
}

void Box64Bridge::shutdown() {
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
    register_thunk("kernel32.dll", "VirtualAlloc", &thunk_VirtualAlloc);
    register_thunk("kernel32.dll", "VirtualFree", &thunk_VirtualFree);
    register_thunk("xinput1_4.dll", "XInputGetState", &thunk_XInputGetState);
    register_thunk("xinput1_3.dll", "XInputGetState", &thunk_XInputGetState);
    register_thunk("xinput1_4.dll", "XInputSetState", &thunk_XInputSetState);
    register_thunk("xinput1_3.dll", "XInputSetState", &thunk_XInputSetState);
    register_thunk("d3d11.dll", "D3D11CreateDevice", &thunk_D3D11CreateDevice);
    register_thunk("dxgi.dll", "CreateDXGIFactory1", &thunk_CreateDXGIFactory1);
}

} // namespace mobiro::cpu
