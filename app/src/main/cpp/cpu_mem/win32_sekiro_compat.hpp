#pragma once

// Companion Sekiro PC + BYOF DLL (FMODEx, Bink2, Oodle, AMD AGS, Steam) Win32 compatibility thunks.
// Included inside `namespace mobiro::cpu` from `win32_shim.cpp` so it directly reuses core thunks
// and Box64Bridge helpers with zero duplication.

namespace {

// --- Box64 onebridge_t proxy for IDirectInput8 (prevents guest x86_64 jumping to raw ARM64 vtables) ---
struct alignas(32) DirectInput8Proxy {
    const uintptr_t* lpVtbl = nullptr;
    mobiro::win32::IDirectInput8Com* native_obj = nullptr;
};
static_assert(offsetof(DirectInput8Proxy, lpVtbl) == 0);

class DirectInput8ComBridge {
public:
    static constexpr size_t kSlots = 9;
    static DirectInput8ComBridge& global() {
        static DirectInput8ComBridge inst;
        return inst;
    }
    DirectInput8ComBridge() { init(std::make_index_sequence<kSlots>{}); }

    DirectInput8Proxy* wrap(mobiro::win32::IDirectInput8Com* obj) {
        if (!obj) return nullptr;
        auto* p = new DirectInput8Proxy();
        p->lpVtbl = vtbl_.data();
        p->native_obj = obj;
        return p;
    }

    template <size_t Slot>
    static void dispatch(x64emu_t* emu) {
        if (!emu) return;
        auto* p = reinterpret_cast<DirectInput8Proxy*>(reg_rcx(emu));
        if (!p || !p->native_obj) { reg_rax(emu) = 0x80070057ULL; return; }
        const auto* nvtbl = *reinterpret_cast<void* const* const*>(p->native_obj);
        const uint64_t rdx = reg_rdx(emu), r8 = reg_r8(emu), r9 = reg_r9(emu);
        const uint64_t a4 = stack_arg(emu, 0);
        using Fn = uint64_t (*)(void*, uint64_t, uint64_t, uint64_t, uint64_t);
        const uint64_t ret = reinterpret_cast<Fn>(nvtbl[Slot])(p->native_obj, rdx, r8, r9, a4);
        reg_rax(emu) = ret;
        if constexpr (Slot == 0) {
            if (static_cast<int32_t>(ret) >= 0 && r8) *reinterpret_cast<void**>(r8) = p;
        } else if constexpr (Slot == 2) {
            if (static_cast<uint32_t>(ret) == 0) delete p;
        }
    }

private:
    template <size_t... Is>
    void init(std::index_sequence<Is...>) {
        ((stubs_[Is] = NativeBridgeStub{},
          stubs_[Is].wrapper_ptr = reinterpret_cast<uint64_t>(&mobiro_native_thunk_wrapper),
          stubs_[Is].thunk_ptr = reinterpret_cast<uint64_t>(&dispatch<Is>),
          vtbl_[Is] = reinterpret_cast<uintptr_t>(&stubs_[Is])), ...);
        sync_box64_exec_region(stubs_.data(), sizeof(stubs_));
    }
    std::array<NativeBridgeStub, kSlots> stubs_{};
    std::array<uintptr_t, kSlots> vtbl_{};
};

void thunk_DirectInput8Create_Proxy(x64emu_t* emu) {
    auto** out_di = reinterpret_cast<void**>(reg_r9(emu));
    const int32_t hr = win32::create_dinput8_com(out_di);
    if (hr >= 0 && out_di && *out_di) {
        *out_di = DirectInput8ComBridge::global().wrap(static_cast<win32::IDirectInput8Com*>(*out_di));
    }
    reg_rax(emu) = static_cast<uint64_t>(static_cast<uint32_t>(hr));
}

// --- WinMM waveOut* -> AAudioXAudioBridge (powers FMODEx & Bink2 audio) ---

void thunk_waveOutGetNumDevs(x64emu_t* emu) { reg_rax(emu) = 1ULL; }

void thunk_waveOutGetDevCapsA(x64emu_t* emu) {
    auto* out = reinterpret_cast<uint8_t*>(reg_rdx(emu));
    const size_t cb = static_cast<size_t>(reg_r8(emu));
    if (!out || cb < 52) { reg_rax(emu) = 11ULL; return; }
    std::memset(out, 0, cb);
    const uint16_t mid = 1, pid = 1, ch = 2;
    const uint32_t formats = 0x000FFFFFu;
    std::memcpy(out + 0, &mid, 2);
    std::memcpy(out + 2, &pid, 2);
    std::memcpy(out + 8, "Mobiro AAudio", 14);
    std::memcpy(out + 40, &formats, 4);
    std::memcpy(out + 44, &ch, 2);
    reg_rax(emu) = 0ULL;
}

void thunk_waveOutGetDevCapsW(x64emu_t* emu) {
    auto* out = reinterpret_cast<uint8_t*>(reg_rdx(emu));
    const size_t cb = static_cast<size_t>(reg_r8(emu));
    if (!out || cb < 84) { reg_rax(emu) = 11ULL; return; }
    std::memset(out, 0, cb);
    const uint16_t mid = 1, pid = 1, ch = 2;
    const uint32_t formats = 0x000FFFFFu;
    std::memcpy(out + 0, &mid, 2);
    std::memcpy(out + 2, &pid, 2);
    const char* name = "Mobiro AAudio";
    auto* wname = reinterpret_cast<uint16_t*>(out + 8);
    for (size_t i = 0; name[i]; ++i) wname[i] = static_cast<uint8_t>(name[i]);
    std::memcpy(out + 72, &formats, 4);
    std::memcpy(out + 76, &ch, 2);
    reg_rax(emu) = 0ULL;
}

void thunk_waveOutOpen(x64emu_t* emu) {
    auto* out_h = reinterpret_cast<uint64_t*>(reg_rcx(emu));
    const auto* fmt = reinterpret_cast<const mobiro::audio::WaveFormatEx*>(reg_r8(emu));
    const uint64_t cb = reg_r9(emu);
    const uint32_t flags = static_cast<uint32_t>(stack_arg(emu, 1));
    reg_rax(emu) = mobiro::audio::WinmmWaveOutBridge::global().open(out_h, fmt, cb, flags);
}

void thunk_waveOutPrepareHeader(x64emu_t* emu) {
    auto* hdr = reinterpret_cast<mobiro::audio::Win64WaveHdr*>(reg_rdx(emu));
    reg_rax(emu) = mobiro::audio::WinmmWaveOutBridge::global().prepare(hdr);
}

void thunk_waveOutUnprepareHeader(x64emu_t* emu) {
    auto* hdr = reinterpret_cast<mobiro::audio::Win64WaveHdr*>(reg_rdx(emu));
    reg_rax(emu) = mobiro::audio::WinmmWaveOutBridge::global().unprepare(hdr);
}

void thunk_waveOutWrite(x64emu_t* emu) {
    const uint64_t h = reg_rcx(emu);
    auto* hdr = reinterpret_cast<mobiro::audio::Win64WaveHdr*>(reg_rdx(emu));
    uint64_t ev = 0;
    const uint32_t rc = mobiro::audio::WinmmWaveOutBridge::global().write(h, hdr, &ev);
    if (rc == 0 && ev) {
        if (auto* b = Box64Bridge::instance()) b->events().set_event(ev);
    }
    reg_rax(emu) = rc;
}

void thunk_waveOutGetPosition(x64emu_t* emu) {
    auto* mmt = reinterpret_cast<mobiro::audio::Win64MmTime*>(reg_rdx(emu));
    reg_rax(emu) = mobiro::audio::WinmmWaveOutBridge::global().get_position(reg_rcx(emu), mmt);
}

void thunk_waveOutPause(x64emu_t* emu)   { reg_rax(emu) = mobiro::audio::WinmmWaveOutBridge::global().set_paused(reg_rcx(emu), true); }
void thunk_waveOutRestart(x64emu_t* emu) { reg_rax(emu) = mobiro::audio::WinmmWaveOutBridge::global().set_paused(reg_rcx(emu), false); }
void thunk_waveOutReset(x64emu_t* emu)   { reg_rax(emu) = mobiro::audio::WinmmWaveOutBridge::global().reset(reg_rcx(emu)); }
void thunk_waveOutClose(x64emu_t* emu)   { reg_rax(emu) = mobiro::audio::WinmmWaveOutBridge::global().close(reg_rcx(emu)); }
void thunk_waveOutSetVolume(x64emu_t* emu) {
    reg_rax(emu) = mobiro::audio::WinmmWaveOutBridge::global().set_volume(reg_rcx(emu), static_cast<uint32_t>(reg_rdx(emu)));
}
void thunk_MmNotSupported(x64emu_t* emu) { reg_rax(emu) = 8ULL; } // MMSYSERR_NOTSUPPORTED

// --- Kernel32 Extended Core (Version, Memory, FS, Time, Locale, SEH, Sync) ---

void thunk_ReturnENotImpl(x64emu_t* emu) { reg_rax(emu) = 0x80004001ULL; } // E_NOTIMPL
void thunk_ReturnNegOne(x64emu_t* emu)   { reg_rax(emu) = ~0ULL; }         // SOCKET_ERROR / INVALID

void thunk_GetVersion(x64emu_t* emu) { reg_rax(emu) = 0x4A65000AULL; } // Win10 10.0 build 19045

void thunk_GetVersionEx(x64emu_t* emu) {
    auto* p = reinterpret_cast<uint32_t*>(reg_rcx(emu));
    if (!p || p[0] < 20) { reg_rax(emu) = 0ULL; return; }
    p[1] = 10u; p[2] = 0u; p[3] = 19045u; p[4] = 2u; // VER_PLATFORM_WIN32_NT
    reg_rax(emu) = 1ULL;
}

void thunk_LocalOrGlobalAlloc(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    const uint32_t flags = static_cast<uint32_t>(reg_rcx(emu));
    const size_t bytes = static_cast<size_t>(reg_rdx(emu));
    const bool zero = (flags & 0x40u) != 0; // LMEM_ZEROINIT / GMEM_ZEROINIT
    reg_rax(emu) = b ? static_cast<uint64_t>(b->heap().alloc(bytes ? bytes : 16, zero)) : 0ULL;
}

void thunk_LocalOrGlobalFree(x64emu_t* emu) {
    if (auto* b = Box64Bridge::instance()) b->heap().free(static_cast<uintptr_t>(reg_rcx(emu)));
    reg_rax(emu) = 0ULL; // NULL = success
}

void thunk_GlobalLock(x64emu_t* emu) { reg_rax(emu) = reg_rcx(emu); }

void thunk_GlobalMemoryStatus(x64emu_t* emu) {
    auto* p = reinterpret_cast<uint64_t*>(reg_rcx(emu));
    if (!p) { reg_rax(emu) = 0ULL; return; }
    std::memset(p, 0, 56);
    const uint32_t len = 56, load = 35;
    std::memcpy(p, &len, 4);
    std::memcpy(reinterpret_cast<uint8_t*>(p) + 4, &load, 4);
    p[1] = 8ULL * 1024 * 1024 * 1024; // dwTotalPhys
    p[2] = 5ULL * 1024 * 1024 * 1024; // dwAvailPhys
    p[3] = 8ULL * 1024 * 1024 * 1024;
    p[4] = 5ULL * 1024 * 1024 * 1024;
    p[5] = 64ULL * 1024 * 1024 * 1024;
    p[6] = 60ULL * 1024 * 1024 * 1024;
    reg_rax(emu) = 0ULL;
}

void thunk_SetFilePointer32(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    const uint64_t h = reg_rcx(emu);
    const int32_t dist_lo = static_cast<int32_t>(reg_rdx(emu));
    auto* dist_hi_ptr = reinterpret_cast<int32_t*>(reg_r8(emu));
    const uint32_t method = static_cast<uint32_t>(reg_r9(emu));
    int64_t dist = dist_hi_ptr
        ? (static_cast<int64_t>(*dist_hi_ptr) << 32) | static_cast<uint32_t>(dist_lo)
        : static_cast<int64_t>(dist_lo);
    int64_t pos = 0;
    if (!b || !b->files().seek_file(h, dist, method, &pos)) {
        reg_rax(emu) = 0xFFFFFFFFULL; // INVALID_SET_FILE_POINTER
        return;
    }
    if (dist_hi_ptr) *dist_hi_ptr = static_cast<int32_t>(pos >> 32);
    reg_rax(emu) = static_cast<uint32_t>(pos & 0xFFFFFFFFULL);
}

void thunk_GetFileSize32(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    auto* hi_out = reinterpret_cast<uint32_t*>(reg_rdx(emu));
    int64_t sz = 0;
    if (!b || !b->files().get_file_size(reg_rcx(emu), &sz)) {
        reg_rax(emu) = 0xFFFFFFFFULL;
        return;
    }
    if (hi_out) *hi_out = static_cast<uint32_t>(static_cast<uint64_t>(sz) >> 32);
    reg_rax(emu) = static_cast<uint32_t>(sz & 0xFFFFFFFFULL);
}

void thunk_GetFileAttributesExW(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    const std::string path = mobiro::win32::utf16le_to_utf8(reinterpret_cast<const uint16_t*>(reg_rcx(emu)));
    auto* out = reinterpret_cast<uint8_t*>(reg_r8(emu));
    std::string host;
    if (!b || !b->vfs() || !out || !b->vfs()->resolve(path, host)) {
        reg_rax(emu) = 0ULL;
        return;
    }
    std::memset(out, 0, 36);
    std::error_code ec;
    const bool is_dir = std::filesystem::is_directory(host, ec);
    const uint32_t attrs = is_dir ? 0x10u : 0x80u;
    const uint64_t sz = is_dir ? 0ULL : static_cast<uint64_t>(std::filesystem::file_size(host, ec));
    const uint32_t hi = static_cast<uint32_t>(sz >> 32), lo = static_cast<uint32_t>(sz & 0xFFFFFFFFULL);
    std::memcpy(out + 0, &attrs, 4);
    std::memcpy(out + 28, &hi, 4);
    std::memcpy(out + 32, &lo, 4);
    reg_rax(emu) = 1ULL;
}

void thunk_GetFullPathNameW(x64emu_t* emu) {
    const auto* src = reinterpret_cast<const uint16_t*>(reg_rcx(emu));
    const uint32_t cap = static_cast<uint32_t>(reg_rdx(emu));
    auto* dst = reinterpret_cast<uint16_t*>(reg_r8(emu));
    if (!src) { reg_rax(emu) = 0ULL; return; }
    size_t len = 0;
    while (src[len]) ++len;
    if (dst && cap > len) {
        std::memcpy(dst, src, (len + 1) * 2);
        reg_rax(emu) = len;
    } else {
        reg_rax(emu) = len + 1;
    }
}

void thunk_GetFullPathNameA(x64emu_t* emu) {
    const char* src = reinterpret_cast<const char*>(reg_rcx(emu));
    const uint32_t cap = static_cast<uint32_t>(reg_rdx(emu));
    char* dst = reinterpret_cast<char*>(reg_r8(emu));
    if (!src) { reg_rax(emu) = 0ULL; return; }
    const size_t len = std::strlen(src);
    if (dst && cap > len) {
        std::memcpy(dst, src, len + 1);
        reg_rax(emu) = len;
    } else {
        reg_rax(emu) = len + 1;
    }
}

void thunk_CopyFileW(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    const std::string src_g = mobiro::win32::utf16le_to_utf8(reinterpret_cast<const uint16_t*>(reg_rcx(emu)));
    const std::string dst_g = mobiro::win32::utf16le_to_utf8(reinterpret_cast<const uint16_t*>(reg_rdx(emu)));
    std::string src_h, dst_h;
    if (!b || !b->vfs() || !b->vfs()->resolve(src_g, src_h) || !b->vfs()->resolve_for_write(dst_g, dst_h)) {
        reg_rax(emu) = 0ULL;
        return;
    }
    std::error_code ec;
    std::filesystem::copy_file(src_h, dst_h, std::filesystem::copy_options::overwrite_existing, ec);
    reg_rax(emu) = ec ? 0ULL : 1ULL;
}

void thunk_GetDiskFreeSpaceExW(x64emu_t* emu) {
    const uint64_t avail = 32ULL * 1024 * 1024 * 1024;
    const uint64_t total = 64ULL * 1024 * 1024 * 1024;
    if (auto* p = reinterpret_cast<uint64_t*>(reg_rdx(emu))) *p = avail;
    if (auto* p = reinterpret_cast<uint64_t*>(reg_r8(emu)))  *p = total;
    if (auto* p = reinterpret_cast<uint64_t*>(reg_r9(emu)))  *p = avail;
    reg_rax(emu) = 1ULL;
}

void thunk_GetDriveType(x64emu_t* emu) { reg_rax(emu) = 3ULL; } // DRIVE_FIXED

void thunk_GetSystemDirA(x64emu_t* emu) {
    char* dst = reinterpret_cast<char*>(reg_rcx(emu));
    const uint32_t cap = static_cast<uint32_t>(reg_rdx(emu));
    const char* s = "C:\\Windows\\System32";
    const size_t n = std::strlen(s);
    if (dst && cap > n) std::memcpy(dst, s, n + 1);
    reg_rax(emu) = n;
}

void thunk_GetSystemDirW(x64emu_t* emu) {
    auto* dst = reinterpret_cast<uint16_t*>(reg_rcx(emu));
    const uint32_t cap = static_cast<uint32_t>(reg_rdx(emu));
    const char* s = "C:\\Windows\\System32";
    const size_t n = std::strlen(s);
    if (dst && cap > n) {
        for (size_t i = 0; i <= n; ++i) dst[i] = static_cast<uint8_t>(s[i]);
    }
    reg_rax(emu) = n;
}

void thunk_GetTempPathA(x64emu_t* emu) {
    const uint32_t cap = static_cast<uint32_t>(reg_rcx(emu));
    char* dst = reinterpret_cast<char*>(reg_rdx(emu));
    const char* s = "C:\\Temp\\";
    const size_t n = std::strlen(s);
    if (dst && cap > n) std::memcpy(dst, s, n + 1);
    reg_rax(emu) = n;
}

void thunk_CompareStringW(x64emu_t* emu) {
    const uint32_t flags = static_cast<uint32_t>(reg_rdx(emu));
    const auto* a = reinterpret_cast<const uint16_t*>(reg_r8(emu));
    int32_t la = static_cast<int32_t>(reg_r9(emu));
    const auto* b = reinterpret_cast<const uint16_t*>(stack_arg(emu, 0));
    int32_t lb = static_cast<int32_t>(stack_arg(emu, 1));
    if (!a || !b) { reg_rax(emu) = 0ULL; return; }
    if (la < 0) { la = 0; while (a[la]) ++la; }
    if (lb < 0) { lb = 0; while (b[lb]) ++lb; }
    const bool nocase = (flags & 1u) != 0;
    const int32_t n = (la < lb) ? la : lb;
    for (int32_t i = 0; i < n; ++i) {
        uint16_t ca = a[i], cb = b[i];
        if (nocase) {
            if (ca >= 'A' && ca <= 'Z') ca += 32;
            if (cb >= 'A' && cb <= 'Z') cb += 32;
        }
        if (ca < cb) { reg_rax(emu) = 1ULL; return; } // CSTR_LESS_THAN
        if (ca > cb) { reg_rax(emu) = 3ULL; return; } // CSTR_GREATER_THAN
    }
    reg_rax(emu) = (la < lb) ? 1ULL : (la > lb ? 3ULL : 2ULL); // CSTR_EQUAL=2
}

void thunk_FileTimeCopy(x64emu_t* emu) {
    const auto* src = reinterpret_cast<const uint64_t*>(reg_rcx(emu));
    auto* dst = reinterpret_cast<uint64_t*>(reg_rdx(emu));
    if (src && dst) *dst = *src;
    reg_rax(emu) = (src && dst) ? 1ULL : 0ULL;
}

void thunk_FileTimeToSystemTime(x64emu_t* emu) {
    const auto* ft = reinterpret_cast<const uint64_t*>(reg_rcx(emu));
    auto* st = reinterpret_cast<uint16_t*>(reg_rdx(emu));
    if (!ft || !st) { reg_rax(emu) = 0ULL; return; }
    constexpr uint64_t kEpochDiff = 116444736000000000ULL;
    const uint64_t unix_100ns = (*ft > kEpochDiff) ? (*ft - kEpochDiff) : 0ULL;
    const std::time_t tt = static_cast<std::time_t>(unix_100ns / 10000000ULL);
    std::tm tmv{};
#if defined(_WIN32)
    gmtime_s(&tmv, &tt);
#else
    gmtime_r(&tt, &tmv);
#endif
    st[0] = static_cast<uint16_t>(tmv.tm_year + 1900);
    st[1] = static_cast<uint16_t>(tmv.tm_mon + 1);
    st[2] = static_cast<uint16_t>(tmv.tm_wday);
    st[3] = static_cast<uint16_t>(tmv.tm_mday);
    st[4] = static_cast<uint16_t>(tmv.tm_hour);
    st[5] = static_cast<uint16_t>(tmv.tm_min);
    st[6] = static_cast<uint16_t>(tmv.tm_sec);
    st[7] = static_cast<uint16_t>((unix_100ns / 10000ULL) % 1000ULL);
    reg_rax(emu) = 1ULL;
}

void thunk_SystemTimeToFileTime(x64emu_t* emu) {
    const auto* st = reinterpret_cast<const uint16_t*>(reg_rcx(emu));
    auto* ft = reinterpret_cast<uint64_t*>(reg_rdx(emu));
    if (!st || !ft) { reg_rax(emu) = 0ULL; return; }
    std::tm tmv{};
    tmv.tm_year = static_cast<int>(st[0]) - 1900;
    tmv.tm_mon  = static_cast<int>(st[1]) - 1;
    tmv.tm_mday = static_cast<int>(st[3]);
    tmv.tm_hour = static_cast<int>(st[4]);
    tmv.tm_min  = static_cast<int>(st[5]);
    tmv.tm_sec  = static_cast<int>(st[6]);
    const std::time_t tt = std::mktime(&tmv);
    constexpr uint64_t kEpochDiff = 116444736000000000ULL;
    *ft = (tt > 0 ? static_cast<uint64_t>(tt) * 10000000ULL : 0ULL) + kEpochDiff +
          static_cast<uint64_t>(st[7]) * 10000ULL;
    reg_rax(emu) = 1ULL;
}

void thunk_GetTimeZoneInformation(x64emu_t* emu) {
    if (auto* tz = reinterpret_cast<uint8_t*>(reg_rcx(emu))) std::memset(tz, 0, 172);
    reg_rax(emu) = 0ULL; // TIME_ZONE_ID_UNKNOWN (UTC)
}

void thunk_GetSystemDefaultLocaleName(x64emu_t* emu) {
    auto* dst = reinterpret_cast<uint16_t*>(reg_rcx(emu));
    const int cap = static_cast<int>(reg_rdx(emu));
    const uint16_t en[] = {'e','n','-','U','S', 0};
    if (dst && cap >= 6) std::memcpy(dst, en, sizeof(en));
    reg_rax(emu) = 6ULL;
}

void thunk_GetExitCodeStillActive(x64emu_t* emu) {
    if (auto* out = reinterpret_cast<uint32_t*>(reg_rdx(emu))) *out = 0u;
    reg_rax(emu) = 1ULL;
}

void thunk_RtlPcToFileHeader(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    const uintptr_t base = b ? b->main_module_base() : 0;
    if (auto* out = reinterpret_cast<uint64_t*>(reg_rdx(emu))) *out = static_cast<uint64_t>(base);
    reg_rax(emu) = static_cast<uint64_t>(base);
}

void thunk_GetOverlappedResult(x64emu_t* emu) {
    if (auto* xfer = reinterpret_cast<uint32_t*>(reg_r8(emu))) *xfer = 0;
    reg_rax(emu) = 1ULL;
}

// --- User32 / GDI32 / OLE32 / OLEAUT32 / Advapi32 / Shell32 ---

void thunk_GetWindowHandle(x64emu_t* emu) {
    reg_rax(emu) = win32::HeadlessWindowState::kMainHwnd;
}

void thunk_GetWindowThreadProcessId(x64emu_t* emu) {
    if (auto* pid = reinterpret_cast<uint32_t*>(reg_rdx(emu))) *pid = 1000u;
    reg_rax(emu) = 1000ULL;
}

void thunk_CharLowerBuffA(x64emu_t* emu) {
    char* s = reinterpret_cast<char*>(reg_rcx(emu));
    const uint32_t n = static_cast<uint32_t>(reg_rdx(emu));
    if (s) {
        for (uint32_t i = 0; i < n; ++i) {
            if (s[i] >= 'A' && s[i] <= 'Z') s[i] = static_cast<char>(s[i] + 32);
        }
    }
    reg_rax(emu) = n;
}

void thunk_GetCursorPos(x64emu_t* emu) {
    if (auto* pt = reinterpret_cast<int32_t*>(reg_rcx(emu))) { pt[0] = 0; pt[1] = 0; }
    reg_rax(emu) = 1ULL;
}

void thunk_GetKeyboardState(x64emu_t* emu) {
    if (auto* st = reinterpret_cast<uint8_t*>(reg_rcx(emu))) std::memset(st, 0, 256);
    reg_rax(emu) = 1ULL;
}

void thunk_CoCreateGuid(x64emu_t* emu) {
    auto* out = reinterpret_cast<uint8_t*>(reg_rcx(emu));
    if (!out) { reg_rax(emu) = 0x80070057ULL; return; }
    std::random_device rd;
    for (int i = 0; i < 16; ++i) out[i] = static_cast<uint8_t>(rd() & 0xFFu);
    out[6] = static_cast<uint8_t>((out[6] & 0x0Fu) | 0x40u);
    out[8] = static_cast<uint8_t>((out[8] & 0x3Fu) | 0x80u);
    reg_rax(emu) = 0ULL;
}

void thunk_SysAllocString(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    const auto* src = reinterpret_cast<const uint16_t*>(reg_rcx(emu));
    if (!b || !src) { reg_rax(emu) = 0ULL; return; }
    size_t len = 0;
    while (src[len]) ++len;
    const uint32_t byte_len = static_cast<uint32_t>(len * 2);
    const uintptr_t blk = b->heap().alloc(byte_len + 6, true);
    if (!blk) { reg_rax(emu) = 0ULL; return; }
    std::memcpy(reinterpret_cast<void*>(blk), &byte_len, 4);
    std::memcpy(reinterpret_cast<void*>(blk + 4), src, byte_len + 2);
    reg_rax(emu) = static_cast<uint64_t>(blk + 4);
}

void thunk_SysFreeString(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    const uintptr_t bstr = static_cast<uintptr_t>(reg_rcx(emu));
    if (b && bstr >= 4) b->heap().free(bstr - 4);
    reg_rax(emu) = 0ULL;
}

void thunk_CryptGenRandom(x64emu_t* emu) {
    // CryptGenRandom(HCRYPTPROV, DWORD dwLen, BYTE* pbBuffer) / SystemFunction036(buf, len)
    const uint32_t len = static_cast<uint32_t>(reg_rdx(emu));
    auto* buf = reinterpret_cast<uint8_t*>(reg_r8(emu));
    if (!buf) { buf = reinterpret_cast<uint8_t*>(reg_rcx(emu)); }
    if (buf && len) {
        std::random_device rd;
        for (uint32_t i = 0; i < len; ++i) buf[i] = static_cast<uint8_t>(rd() & 0xFFu);
    }
    reg_rax(emu) = 1ULL;
}

void thunk_GetUserNameA(x64emu_t* emu) {
    char* dst = reinterpret_cast<char*>(reg_rcx(emu));
    auto* cap = reinterpret_cast<uint32_t*>(reg_rdx(emu));
    const char* name = "Wolf";
    if (dst && cap && *cap >= 5) { std::memcpy(dst, name, 5); *cap = 5; reg_rax(emu) = 1ULL; return; }
    reg_rax(emu) = 0ULL;
}

void thunk_GetUserNameW(x64emu_t* emu) {
    auto* dst = reinterpret_cast<uint16_t*>(reg_rcx(emu));
    auto* cap = reinterpret_cast<uint32_t*>(reg_rdx(emu));
    const uint16_t name[] = {'W','o','l','f', 0};
    if (dst && cap && *cap >= 5) { std::memcpy(dst, name, sizeof(name)); *cap = 5; reg_rax(emu) = 1ULL; return; }
    reg_rax(emu) = 0ULL;
}

void thunk_CommandLineToArgvW(x64emu_t* emu) {
    auto* b = Box64Bridge::instance();
    auto* argc_out = reinterpret_cast<int32_t*>(reg_rdx(emu));
    if (argc_out) *argc_out = 1;
    if (!b) { reg_rax(emu) = 0ULL; return; }
    const uintptr_t blk = b->heap().alloc(64, true);
    if (!blk) { reg_rax(emu) = 0ULL; return; }
    const uint64_t str_ptr = static_cast<uint64_t>(blk + 16);
    std::memcpy(reinterpret_cast<void*>(blk), &str_ptr, 8);
    const uint16_t exe[] = {'S','e','k','i','r','o','.','e','x','e', 0};
    std::memcpy(reinterpret_cast<void*>(blk + 16), exe, sizeof(exe));
    reg_rax(emu) = static_cast<uint64_t>(blk);
}

void thunk_WsaNotConnected(x64emu_t* emu) { reg_rax(emu) = 10057ULL; } // WSAENOTCONN

} // namespace

inline void register_sekiro_compat_thunks(Box64Bridge& br) {
    // Wrap DirectInput8 in Box64 onebridge_t proxy so ARM64 never jumps into raw native vtable pointers
    br.register_thunk("dinput8.dll", "DirectInput8Create", &thunk_DirectInput8Create_Proxy);

    // Critical Graphics & XInput ordinals imported by retail sekiro.exe
    br.register_thunk("dxgi.dll", "CreateDXGIFactory", &thunk_CreateDXGIFactory1);
    br.register_thunk("xinput1_3.dll", "#2", &thunk_XInputGetState);
    br.register_thunk("xinput1_3.dll", "#3", &thunk_XInputSetState);
    br.register_thunk("d3d9.dll", "D3DPERF_GetStatus", &thunk_ReturnZero);
    br.register_thunk("d3dcompiler_43.dll", "D3DGetBlobPart", &thunk_ReturnENotImpl);
    br.register_thunk("d3dx11_43.dll", "D3DX11SaveTextureToFileW", &thunk_ReturnENotImpl);
    br.register_thunk("imm32.dll", "ImmDisableIME", &thunk_ReturnTrue);

    // WinMM waveOut* -> AAudio (FMODEx / Bink2) + waveIn/MCI/MSACM safe stubs
    br.register_thunk("winmm.dll", "waveOutGetNumDevs", &thunk_waveOutGetNumDevs);
    br.register_thunk("winmm.dll", "waveOutGetDevCapsA", &thunk_waveOutGetDevCapsA);
    br.register_thunk("winmm.dll", "waveOutGetDevCapsW", &thunk_waveOutGetDevCapsW);
    br.register_thunk("winmm.dll", "waveOutOpen", &thunk_waveOutOpen);
    br.register_thunk("winmm.dll", "waveOutPrepareHeader", &thunk_waveOutPrepareHeader);
    br.register_thunk("winmm.dll", "waveOutUnprepareHeader", &thunk_waveOutUnprepareHeader);
    br.register_thunk("winmm.dll", "waveOutWrite", &thunk_waveOutWrite);
    br.register_thunk("winmm.dll", "waveOutGetPosition", &thunk_waveOutGetPosition);
    br.register_thunk("winmm.dll", "waveOutPause", &thunk_waveOutPause);
    br.register_thunk("winmm.dll", "waveOutRestart", &thunk_waveOutRestart);
    br.register_thunk("winmm.dll", "waveOutReset", &thunk_waveOutReset);
    br.register_thunk("winmm.dll", "waveOutClose", &thunk_waveOutClose);
    br.register_thunk("winmm.dll", "waveOutSetVolume", &thunk_waveOutSetVolume);
    br.register_thunk("winmm.dll", "mciSendCommandA", &thunk_ReturnZero);
    const char* wavein_syms[] = {
        "waveInAddBuffer", "waveInClose", "waveInGetDevCapsA", "waveInGetDevCapsW",
        "waveInGetNumDevs", "waveInOpen", "waveInPrepareHeader", "waveInReset",
        "waveInStart", "waveInUnprepareHeader"
    };
    for (const char* s : wavein_syms) br.register_thunk("winmm.dll", s, &thunk_ReturnZero);
    const char* msacm_syms[] = {
        "acmFormatSuggest", "acmStreamConvert", "acmStreamOpen",
        "acmStreamPrepareHeader", "acmStreamSize", "acmStreamUnprepareHeader"
    };
    for (const char* s : msacm_syms) br.register_thunk("msacm32.dll", s, &thunk_MmNotSupported);

    // Kernel32 full retail Sekiro + BYOF DLL coverage
    br.register_thunk("kernel32.dll", "WaitForSingleObjectEx", &thunk_WaitForSingleObject);
    br.register_thunk("kernel32.dll", "SleepEx", &thunk_Sleep);
    br.register_thunk("kernel32.dll", "SignalObjectAndWait", &thunk_ReturnZero);
    br.register_thunk("kernel32.dll", "TlsFree", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "ExitThread", &thunk_ReturnZero);
    br.register_thunk("kernel32.dll", "FreeLibraryAndExitThread", &thunk_ReturnZero);
    br.register_thunk("kernel32.dll", "ResumeThread", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "SuspendThread", &thunk_ReturnZero);
    br.register_thunk("kernel32.dll", "TerminateThread", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "GetExitCodeThread", &thunk_GetExitCodeStillActive);
    br.register_thunk("kernel32.dll", "GetExitCodeProcess", &thunk_GetExitCodeStillActive);
    br.register_thunk("kernel32.dll", "GetThreadPriority", &thunk_ReturnZero);
    br.register_thunk("kernel32.dll", "GetThreadTimes", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "SetProcessAffinityMask", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "GetNumaHighestNodeNumber", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "OpenEventA", &thunk_ReturnZero);
    br.register_thunk("kernel32.dll", "PulseEvent", &thunk_SetEvent);
    br.register_thunk("kernel32.dll", "OpenProcess", &thunk_GetCurrentProcess);
    br.register_thunk("kernel32.dll", "OpenThread", &thunk_GetCurrentThread);
    br.register_thunk("kernel32.dll", "CreateWaitableTimerA", &thunk_CreateEventW);
    br.register_thunk("kernel32.dll", "SetWaitableTimer", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "CreateTimerQueue", &thunk_CreateEventW);
    br.register_thunk("kernel32.dll", "CreateTimerQueueTimer", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "ChangeTimerQueueTimer", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "DeleteTimerQueueTimer", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "RegisterWaitForSingleObject", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "UnregisterWait", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "UnregisterWaitEx", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "QueueUserAPC", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "ConvertFiberToThread", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "DeleteFiber", &thunk_ReturnZero);

    br.register_thunk("kernel32.dll", "HeapCreate", &thunk_GetProcessHeap);
    br.register_thunk("kernel32.dll", "HeapDestroy", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "LocalAlloc", &thunk_LocalOrGlobalAlloc);
    br.register_thunk("kernel32.dll", "LocalFree", &thunk_LocalOrGlobalFree);
    br.register_thunk("kernel32.dll", "GlobalAlloc", &thunk_LocalOrGlobalAlloc);
    br.register_thunk("kernel32.dll", "GlobalLock", &thunk_GlobalLock);
    br.register_thunk("kernel32.dll", "GlobalUnlock", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "GlobalMemoryStatus", &thunk_GlobalMemoryStatus);

    br.register_thunk("kernel32.dll", "SetFilePointer", &thunk_SetFilePointer32);
    br.register_thunk("kernel32.dll", "GetFileSize", &thunk_GetFileSize32);
    br.register_thunk("kernel32.dll", "GetFileAttributesExW", &thunk_GetFileAttributesExW);
    br.register_thunk("kernel32.dll", "FindFirstFileExW", &thunk_FindFirstFileW);
    br.register_thunk("kernel32.dll", "FindFirstFileExA", &thunk_ReturnNegOne);
    br.register_thunk("kernel32.dll", "FindNextFileA", &thunk_FindNextFileW);
    br.register_thunk("kernel32.dll", "GetFullPathNameW", &thunk_GetFullPathNameW);
    br.register_thunk("kernel32.dll", "GetFullPathNameA", &thunk_GetFullPathNameA);
    br.register_thunk("kernel32.dll", "CopyFileW", &thunk_CopyFileW);
    br.register_thunk("kernel32.dll", "MoveFileW", &thunk_MoveFileExW);
    br.register_thunk("kernel32.dll", "RemoveDirectoryW", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "SetFileAttributesW", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "GetOverlappedResult", &thunk_GetOverlappedResult);
    br.register_thunk("kernel32.dll", "CancelIo", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "GetDiskFreeSpaceExW", &thunk_GetDiskFreeSpaceExW);
    br.register_thunk("kernel32.dll", "GetDiskFreeSpaceW", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "GetDriveTypeW", &thunk_GetDriveType);
    br.register_thunk("kernel32.dll", "GetDriveTypeA", &thunk_GetDriveType);
    br.register_thunk("kernel32.dll", "GetSystemDirectoryW", &thunk_GetSystemDirW);
    br.register_thunk("kernel32.dll", "GetSystemDirectoryA", &thunk_GetSystemDirA);
    br.register_thunk("kernel32.dll", "GetWindowsDirectoryA", &thunk_GetSystemDirA);
    br.register_thunk("kernel32.dll", "GetTempPathA", &thunk_GetTempPathA);
    br.register_thunk("kernel32.dll", "GetTempFileNameW", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "OpenFile", &thunk_ReturnNegOne);
    br.register_thunk("kernel32.dll", "CreatePipe", &thunk_ReturnZero);
    br.register_thunk("kernel32.dll", "PeekNamedPipe", &thunk_ReturnZero);
    br.register_thunk("kernel32.dll", "DeviceIoControl", &thunk_ReturnZero);
    br.register_thunk("kernel32.dll", "ReadDirectoryChangesW", &thunk_ReturnZero);

    br.register_thunk("kernel32.dll", "GetVersion", &thunk_GetVersion);
    br.register_thunk("kernel32.dll", "GetVersionExW", &thunk_GetVersionEx);
    br.register_thunk("kernel32.dll", "GetVersionExA", &thunk_GetVersionEx);
    br.register_thunk("kernel32.dll", "VerSetConditionMask", &thunk_ReturnZero);
    br.register_thunk("kernel32.dll", "VerifyVersionInfoW", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "GetStartupInfoA", &thunk_GetStartupInfoW);
    br.register_thunk("kernel32.dll", "GetEnvironmentStrings", &thunk_GetEnvironmentStringsW);
    br.register_thunk("kernel32.dll", "FreeEnvironmentStringsA", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "SetEnvironmentVariableW", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "SetEnvironmentVariableA", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "ExpandEnvironmentStringsA", &thunk_ReturnZero);
    br.register_thunk("kernel32.dll", "CompareStringW", &thunk_CompareStringW);
    br.register_thunk("kernel32.dll", "LCMapStringW", &thunk_ReturnZero);
    br.register_thunk("kernel32.dll", "LCMapStringA", &thunk_ReturnZero);
    br.register_thunk("kernel32.dll", "GetStringTypeW", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "GetStringTypeA", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "GetLocaleInfoW", &thunk_ReturnZero);
    br.register_thunk("kernel32.dll", "GetLocaleInfoA", &thunk_ReturnZero);
    br.register_thunk("kernel32.dll", "GetSystemDefaultLCID", &thunk_GetLocaleEnUs);
    br.register_thunk("kernel32.dll", "GetSystemDefaultLangID", &thunk_GetLocaleEnUs);
    br.register_thunk("kernel32.dll", "GetUserDefaultLangID", &thunk_GetLocaleEnUs);
    br.register_thunk("kernel32.dll", "GetSystemDefaultLocaleName", &thunk_GetSystemDefaultLocaleName);
    br.register_thunk("kernel32.dll", "IsValidLocale", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "EnumSystemLocalesW", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "GetTimeZoneInformation", &thunk_GetTimeZoneInformation);
    br.register_thunk("kernel32.dll", "FileTimeToSystemTime", &thunk_FileTimeToSystemTime);
    br.register_thunk("kernel32.dll", "SystemTimeToFileTime", &thunk_SystemTimeToFileTime);
    br.register_thunk("kernel32.dll", "FileTimeToLocalFileTime", &thunk_FileTimeCopy);
    br.register_thunk("kernel32.dll", "LocalFileTimeToFileTime", &thunk_FileTimeCopy);
    br.register_thunk("kernel32.dll", "SystemTimeToTzSpecificLocalTime", &thunk_FileTimeCopy);
    br.register_thunk("kernel32.dll", "GetDateFormatW", &thunk_ReturnZero);
    br.register_thunk("kernel32.dll", "GetTimeFormatW", &thunk_ReturnZero);
    br.register_thunk("kernel32.dll", "FormatMessageW", &thunk_ReturnZero);
    br.register_thunk("kernel32.dll", "FormatMessageA", &thunk_ReturnZero);
    br.register_thunk("kernel32.dll", "GetConsoleCP", &thunk_GetACP);
    br.register_thunk("kernel32.dll", "SetConsoleCtrlHandler", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "SetConsoleMode", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "ReadConsoleW", &thunk_ReturnZero);
    br.register_thunk("kernel32.dll", "ReadConsoleA", &thunk_ReturnZero);
    br.register_thunk("kernel32.dll", "SetStdHandle", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "SetHandleCount", &thunk_GlobalLock);
    br.register_thunk("kernel32.dll", "SetHandleInformation", &thunk_ReturnTrue);
    br.register_thunk("kernel32.dll", "SetErrorMode", &thunk_ReturnZero);
    br.register_thunk("kernel32.dll", "RtlCaptureContext", &thunk_ReturnZero);
    br.register_thunk("kernel32.dll", "RtlPcToFileHeader", &thunk_RtlPcToFileHeader);
    br.register_thunk("kernel32.dll", "RtlUnwindEx", &thunk_ReturnZero);
    br.register_thunk("kernel32.dll", "RtlVirtualUnwind", &thunk_ReturnZero);
    br.register_thunk("kernel32.dll", "UnhandledExceptionFilter", &thunk_ReturnZero);
    br.register_thunk("kernel32.dll", "RaiseException", &thunk_ReturnZero);
    br.register_thunk("kernel32.dll", "CreateProcessA", &thunk_ReturnZero);

    // User32 / GDI32 / OLE32 / OLEAUT32 / Shell32
    br.register_thunk("user32.dll", "GetDesktopWindow", &thunk_GetWindowHandle);
    br.register_thunk("user32.dll", "GetForegroundWindow", &thunk_GetWindowHandle);
    br.register_thunk("user32.dll", "GetActiveWindow", &thunk_GetWindowHandle);
    br.register_thunk("user32.dll", "SetActiveWindow", &thunk_GetWindowHandle);
    br.register_thunk("user32.dll", "GetTopWindow", &thunk_GetWindowHandle);
    br.register_thunk("user32.dll", "GetWindow", &thunk_ReturnZero);
    br.register_thunk("user32.dll", "FindWindowW", &thunk_ReturnZero);
    br.register_thunk("user32.dll", "GetWindowLongW", &thunk_ReturnZero);
    br.register_thunk("user32.dll", "GetWindowLongA", &thunk_ReturnZero);
    br.register_thunk("user32.dll", "GetWindowLongPtrA", &thunk_ReturnZero);
    br.register_thunk("user32.dll", "SetWindowLongW", &thunk_ReturnZero);
    br.register_thunk("user32.dll", "SetWindowTextW", &thunk_ReturnTrue);
    br.register_thunk("user32.dll", "GetWindowThreadProcessId", &thunk_GetWindowThreadProcessId);
    br.register_thunk("user32.dll", "IsZoomed", &thunk_ReturnZero);
    br.register_thunk("user32.dll", "AdjustWindowRect", &thunk_ReturnTrue);
    br.register_thunk("user32.dll", "ClientToScreen", &thunk_ReturnTrue);
    br.register_thunk("user32.dll", "ScreenToClient", &thunk_ReturnTrue);
    br.register_thunk("user32.dll", "GetCursorPos", &thunk_GetCursorPos);
    br.register_thunk("user32.dll", "SetCursorPos", &thunk_ReturnTrue);
    br.register_thunk("user32.dll", "SetCursor", &thunk_ReturnZero);
    br.register_thunk("user32.dll", "LoadCursorW", &thunk_ReturnTrue);
    br.register_thunk("user32.dll", "LoadIconW", &thunk_ReturnTrue);
    br.register_thunk("user32.dll", "GetDC", &thunk_ReturnTrue);
    br.register_thunk("user32.dll", "GetMessageW", &thunk_PeekMessage);
    br.register_thunk("user32.dll", "PostMessageW", &thunk_ReturnTrue);
    br.register_thunk("user32.dll", "SendMessageW", &thunk_ReturnZero);
    br.register_thunk("user32.dll", "GetMessageExtraInfo", &thunk_ReturnZero);
    br.register_thunk("user32.dll", "SetTimer", &thunk_ReturnTrue);
    br.register_thunk("user32.dll", "KillTimer", &thunk_ReturnTrue);
    br.register_thunk("user32.dll", "GetKeyboardState", &thunk_GetKeyboardState);
    br.register_thunk("user32.dll", "GetKeyboardLayout", &thunk_GetLocaleEnUs);
    br.register_thunk("user32.dll", "CharLowerBuffA", &thunk_CharLowerBuffA);
    br.register_thunk("user32.dll", "EnumDisplayDevicesA", &thunk_ReturnZero);
    br.register_thunk("user32.dll", "GetProcessWindowStation", &thunk_ReturnTrue);
    br.register_thunk("user32.dll", "GetUserObjectInformationW", &thunk_ReturnTrue);
    br.register_thunk("user32.dll", "OpenClipboard", &thunk_ReturnZero);
    br.register_thunk("user32.dll", "CloseClipboard", &thunk_ReturnTrue);
    br.register_thunk("user32.dll", "EmptyClipboard", &thunk_ReturnTrue);
    br.register_thunk("user32.dll", "GetClipboardData", &thunk_ReturnZero);
    br.register_thunk("user32.dll", "SetClipboardData", &thunk_ReturnZero);
    br.register_thunk("user32.dll", "MessageBoxW", &thunk_ReturnTrue);
    br.register_thunk("user32.dll", "SendInput", &thunk_ReturnZero);

    const char* gdi_syms[] = {
        "CreateBitmap", "CreateDCW", "CreateFontW", "DeleteDC", "DeleteObject",
        "EnumFontFamiliesExW", "ExtEscape", "GetGlyphOutlineW", "GetKerningPairsW",
        "GetTextMetricsW", "SelectObject"
    };
    for (const char* s : gdi_syms) br.register_thunk("gdi32.dll", s, &thunk_ReturnTrue);

    br.register_thunk("ole32.dll", "CoCreateGuid", &thunk_CoCreateGuid);
    br.register_thunk("ole32.dll", "CLSIDFromString", &thunk_ReturnZero);
    br.register_thunk("ole32.dll", "CoCreateInstance", &thunk_ReturnENotImpl);
    br.register_thunk("ole32.dll", "CoSetProxyBlanket", &thunk_ReturnZero);
    br.register_thunk("ole32.dll", "PropVariantClear", &thunk_ReturnZero);
    br.register_thunk("oleaut32.dll", "#2", &thunk_SysAllocString);
    br.register_thunk("oleaut32.dll", "#6", &thunk_SysFreeString);
    br.register_thunk("shell32.dll", "CommandLineToArgvW", &thunk_CommandLineToArgvW);
    br.register_thunk("shell32.dll", "ShellExecuteA", &thunk_ReturnZero);

    // Advapi32 & Crypt32 (offline-safe entropy, username, security descriptors & cert stubs)
    br.register_thunk("advapi32.dll", "CryptGenRandom", &thunk_CryptGenRandom);
    br.register_thunk("advapi32.dll", "SystemFunction036", &thunk_CryptGenRandom);
    br.register_thunk("advapi32.dll", "GetUserNameA", &thunk_GetUserNameA);
    br.register_thunk("advapi32.dll", "GetUserNameW", &thunk_GetUserNameW);
    br.register_thunk("advapi32.dll", "InitializeSecurityDescriptor", &thunk_ReturnTrue);
    br.register_thunk("advapi32.dll", "SetSecurityDescriptorDacl", &thunk_ReturnTrue);
    br.register_thunk("advapi32.dll", "RegOpenKeyA", &thunk_RegNotFound);
    br.register_thunk("advapi32.dll", "RegEnumKeyA", &thunk_RegNotFound);
    const char* adv_zero[] = {
        "CryptAcquireContextA", "CryptAcquireContextW", "CryptCreateHash", "CryptDecrypt",
        "CryptDestroyHash", "CryptDestroyKey", "CryptEnumProvidersW", "CryptExportKey",
        "CryptGetHashParam", "CryptGetProvParam", "CryptGetUserKey", "CryptHashData",
        "CryptReleaseContext", "CryptSetHashParam", "CryptSignHashW",
        "DeregisterEventSource", "RegisterEventSourceW", "ReportEventW"
    };
    for (const char* s : adv_zero) br.register_thunk("advapi32.dll", s, &thunk_ReturnZero);
    const char* crypt32_syms[] = {
        "CertCloseStore", "CertDuplicateCertificateContext", "CertEnumCertificatesInStore",
        "CertFindCertificateInStore", "CertFreeCertificateContext",
        "CertGetCertificateContextProperty", "CertOpenStore"
    };
    for (const char* s : crypt32_syms) br.register_thunk("crypt32.dll", s, &thunk_ReturnZero);

    // Offline-safe Winsock2 / Wsock32 / Wldap32 stubs (Sekiro runs offline cleanly)
    const char* ws2_ords[] = {
        "#1","#2","#3","#4","#5","#6","#7","#8","#9","#10","#11","#12","#13","#14","#15",
        "#16","#17","#18","#19","#20","#21","#22","#23","#51","#52","#55","#56","#57",
        "#111","#112","#115","#116","#151"
    };
    for (const char* o : ws2_ords) {
        NativeThunkFn fn = &thunk_ReturnNegOne;
        if (std::strcmp(o, "#115") == 0 || std::strcmp(o, "#116") == 0 || std::strcmp(o, "#3") == 0) fn = &thunk_ReturnZero;
        else if (std::strcmp(o, "#111") == 0) fn = &thunk_WsaNotConnected;
        br.register_thunk("ws2_32.dll", o, fn);
    }
    const char* ws2_named[] = {
        "WSACloseEvent", "WSACreateEvent", "WSAEnumNetworkEvents", "WSAEventSelect",
        "WSAResetEvent", "WSASetEvent", "WSASocketW", "WSAWaitForMultipleEvents",
        "freeaddrinfo", "getaddrinfo", "getnameinfo", "inet_ntop", "inet_pton"
    };
    for (const char* s : ws2_named) br.register_thunk("ws2_32.dll", s, &thunk_ReturnNegOne);

    const char* wsock_ords[] = {
        "#1","#2","#3","#4","#8","#9","#10","#11","#12","#13","#14","#15","#16","#18","#19",
        "#23","#103","#108","#111","#115","#116","#151"
    };
    for (const char* o : wsock_ords) {
        NativeThunkFn fn = &thunk_ReturnNegOne;
        if (std::strcmp(o, "#115") == 0 || std::strcmp(o, "#116") == 0 || std::strcmp(o, "#3") == 0) fn = &thunk_ReturnZero;
        else if (std::strcmp(o, "#111") == 0) fn = &thunk_WsaNotConnected;
        br.register_thunk("wsock32.dll", o, fn);
    }

    const char* wldap_ords[] = {
        "#22","#26","#27","#30","#32","#33","#35","#41","#46","#50","#60","#79","#143","#200","#211","#301"
    };
    for (const char* o : wldap_ords) br.register_thunk("wldap32.dll", o, &thunk_ReturnZero);
}
