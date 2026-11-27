// Clean-room Win64 x86_64 Direct3D 11 + XAudio2 + XInput 60 FPS self-test payload for Mobiro.
// Zero copyrighted assets, zero DRM, zero CRT dependencies (-nostdlib).
// Build: x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -fno-builtin -nostdlib -e WinMainCRTStartup \
//          tools/mobiro_selftest.c -o mobiro_selftest.exe -lkernel32 -luser32 -ld3d11 -ldxgi -lwinmm

#include <stdint.h>

#define DLLIMP __declspec(dllimport)
#define WINAPI __stdcall

typedef struct { uint32_t d1; uint16_t d2, d3; uint8_t d4[8]; } GUID;
typedef struct { uint32_t w, h, num, den, fmt, scan, scaling; } DXGI_MODE_DESC;
typedef struct { uint32_t count, quality; } DXGI_SAMPLE_DESC;
typedef struct {
    DXGI_MODE_DESC buf_desc;
    DXGI_SAMPLE_DESC sample_desc;
    uint32_t usage;
    uint32_t buf_count;
    void* output_wnd;
    int32_t windowed;
    uint32_t swap_effect;
    uint32_t flags;
} DXGI_SWAP_CHAIN_DESC;

typedef struct {
    uint16_t buttons;
    uint8_t lt, rt;
    int16_t lx, ly, rx, ry;
} XINPUT_GAMEPAD;

typedef struct {
    uint32_t packet;
    XINPUT_GAMEPAD pad;
} XINPUT_STATE;

typedef struct {
    void* hwnd;
    uint32_t msg;
    uint64_t wparam;
    int64_t lparam;
    uint32_t time;
    int32_t pt_x, pt_y;
} WIN_MSG;

typedef struct { void** vtbl; } COM_OBJ;

DLLIMP int32_t WINAPI QueryPerformanceFrequency(int64_t* freq);
DLLIMP int32_t WINAPI QueryPerformanceCounter(int64_t* cnt);
DLLIMP void*   WINAPI LoadLibraryA(const char* name);
DLLIMP void*   WINAPI GetProcAddress(void* mod, const char* sym);
DLLIMP void    WINAPI ExitProcess(uint32_t code);

DLLIMP void*   WINAPI CreateWindowExW(uint32_t ex, const uint16_t* cls, const uint16_t* title,
                                      uint32_t style, int32_t x, int32_t y, int32_t w, int32_t h,
                                      void* parent, void* menu, void* inst, void* param);
DLLIMP int32_t WINAPI PeekMessageW(WIN_MSG* msg, void* hwnd, uint32_t lo, uint32_t hi, uint32_t rem);
DLLIMP int64_t WINAPI DispatchMessageW(const WIN_MSG* msg);

DLLIMP int32_t WINAPI CreateDXGIFactory1(const GUID* riid, void** pp_factory);
DLLIMP int32_t WINAPI D3D11CreateDeviceAndSwapChain(
    void* adapter, uint32_t driver_type, void* sw, uint32_t flags,
    const uint32_t* feat_levels, uint32_t num_levels, uint32_t sdk_ver,
    const DXGI_SWAP_CHAIN_DESC* sc_desc, void** pp_sc, void** pp_dev,
    uint32_t* out_lvl, void** pp_ctx);

DLLIMP uint32_t WINAPI timeGetTime(void);
DLLIMP uint32_t WINAPI waveOutGetNumDevs(void);

typedef uint32_t (WINAPI *PFN_XInputGetState)(uint32_t idx, XINPUT_STATE* st);
typedef int32_t  (WINAPI *PFN_XAudio2Create)(void** pp_xa2, uint32_t flags, uint32_t proc);

typedef uint32_t (WINAPI *PFN_Release)(void* self);
typedef int32_t  (WINAPI *PFN_Present)(void* self, uint32_t sync, uint32_t flags);
typedef int32_t  (WINAPI *PFN_GetBuffer)(void* self, uint32_t idx, const GUID* riid, void** pp_surf);
typedef int32_t  (WINAPI *PFN_CreateRTV)(void* self, void* res, const void* desc, void** pp_rtv);
typedef void     (WINAPI *PFN_OMSetRT)(void* self, uint32_t n, void* const* rtvs, void* dsv);
typedef void     (WINAPI *PFN_ClearRTV)(void* self, void* rtv, const float rgba[4]);

static void zero_bytes(void* p, uint32_t n) {
    uint8_t* b = (uint8_t*)p;
    for (uint32_t i = 0; i < n; ++i) b[i] = 0;
}

static void com_release(void* obj) {
    if (!obj) return;
    COM_OBJ* c = (COM_OBJ*)obj;
    ((PFN_Release)c->vtbl[2])(obj);
}

void WinMainCRTStartup(void) {
    static const GUID kIID_IDXGIFactory1 = {
        0x770aae78u, 0xf26fu, 0x4dbau, {0xa8u, 0x29u, 0x25u, 0x3cu, 0x83u, 0xd1u, 0xb3u, 0x87u}
    };
    static const GUID kIID_ID3D11Texture2D = {
        0x6f15aaf2u, 0xd208u, 0x4e89u, {0x9au, 0xb4u, 0x48u, 0x95u, 0x35u, 0xd3u, 0x4fu, 0x9cu}
    };
    static const uint16_t kTitle[] = {'M','o','b','i','r','o',' ','6','0','F','P','S',' ','S','e','l','f','T','e','s','t',0};

    int64_t qpf = 0, t0 = 0;
    QueryPerformanceFrequency(&qpf);
    QueryPerformanceCounter(&t0);
    (void)timeGetTime();
    (void)waveOutGetNumDevs();

    void* hwnd = CreateWindowExW(0, kTitle, kTitle, 0x10000000u, 0, 0, 1280, 720, 0, 0, 0, 0);

    // Probe DXGI factory creation
    void* factory = 0;
    if (CreateDXGIFactory1(&kIID_IDXGIFactory1, &factory) == 0 && factory) {
        com_release(factory);
    }

    // Dynamic LoadLibraryA + GetProcAddress probes for XInput & XAudio2
    PFN_XInputGetState pfn_xinput = 0;
    void* mod_xi = LoadLibraryA("xinput1_3.dll");
    if (mod_xi) pfn_xinput = (PFN_XInputGetState)GetProcAddress(mod_xi, "XInputGetState");

    void* mod_xa = LoadLibraryA("xaudio2_7.dll");
    if (mod_xa) {
        PFN_XAudio2Create pfn_xa = (PFN_XAudio2Create)GetProcAddress(mod_xa, "XAudio2Create");
        void* xa2 = 0;
        if (pfn_xa && pfn_xa(&xa2, 0, 1) == 0 && xa2) {
            com_release(xa2);
        }
    }

    // Create D3D11 device + swapchain + backbuffer RTV
    DXGI_SWAP_CHAIN_DESC scd;
    zero_bytes(&scd, sizeof(scd));
    scd.buf_desc.w = 1280;
    scd.buf_desc.h = 720;
    scd.buf_desc.num = 60;
    scd.buf_desc.den = 1;
    scd.buf_desc.fmt = 28; // DXGI_FORMAT_R8G8B8A8_UNORM
    scd.sample_desc.count = 1;
    scd.usage = 0x20u; // DXGI_USAGE_RENDER_TARGET_OUTPUT
    scd.buf_count = 2;
    scd.output_wnd = hwnd;
    scd.windowed = 1;

    const uint32_t fl = 0xb000u; // D3D_FEATURE_LEVEL_11_0
    uint32_t got_fl = 0;
    void *sc = 0, *dev = 0, *ctx = 0;
    int32_t hr = D3D11CreateDeviceAndSwapChain(
        0, 1, 0, 0, &fl, 1, 7, &scd, &sc, &dev, &got_fl, &ctx);
    if (hr != 0 || !sc || !dev || !ctx) {
        ExitProcess(2);
    }

    void* backbuf = 0;
    void* rtv = 0;
    hr = ((PFN_GetBuffer)((COM_OBJ*)sc)->vtbl[9])(sc, 0, &kIID_ID3D11Texture2D, &backbuf);
    if (hr == 0 && backbuf) {
        hr = ((PFN_CreateRTV)((COM_OBJ*)dev)->vtbl[9])(dev, backbuf, 0, &rtv);
        com_release(backbuf);
    }
    if (hr != 0 || !rtv) {
        com_release(ctx);
        com_release(dev);
        com_release(sc);
        ExitProcess(3);
    }

    // 120-frame 60 FPS render & input pacing loop
    for (uint32_t frame = 0; frame < 120; ++frame) {
        WIN_MSG msg;
        zero_bytes(&msg, sizeof(msg));
        while (PeekMessageW(&msg, 0, 0, 0, 1)) {
            if (msg.msg == 0x0012u) goto done; // WM_QUIT
            DispatchMessageW(&msg);
        }

        XINPUT_STATE pad;
        zero_bytes(&pad, sizeof(pad));
        if (pfn_xinput) pfn_xinput(0, &pad);

        float rgba[4];
        rgba[0] = (float)(frame % 60) / 60.0f;
        rgba[1] = (pad.pad.buttons != 0) ? 0.85f : 0.20f;
        rgba[2] = 0.45f;
        rgba[3] = 1.0f;

        ((PFN_OMSetRT)((COM_OBJ*)ctx)->vtbl[33])(ctx, 1, &rtv, 0);
        ((PFN_ClearRTV)((COM_OBJ*)ctx)->vtbl[50])(ctx, rtv, rgba);
        ((PFN_Present)((COM_OBJ*)sc)->vtbl[8])(sc, 1, 0);
    }

done:
    com_release(rtv);
    com_release(ctx);
    com_release(dev);
    com_release(sc);
    ExitProcess(0);
}
