// Clean-room Win64 x86_64 Direct3D 11 + XAudio2 + XInput 60 FPS self-test payload for Mobiro.
// Zero copyrighted assets, zero DRM, zero CRT dependencies (-nostdlib).
// Build: x86_64-w64-mingw32-gcc -O2 -Wall -Wextra -fno-builtin -nostdlib -e WinMainCRTStartup
//        tools/mobiro_selftest.c -o mobiro_selftest.exe -lkernel32 -luser32 -ld3d11 -ldxgi -lwinmm

#include <stdint.h>
#include "selftest_shaders_dxbc.h"

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

typedef struct {
    uint32_t byte_width;
    uint32_t usage;
    uint32_t bind_flags;
    uint32_t cpu_access;
    uint32_t misc_flags;
    uint32_t stride;
} D3D11_BUFFER_DESC;

typedef struct {
    void* data;
    uint32_t row_pitch;
    uint32_t depth_pitch;
} D3D11_MAPPED_SUBRESOURCE;

#pragma pack(push, 1)
typedef struct {
    uint16_t format_tag;
    uint16_t channels;
    uint32_t samples_per_sec;
    uint32_t avg_bytes_per_sec;
    uint16_t block_align;
    uint16_t bits_per_sample;
    uint16_t cb_size;
} WAVEFORMATEX;
#pragma pack(pop)

typedef struct {
    uint32_t flags;
    uint32_t audio_bytes;
    const uint8_t* audio_data;
    uint32_t play_begin;
    uint32_t play_length;
    uint32_t loop_begin;
    uint32_t loop_length;
    uint32_t loop_count;
    void* context;
} XAUDIO2_BUFFER;

typedef struct {
    const void* sys_mem;
    uint32_t sys_pitch;
    uint32_t sys_slice_pitch;
} D3D11_SUBRESOURCE_DATA;

typedef struct {
    uint32_t width, height, mip_levels, array_size, format;
    DXGI_SAMPLE_DESC sample_desc;
    uint32_t usage, bind_flags, cpu_access, misc_flags;
} D3D11_TEXTURE2D_DESC;

typedef struct {
    const char* semantic_name;
    uint32_t semantic_index;
    uint32_t format;
    uint32_t input_slot;
    uint32_t aligned_byte_offset;
    uint32_t input_slot_class;
    uint32_t instance_step_rate;
} D3D11_INPUT_ELEMENT_DESC;

typedef struct {
    uint32_t fill_mode, cull_mode;
    int32_t front_ccw, depth_bias;
    float depth_bias_clamp, slope_depth_bias;
    int32_t depth_clip_en, scissor_en, multisample_en, antialiased_ln;
} D3D11_RASTERIZER_DESC;

typedef struct {
    uint32_t filter, addr_u, addr_v, addr_w;
    float mip_lod_bias;
    uint32_t max_aniso, cmp_func;
    float border_color[4];
    float min_lod, max_lod;
} D3D11_SAMPLER_DESC;

typedef struct { float x, y, w, h, min_d, max_d; } D3D11_VIEWPORT;

typedef uint32_t (WINAPI *PFN_Release)(void* self);
typedef int32_t  (WINAPI *PFN_Present)(void* self, uint32_t sync, uint32_t flags);
typedef int32_t  (WINAPI *PFN_GetBuffer)(void* self, uint32_t idx, const GUID* riid, void** pp_surf);
typedef int32_t  (WINAPI *PFN_CreateBuffer)(void* self, const D3D11_BUFFER_DESC* desc, const D3D11_SUBRESOURCE_DATA* init, void** pp_buf);
typedef int32_t  (WINAPI *PFN_CreateTex2D)(void* self, const D3D11_TEXTURE2D_DESC* desc, const D3D11_SUBRESOURCE_DATA* init, void** pp_tex);
typedef int32_t  (WINAPI *PFN_CreateSRV)(void* self, void* res, const void* desc, void** pp_srv);
typedef int32_t  (WINAPI *PFN_CreateRTV)(void* self, void* res, const void* desc, void** pp_rtv);
typedef int32_t  (WINAPI *PFN_CreateDSV)(void* self, void* res, const void* desc, void** pp_dsv);
typedef int32_t  (WINAPI *PFN_CreateIL)(void* self, const D3D11_INPUT_ELEMENT_DESC* el, uint32_t n, const void* bc, uint64_t len, void** pp_il);
typedef int32_t  (WINAPI *PFN_CreateShader)(void* self, const void* bc, uint64_t len, void* link, void** pp_sh);
typedef int32_t  (WINAPI *PFN_CreateRS)(void* self, const D3D11_RASTERIZER_DESC* desc, void** pp_rs);
typedef int32_t  (WINAPI *PFN_CreateSamp)(void* self, const D3D11_SAMPLER_DESC* desc, void** pp_ss);
typedef void     (WINAPI *PFN_VSSetCB)(void* self, uint32_t start, uint32_t n, void* const* cbs);
typedef void     (WINAPI *PFN_PSSetSRV)(void* self, uint32_t start, uint32_t n, void* const* srvs);
typedef void     (WINAPI *PFN_SetShader)(void* self, void* sh, void* const* cls, uint32_t n);
typedef void     (WINAPI *PFN_PSSetSamp)(void* self, uint32_t start, uint32_t n, void* const* samps);
typedef void     (WINAPI *PFN_DrawIndexed)(void* self, uint32_t idx_cnt, uint32_t start_idx, int32_t base_vtx);
typedef int32_t  (WINAPI *PFN_Map)(void* self, void* res, uint32_t sub, uint32_t type, uint32_t flags, D3D11_MAPPED_SUBRESOURCE* out);
typedef void     (WINAPI *PFN_Unmap)(void* self, void* res, uint32_t sub);
typedef void     (WINAPI *PFN_IASetIL)(void* self, void* il);
typedef void     (WINAPI *PFN_IASetVB)(void* self, uint32_t start, uint32_t n, void* const* vbs, const uint32_t* strides, const uint32_t* offsets);
typedef void     (WINAPI *PFN_IASetIB)(void* self, void* ib, uint32_t fmt, uint32_t offset);
typedef void     (WINAPI *PFN_IASetTopo)(void* self, uint32_t topo);
typedef void     (WINAPI *PFN_OMSetRT)(void* self, uint32_t n, void* const* rtvs, void* dsv);
typedef void     (WINAPI *PFN_RSSetState)(void* self, void* rs);
typedef void     (WINAPI *PFN_RSSetVP)(void* self, uint32_t n, const D3D11_VIEWPORT* vps);
typedef void     (WINAPI *PFN_ClearRTV)(void* self, void* rtv, const float rgba[4]);
typedef void     (WINAPI *PFN_ClearDSV)(void* self, void* dsv, uint32_t flags, float depth, uint8_t stencil);

typedef int32_t  (WINAPI *PFN_XA27_Init)(void* self, uint32_t flags, uint32_t proc);
typedef int32_t  (WINAPI *PFN_XA27_CreateMaster)(void* self, void** pp, uint32_t ch, uint32_t rate, uint32_t flags, uint32_t dev_idx, const void* fx);
typedef int32_t  (WINAPI *PFN_XA27_CreateSource)(void* self, void** pp, const WAVEFORMATEX* fmt, uint32_t flags, float max_ratio, void* cb, const void* send, const void* fx);
typedef int32_t  (WINAPI *PFN_XAVoice_SetVol)(void* self, float vol, uint32_t op_set);
typedef void     (WINAPI *PFN_XAVoice_Destroy)(void* self);
typedef int32_t  (WINAPI *PFN_XASrc_Start)(void* self, uint32_t flags, uint32_t op_set);
typedef int32_t  (WINAPI *PFN_XASrc_Submit)(void* self, const XAUDIO2_BUFFER* buf, const void* wma);

static float approx_sin_turn(float turn) {
    while (turn >= 0.5f) turn -= 1.0f;
    while (turn < -0.5f) turn += 1.0f;
    float u = turn * 2.0f; // [-1, 1]
    float au = (u < 0.0f) ? -u : u;
    return 4.0f * u * (1.0f - au);
}

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

    void* xa2 = 0;
    void* xa_master = 0;
    void* xa_src = 0;
    static int16_t pcm_chirp[2400 * 2]; // 50 ms stereo 48 kHz soft triangle wave
    void* mod_xa = LoadLibraryA("xaudio2_7.dll");
    if (mod_xa) {
        PFN_XAudio2Create pfn_xa = (PFN_XAudio2Create)GetProcAddress(mod_xa, "XAudio2Create");
        if (pfn_xa && pfn_xa(&xa2, 0, 1) == 0 && xa2) {
            ((PFN_XA27_Init)((COM_OBJ*)xa2)->vtbl[5])(xa2, 0, 1);
            if (((PFN_XA27_CreateMaster)((COM_OBJ*)xa2)->vtbl[10])(xa2, &xa_master, 2, 48000, 0, 0, 0) == 0 && xa_master) {
                WAVEFORMATEX wfx;
                zero_bytes(&wfx, sizeof(wfx));
                wfx.format_tag = 1;
                wfx.channels = 2;
                wfx.samples_per_sec = 48000;
                wfx.bits_per_sample = 16;
                wfx.block_align = 4;
                wfx.avg_bytes_per_sec = 192000;
                if (((PFN_XA27_CreateSource)((COM_OBJ*)xa2)->vtbl[8])(xa2, &xa_src, &wfx, 0, 2.0f, 0, 0, 0) == 0 && xa_src) {
                    for (uint32_t i = 0; i < 2400; ++i) {
                        int32_t p = (int32_t)(i % 109);
                        int16_t s = (int16_t)((p < 54 ? p : (108 - p)) * 60 - 1620);
                        pcm_chirp[i * 2] = s;
                        pcm_chirp[i * 2 + 1] = s;
                    }
                    ((PFN_XAVoice_SetVol)((COM_OBJ*)xa_src)->vtbl[12])(xa_src, 0.25f, 0);
                    XAUDIO2_BUFFER xab;
                    zero_bytes(&xab, sizeof(xab));
                    xab.audio_bytes = sizeof(pcm_chirp);
                    xab.audio_data = (const uint8_t*)pcm_chirp;
                    ((PFN_XASrc_Submit)((COM_OBJ*)xa_src)->vtbl[21])(xa_src, &xab, 0);
                    ((PFN_XASrc_Start)((COM_OBJ*)xa_src)->vtbl[19])(xa_src, 0, 0);
                }
            }
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

    // Dynamic constant buffer to exercise CreateBuffer + Map/Unmap + VSSetConstantBuffers per frame
    D3D11_BUFFER_DESC cb_desc;
    zero_bytes(&cb_desc, sizeof(cb_desc));
    cb_desc.byte_width = 64;
    cb_desc.usage = 2;             // D3D11_USAGE_DYNAMIC
    cb_desc.bind_flags = 4;        // D3D11_BIND_CONSTANT_BUFFER
    cb_desc.cpu_access = 0x10000u; // D3D11_CPU_ACCESS_WRITE
    void* cb = 0;
    ((PFN_CreateBuffer)((COM_OBJ*)dev)->vtbl[3])(dev, &cb_desc, 0, &cb);

    // Real 3D D3D11 pipeline: DXBC VS/PS, InputLayout, VB/IB (pyramid), D24S8 depth, 64x64 texture, Sampler, RS
    void *vs = 0, *ps = 0, *il = 0, *vb = 0, *ib = 0;
    void *depth_tex = 0, *dsv = 0, *albedo_tex = 0, *srv = 0, *samp = 0, *rs = 0;
    ((PFN_CreateShader)((COM_OBJ*)dev)->vtbl[12])(dev, kSelftestVsDxbc, sizeof(kSelftestVsDxbc), 0, &vs);
    ((PFN_CreateShader)((COM_OBJ*)dev)->vtbl[15])(dev, kSelftestPsDxbc, sizeof(kSelftestPsDxbc), 0, &ps);

    static const D3D11_INPUT_ELEMENT_DESC kLayout[2] = {
        {"POSITION", 0, 6u,  0, 0,  0, 0}, // DXGI_FORMAT_R32G32B32_FLOAT
        {"TEXCOORD", 0, 16u, 0, 12, 0, 0}, // DXGI_FORMAT_R32G32_FLOAT
    };
    if (vs) {
        ((PFN_CreateIL)((COM_OBJ*)dev)->vtbl[11])(dev, kLayout, 2, kSelftestVsDxbc, sizeof(kSelftestVsDxbc), &il);
    }

    static const float kVerts[5 * 5] = {
         0.0f,  0.75f,  0.0f, 0.5f, 0.0f,
        -0.7f, -0.55f, -0.7f, 0.0f, 1.0f,
         0.7f, -0.55f, -0.7f, 1.0f, 1.0f,
         0.7f, -0.55f,  0.7f, 0.0f, 1.0f,
        -0.7f, -0.55f,  0.7f, 1.0f, 1.0f,
    };
    static const uint16_t kIndices[18] = {
        0, 1, 2,  0, 2, 3,  0, 3, 4,  0, 4, 1,  1, 3, 2,  1, 4, 3
    };
    D3D11_BUFFER_DESC vbd; zero_bytes(&vbd, sizeof(vbd));
    vbd.byte_width = sizeof(kVerts); vbd.bind_flags = 1; // VERTEX_BUFFER
    D3D11_SUBRESOURCE_DATA vinit = {kVerts, 0, 0};
    ((PFN_CreateBuffer)((COM_OBJ*)dev)->vtbl[3])(dev, &vbd, &vinit, &vb);

    D3D11_BUFFER_DESC ibd; zero_bytes(&ibd, sizeof(ibd));
    ibd.byte_width = sizeof(kIndices); ibd.bind_flags = 2; // INDEX_BUFFER
    D3D11_SUBRESOURCE_DATA iinit = {kIndices, 0, 0};
    ((PFN_CreateBuffer)((COM_OBJ*)dev)->vtbl[3])(dev, &ibd, &iinit, &ib);

    D3D11_TEXTURE2D_DESC dtd; zero_bytes(&dtd, sizeof(dtd));
    dtd.width = 1280; dtd.height = 720; dtd.mip_levels = 1; dtd.array_size = 1;
    dtd.format = 45; // DXGI_FORMAT_D24_UNORM_S8_UINT
    dtd.sample_desc.count = 1; dtd.bind_flags = 0x40u; // DEPTH_STENCIL
    if (((PFN_CreateTex2D)((COM_OBJ*)dev)->vtbl[5])(dev, &dtd, 0, &depth_tex) == 0 && depth_tex) {
        ((PFN_CreateDSV)((COM_OBJ*)dev)->vtbl[10])(dev, depth_tex, 0, &dsv);
    }

    static uint32_t tex_pixels[64 * 64];
    for (uint32_t y = 0; y < 64; ++y) {
        for (uint32_t x = 0; x < 64; ++x) {
            const uint32_t chk = ((x >> 3) ^ (y >> 3)) & 1u;
            tex_pixels[y * 64 + x] = chk ? 0xFFF2C85Bu : 0xFF385A8Cu;
        }
    }
    D3D11_TEXTURE2D_DESC ttd; zero_bytes(&ttd, sizeof(ttd));
    ttd.width = 64; ttd.height = 64; ttd.mip_levels = 1; ttd.array_size = 1;
    ttd.format = 28; // DXGI_FORMAT_R8G8B8A8_UNORM
    ttd.sample_desc.count = 1; ttd.bind_flags = 8; // SHADER_RESOURCE
    D3D11_SUBRESOURCE_DATA tinit = {tex_pixels, 64 * 4, 0};
    if (((PFN_CreateTex2D)((COM_OBJ*)dev)->vtbl[5])(dev, &ttd, &tinit, &albedo_tex) == 0 && albedo_tex) {
        ((PFN_CreateSRV)((COM_OBJ*)dev)->vtbl[7])(dev, albedo_tex, 0, &srv);
    }

    D3D11_SAMPLER_DESC sdesc; zero_bytes(&sdesc, sizeof(sdesc));
    sdesc.filter = 0x15u; // MIN_MAG_MIP_LINEAR
    sdesc.addr_u = sdesc.addr_v = sdesc.addr_w = 1; // WRAP
    sdesc.max_aniso = 1; sdesc.cmp_func = 1; sdesc.max_lod = 3.4e38f;
    ((PFN_CreateSamp)((COM_OBJ*)dev)->vtbl[23])(dev, &sdesc, &samp);

    D3D11_RASTERIZER_DESC rdesc; zero_bytes(&rdesc, sizeof(rdesc));
    rdesc.fill_mode = 3; // SOLID
    rdesc.cull_mode = 1; // NONE
    rdesc.depth_clip_en = 1;
    ((PFN_CreateRS)((COM_OBJ*)dev)->vtbl[22])(dev, &rdesc, &rs);

    D3D11_VIEWPORT vp = {0.0f, 0.0f, 1280.0f, 720.0f, 0.0f, 1.0f};
    const uint32_t vb_stride = 20u, vb_offset = 0u;

    // 120-frame 60 FPS 3D render (64 DrawIndexed/frame = 7,680 draws), buffer update & input pacing loop
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
        rgba[0] = 0.08f + 0.12f * ((float)(frame % 60) / 60.0f);
        rgba[1] = (pad.pad.buttons != 0) ? 0.35f : 0.10f;
        rgba[2] = 0.18f;
        rgba[3] = 1.0f;

        if (cb) {
            D3D11_MAPPED_SUBRESOURCE mapped;
            zero_bytes(&mapped, sizeof(mapped));
            if (((PFN_Map)((COM_OBJ*)ctx)->vtbl[14])(ctx, cb, 0, 4, 0, &mapped) == 0 && mapped.data) {
                const float turn = (float)frame / 120.0f;
                float* dst = (float*)mapped.data;
                dst[0] = approx_sin_turn(turn + 0.25f); // cos
                dst[1] = approx_sin_turn(turn);         // sin
                dst[2] = 1.55f;                         // scale
                dst[3] = (float)(frame % 60) / 60.0f;   // tint phase
                ((PFN_Unmap)((COM_OBJ*)ctx)->vtbl[15])(ctx, cb, 0);
            }
            ((PFN_VSSetCB)((COM_OBJ*)ctx)->vtbl[7])(ctx, 0, 1, &cb);
        }

        ((PFN_OMSetRT)((COM_OBJ*)ctx)->vtbl[33])(ctx, 1, &rtv, dsv);
        ((PFN_RSSetVP)((COM_OBJ*)ctx)->vtbl[44])(ctx, 1, &vp);
        ((PFN_ClearRTV)((COM_OBJ*)ctx)->vtbl[50])(ctx, rtv, rgba);
        if (dsv) ((PFN_ClearDSV)((COM_OBJ*)ctx)->vtbl[53])(ctx, dsv, 1u, 1.0f, 0u);

        if (vs && ps && il && vb && ib) {
            if (rs)   ((PFN_RSSetState)((COM_OBJ*)ctx)->vtbl[43])(ctx, rs);
            ((PFN_IASetIL)((COM_OBJ*)ctx)->vtbl[17])(ctx, il);
            ((PFN_IASetVB)((COM_OBJ*)ctx)->vtbl[18])(ctx, 0, 1, &vb, &vb_stride, &vb_offset);
            ((PFN_IASetIB)((COM_OBJ*)ctx)->vtbl[19])(ctx, ib, 57u, 0u); // DXGI_FORMAT_R16_UINT
            ((PFN_IASetTopo)((COM_OBJ*)ctx)->vtbl[24])(ctx, 4u);        // TRIANGLELIST
            ((PFN_SetShader)((COM_OBJ*)ctx)->vtbl[11])(ctx, vs, 0, 0);
            ((PFN_SetShader)((COM_OBJ*)ctx)->vtbl[9])(ctx, ps, 0, 0);
            if (srv)  ((PFN_PSSetSRV)((COM_OBJ*)ctx)->vtbl[8])(ctx, 0, 1, &srv);
            if (samp) ((PFN_PSSetSamp)((COM_OBJ*)ctx)->vtbl[10])(ctx, 0, 1, &samp);
            for (uint32_t d = 0; d < 64; ++d) {
                ((PFN_DrawIndexed)((COM_OBJ*)ctx)->vtbl[12])(ctx, 18u, 0u, 0);
            }
        }
        ((PFN_Present)((COM_OBJ*)sc)->vtbl[8])(sc, 1, 0);
    }

done:
    if (xa_src) ((PFN_XAVoice_Destroy)((COM_OBJ*)xa_src)->vtbl[18])(xa_src);
    if (xa_master) ((PFN_XAVoice_Destroy)((COM_OBJ*)xa_master)->vtbl[18])(xa_master);
    com_release(xa2);
    com_release(rs);
    com_release(samp);
    com_release(srv);
    com_release(albedo_tex);
    com_release(dsv);
    com_release(depth_tex);
    com_release(ib);
    com_release(vb);
    com_release(il);
    com_release(ps);
    com_release(vs);
    com_release(cb);
    com_release(rtv);
    com_release(ctx);
    com_release(dev);
    com_release(sc);
    ExitProcess(0);
}
