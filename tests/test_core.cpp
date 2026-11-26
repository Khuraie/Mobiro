#undef NDEBUG
#include "audio/aaudio_xaudio_bridge.hpp"
#include "audio/winmm_waveout_bridge.hpp"
#include "audio/xaudio2_com.hpp"
#include "audio/xaudio2_com_bridge.hpp"
#include "cpu_mem/box64_bridge.hpp"
#include "cpu_mem/guest_arena.hpp"
#include "cpu_mem/guest_executor.hpp"
#include "cpu_mem/pe_loader.hpp"
#include "cpu_mem/win64_teb.hpp"
#include "gfx/d3d11_com_bridge.hpp"
#include "gfx/dxvk_config_gen.hpp"
#include "gfx/dxvk_interop.hpp"
#include "gfx/pipeline_cache_warmer.hpp"
#include "gfx/touch_overlay_vk.hpp"
#include "cpu_mem/win32_ext_shims.hpp"
#include "input/input_router.hpp"
#include "input/touch_controller.hpp"
#include "sched/thread_balancer.hpp"
#include "validator/archive_probe.hpp"
#include "validator/pe_validator.hpp"
#include "validator/vfs_mapper.hpp"

#include <cassert>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

namespace fs = std::filesystem;

namespace {

void wr16(std::vector<uint8_t>& buf, size_t off, uint16_t v) {
    buf[off] = static_cast<uint8_t>(v & 0xFF);
    buf[off + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
}
void wr32(std::vector<uint8_t>& buf, size_t off, uint32_t v) {
    for (int i = 0; i < 4; ++i) buf[off + i] = static_cast<uint8_t>((v >> (i * 8)) & 0xFF);
}
void wr64(std::vector<uint8_t>& buf, size_t off, uint64_t v) {
    for (int i = 0; i < 8; ++i) buf[off + i] = static_cast<uint8_t>((v >> (i * 8)) & 0xFF);
}

// Constructs a synthetic PE32+ (x86_64) image with:
//   Section 0 (.rdata, RVA 0x1000): Import Directory (d3d11.dll + kernel32.dll) + IAT
//   Section 1 (.data,  RVA 0x2000): 64-bit pointer requiring DIR64 base relocation
//   Section 2 (.reloc, RVA 0x3000): Base relocation block patching .data+0x00
void write_synthetic_pe64(const fs::path& path, bool include_d3d11_import) {
    std::vector<uint8_t> img(0x1400, 0);
    img[0] = 'M'; img[1] = 'Z';
    const uint32_t pe_off = 0x80;
    wr32(img, 0x3C, pe_off);

    img[pe_off] = 'P'; img[pe_off + 1] = 'E';
    const size_t coff = pe_off + 4;
    wr16(img, coff + 0, 0x8664); // AMD64
    wr16(img, coff + 2, 3);      // 3 sections
    const uint16_t opt_size = 0xF0;
    wr16(img, coff + 16, opt_size);

    const size_t opt = coff + 20;
    constexpr uint64_t kPrefBase = 0x0000000140000000ULL;
    wr16(img, opt + 0, 0x020B);      // PE32+
    wr32(img, opt + 16, 0x1000);     // EntryPoint RVA
    wr64(img, opt + 24, kPrefBase);  // ImageBase
    wr32(img, opt + 56, 0x4000);     // SizeOfImage
    wr32(img, opt + 60, 0x400);      // SizeOfHeaders
    wr32(img, opt + 108, 16);        // NumberOfRvaAndSizes

    if (include_d3d11_import) {
        wr32(img, opt + 112 + 1 * 8, 0x1000); // DataDirectory[1] Import RVA
        wr32(img, opt + 112 + 1 * 8 + 4, 60); // Import Size
    }
    wr32(img, opt + 112 + 5 * 8, 0x3000);     // DataDirectory[5] BaseReloc RVA
    wr32(img, opt + 112 + 5 * 8 + 4, 12);     // BaseReloc Size

    const size_t sec0 = opt + opt_size;
    // .rdata (VA 0x1000, Raw 0x400, Size 0x400, R)
    std::memcpy(&img[sec0], ".rdata", 6);
    wr32(img, sec0 + 8, 0x400);
    wr32(img, sec0 + 12, 0x1000);
    wr32(img, sec0 + 16, 0x400);
    wr32(img, sec0 + 20, 0x400);
    wr32(img, sec0 + 36, 0x40000040u); // READ | INITIALIZED_DATA

    // .data (VA 0x2000, Raw 0x800, Size 0x400, RW)
    const size_t sec1 = sec0 + 40;
    std::memcpy(&img[sec1], ".data", 5);
    wr32(img, sec1 + 8, 0x400);
    wr32(img, sec1 + 12, 0x2000);
    wr32(img, sec1 + 16, 0x400);
    wr32(img, sec1 + 20, 0x800);
    wr32(img, sec1 + 36, 0xC0000040u); // READ | WRITE

    // .reloc (VA 0x3000, Raw 0xC00, Size 0x400, R)
    const size_t sec2 = sec1 + 40;
    std::memcpy(&img[sec2], ".reloc", 6);
    wr32(img, sec2 + 8, 0x400);
    wr32(img, sec2 + 12, 0x3000);
    wr32(img, sec2 + 16, 0x400);
    wr32(img, sec2 + 20, 0xC00);
    wr32(img, sec2 + 36, 0x42000040u); // READ | DISCARDABLE

    if (include_d3d11_import) {
        // Descriptor 0: d3d11.dll -> D3D11CreateDevice
        wr32(img, 0x400 + 0,  0x1100); // OriginalFirstThunk
        wr32(img, 0x400 + 12, 0x1080); // Name RVA
        wr32(img, 0x400 + 16, 0x1140); // FirstThunk (IAT)

        // Descriptor 1: kernel32.dll -> VirtualAlloc + UnknownFunc
        wr32(img, 0x400 + 20 + 0,  0x1110);
        wr32(img, 0x400 + 20 + 12, 0x10A0);
        wr32(img, 0x400 + 20 + 16, 0x1150);

        std::memcpy(&img[0x480], "d3d11.dll", 10);
        std::memcpy(&img[0x4A0], "kernel32.dll", 13);

        // Thunk lookup tables
        wr64(img, 0x500, 0x1200); // d3d11[0] -> IBN at RVA 0x1200
        wr64(img, 0x510, 0x1220); // k32[0]   -> IBN at RVA 0x1220
        wr64(img, 0x518, 0x1240); // k32[1]   -> IBN at RVA 0x1240 (unresolved)

        // Import-By-Name records (2-byte hint + ASCII name)
        std::memcpy(&img[0x600 + 2], "D3D11CreateDevice", 18);
        std::memcpy(&img[0x620 + 2], "VirtualAlloc", 13);
        std::memcpy(&img[0x640 + 2], "UnimplementedWin32Api", 22);
    }

    // .data+0x00 holds a 64-bit pointer to kPrefBase + 0x2080
    wr64(img, 0x800, kPrefBase + 0x2080);

    // .reloc block: PageRVA=0x2000, BlockSize=12, Entry0=(DIR64<<12 | 0x000), Entry1=0
    wr32(img, 0xC00 + 0, 0x2000);
    wr32(img, 0xC00 + 4, 12);
    wr16(img, 0xC00 + 8, static_cast<uint16_t>((10u << 12) | 0x000u));
    wr16(img, 0xC00 + 10, 0);

    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(img.data()), static_cast<std::streamsize>(img.size()));
}

void test_byof_validator_and_vfs() {
    const fs::path tmp = fs::temp_directory_path() / "mobiro_test_byof";
    fs::remove_all(tmp);
    fs::create_directories(tmp / "movie");

    write_synthetic_pe64(tmp / "Sekiro.exe", true);
    for (int i = 0; i <= 5; ++i) {
        std::ofstream bhd(tmp / ("Data" + std::to_string(i) + ".bhd"), std::ios::binary);
        bhd << "ENCRYPTED_HEADER_STUB";
        std::ofstream bdt(tmp / ("Data" + std::to_string(i) + ".bdt"), std::ios::binary);
        bdt.write("BDF4\0\0\0\0ABCDEFGH", 16);
    }

    mobiro::validator::VfsMapper vfs;
    auto rep = mobiro::validator::validate_byof_directory(tmp.string(), vfs);
    assert(rep.ok);
    assert(rep.verified_archive_pairs == 6);
    assert(rep.pe.preferred_image_base == 0x0000000140000000ULL);
    assert(!rep.pe.build_fingerprint.empty());

    std::string host_path;
    assert(vfs.resolve("C:\\DATA3.BDT", host_path));
    assert(vfs.resolve("SEKIRO.EXE", host_path));

    // Retail PC Sekiro ships Data1..Data5 without Data0: removing Data0 must still validate
    fs::remove(tmp / "Data0.bhd");
    fs::remove(tmp / "Data0.bdt");
    auto retail_rep = mobiro::validator::validate_byof_directory(tmp.string(), vfs);
    assert(retail_rep.ok && retail_rep.verified_archive_pairs == 5);

    // Truncated/corrupt archive should fail cleanly
    {
        std::ofstream bad_bdt(tmp / "Data2.bdt", std::ios::binary | std::ios::trunc);
        bad_bdt.write("BAD", 3);
    }
    auto bad_rep = mobiro::validator::validate_byof_directory(tmp.string(), vfs);
    assert(!bad_rep.ok);

    fs::remove_all(tmp);
}

void test_pe_loader_teb_and_win32_thunks() {
    const fs::path tmp = fs::temp_directory_path() / "mobiro_test_pe_load";
    fs::remove_all(tmp);
    fs::create_directories(tmp);
    write_synthetic_pe64(tmp / "Sekiro.exe", true);
    {
        std::ofstream bdt(tmp / "Data0.bdt", std::ios::binary);
        bdt.write("BDF4\0\0\0\0SEKIRO!!", 16);
    }

    mobiro::validator::VfsMapper vfs;
    assert(vfs.index_root(tmp.string()));

    mobiro::mem::GuestArena arena;
    assert(arena.reserve(0x0000000100000000ULL, 128ULL * 1024 * 1024));

    mobiro::cpu::Box64Bridge bridge;
    assert(bridge.initialize(&arena, &vfs));

    // 1. Load PE64 with forced relocation so DIR64 relocation path is exercised
    std::string exe_path;
    assert(vfs.resolve("sekiro.exe", exe_path));
    auto loaded = mobiro::cpu::PeLoader::load_pe64(exe_path, arena, bridge, /*force_relocate=*/true);
    assert(loaded.ok);
    assert(loaded.relocations_applied == 1);
    assert(loaded.imports_resolved == 2); // D3D11CreateDevice + VirtualAlloc
    assert(loaded.unresolved_imports.size() == 1);
    assert(loaded.unresolved_imports[0] == "kernel32.dll!UnimplementedWin32Api");

    // Verify DIR64 relocated pointer inside mapped .data+0x00
    uint64_t relocated_ptr = 0;
    std::memcpy(&relocated_ptr, reinterpret_cast<const void*>(loaded.mapped_base + 0x2000), 8);
    assert(relocated_ptr == loaded.mapped_base + 0x2080);

    // Verify IAT slot for d3d11!D3D11CreateDevice was patched with a valid NativeBridgeStub
    uint64_t iat_d3d11 = 0;
    std::memcpy(&iat_d3d11, reinterpret_cast<const void*>(loaded.mapped_base + 0x1140), 8);
    assert(iat_d3d11 != 0);
    auto* stub = reinterpret_cast<const mobiro::cpu::NativeBridgeStub*>(iat_d3d11);
    assert(stub->trap_cc == 0xCC && stub->magic[0] == 'S' && stub->magic[1] == 'C' && stub->wrapper_ptr != 0);

    // 2. Initialize Win64 TEB/PEB and test TLS + GetModuleHandleW + QPC thunks
    bridge.set_main_module_base(loaded.mapped_base);
    mobiro::cpu::Win64ThreadEnv tenv;
    assert(tenv.init_main_thread(arena, loaded.mapped_base, 8, 4242, 7777));
    bridge.set_main_teb(tenv.teb);

    assert(tenv.teb->self_ptr == reinterpret_cast<uintptr_t>(tenv.teb));
    assert(tenv.teb->peb_ptr == reinterpret_cast<uintptr_t>(tenv.peb));
    assert(tenv.peb->image_base_address == loaded.mapped_base);

    x64emu_t emu{};
    emu.gs_base = reinterpret_cast<uint64_t>(tenv.teb);

    assert(bridge.invoke_thunk("kernel32.dll", "GetModuleHandleW", &emu));
    assert(emu.rax == loaded.mapped_base);

    assert(bridge.invoke_thunk("kernel32.dll", "TlsAlloc", &emu));
    const uint64_t tls_slot = emu.rax;
    assert(tls_slot == 0);

    emu.rcx = tls_slot;
    emu.rdx = 0xDEADBEEFCAFEBABEULL;
    assert(bridge.invoke_thunk("kernel32.dll", "TlsSetValue", &emu));
    assert(emu.rax == 1);

    emu.rcx = tls_slot;
    assert(bridge.invoke_thunk("kernel32.dll", "TlsGetValue", &emu));
    assert(emu.rax == 0xDEADBEEFCAFEBABEULL);

    int64_t qpc_freq = 0, qpc_val = 0;
    emu.rcx = reinterpret_cast<uint64_t>(&qpc_freq);
    assert(bridge.invoke_thunk("kernel32.dll", "QueryPerformanceFrequency", &emu));
    assert(emu.rax == 1 && qpc_freq == 10'000'000LL);
    emu.rcx = reinterpret_cast<uint64_t>(&qpc_val);
    assert(bridge.invoke_thunk("kernel32.dll", "QueryPerformanceCounter", &emu));
    assert(emu.rax == 1 && qpc_val > 0);

    // 3. Test VFS-backed Win32 CreateFileW + GetFileSizeEx + ReadFile (OVERLAPPED) + CloseHandle
    const uint16_t wpath[] = {'C', ':', '\\', 'D', 'a', 't', 'a', '0', '.', 'b', 'd', 't', 0};
    emu.rcx = reinterpret_cast<uint64_t>(wpath);
    emu.rdx = 0x80000000u; // GENERIC_READ
    assert(bridge.invoke_thunk("kernel32.dll", "CreateFileW", &emu));
    const uint64_t hfile = emu.rax;
    assert(hfile != mobiro::win32::FileHandleTable::kInvalidHandle);

    int64_t fsize = 0;
    emu.rcx = hfile;
    emu.rdx = reinterpret_cast<uint64_t>(&fsize);
    assert(bridge.invoke_thunk("kernel32.dll", "GetFileSizeEx", &emu));
    assert(emu.rax == 1 && fsize == 16);

    char read_buf[9]{};
    uint32_t bytes_read = 0;
    mobiro::win32::Win64Overlapped ov{};
    ov.offset = 8; // Read "SEKIRO!!" starting at offset 8
    uint64_t fake_stack[8]{};
    fake_stack[5] = reinterpret_cast<uint64_t>(&ov); // Win64 5th arg at [RSP+0x28]
    emu.rcx = hfile;
    emu.rdx = reinterpret_cast<uint64_t>(read_buf);
    emu.r8  = 8;
    emu.r9  = reinterpret_cast<uint64_t>(&bytes_read);
    emu.rsp = reinterpret_cast<uint64_t>(fake_stack);
    assert(bridge.invoke_thunk("kernel32.dll", "ReadFile", &emu));
    assert(emu.rax == 1 && bytes_read == 8 && std::memcmp(read_buf, "SEKIRO!!", 8) == 0);

    emu.rcx = hfile;
    assert(bridge.invoke_thunk("kernel32.dll", "CloseHandle", &emu));
    assert(emu.rax == 1);

    // 4. Test XInputGetState thunk via lock-free InputRouter
    auto& router = mobiro::input::InputRouter::global();
    router.set_button(mobiro::input::kLeftShoulder, true);
    router.set_left_stick(0.05f, 0.05f, 0.12f);
    router.set_right_stick(1.0f, 0.0f, 0.10f);

    mobiro::input::XInputState xi{};
    emu.rcx = 0;
    emu.rdx = reinterpret_cast<uint64_t>(&xi);
    assert(bridge.invoke_thunk("xinput1_4.dll", "XInputGetState", &emu));
    assert(emu.rax == 0);
    assert((xi.Gamepad.wButtons & mobiro::input::kLeftShoulder) != 0);
    assert(xi.Gamepad.sThumbLX == 0 && xi.Gamepad.sThumbLY == 0);
    assert(xi.Gamepad.sThumbRX == 32767 && xi.Gamepad.sThumbRY == 0);

    bridge.shutdown();
    fs::remove_all(tmp);
}

void test_dxvk_config_and_topology() {
    auto b8 = mobiro::gfx::compute_uma_budget(8192);
    assert(b8.max_device_memory_mb >= 2048 && b8.max_device_memory_mb <= 4096);
    assert(b8.max_chunk_size_mb == 32);

    auto b16 = mobiro::gfx::compute_uma_budget(16384);
    assert(b16.max_device_memory_mb == 6144);
    assert(b16.max_chunk_size_mb == 64);

    std::string conf = mobiro::gfx::render_dxvk_conf({16384, 3, 60, false});
    assert(conf.find("dxvk.enableGraphicsPipelineLibrary = True") != std::string::npos);
    assert(conf.find("d3d11.maxFrameLatency = 1") != std::string::npos);
    assert(conf.find("d3d11.invariantPosition = True") != std::string::npos);

    auto topo = mobiro::sched::CpuTopology::classify({
        {0, 2265600}, {1, 2265600},
        {2, 2956800}, {3, 2956800}, {4, 3148800}, {5, 3148800}, {6, 3148800},
        {7, 3302400}
    });
    assert(topo.prime_cores.size() == 1 && topo.prime_cores[0] == 7);
    assert(topo.eff_cores.size() == 2);
    assert(topo.perf_cores.size() == 5);
}

// End-to-end test: builds a real executable PE32+ image containing x86_64 machine code
// that reads GS:[0x30] (TEB*), calls IAT-patched GetProcessHeap and HeapAlloc, and returns
// the newly allocated guest pointer in RAX, plus exercises Event, SystemInfo, and SEH .pdata.
void test_x86_64_guest_execution_and_seh() {
    const fs::path tmp = fs::temp_directory_path() / "mobiro_test_exec";
    fs::remove_all(tmp);
    fs::create_directories(tmp);
    const fs::path exe_path = tmp / "guest_probe.exe";

    // Layout:
    //   Section 0 (.text,  RVA 0x1000, Raw 0x400): x86_64 entry code
    //   Section 1 (.rdata, RVA 0x2000, Raw 0x800): Import Directory + IAT + .pdata entry
    std::vector<uint8_t> img(0xC00, 0);
    img[0] = 'M'; img[1] = 'Z';
    const uint32_t pe_off = 0x80;
    wr32(img, 0x3C, pe_off);
    img[pe_off] = 'P'; img[pe_off + 1] = 'E';

    const size_t coff = pe_off + 4;
    wr16(img, coff + 0, 0x8664);
    wr16(img, coff + 2, 2); // 2 sections
    const uint16_t opt_size = 0xF0;
    wr16(img, coff + 16, opt_size);

    const size_t opt = coff + 20;
    wr16(img, opt + 0, 0x020B);
    wr32(img, opt + 16, 0x1000);                // EntryPoint = .text+0
    wr64(img, opt + 24, 0x0000000140000000ULL);
    wr32(img, opt + 56, 0x3000);                // SizeOfImage
    wr32(img, opt + 60, 0x400);                 // SizeOfHeaders
    wr32(img, opt + 108, 16);
    wr32(img, opt + 112 + 1 * 8, 0x2000);       // Import RVA
    wr32(img, opt + 112 + 1 * 8 + 4, 40);       // Import Size
    wr32(img, opt + 112 + 3 * 8, 0x2300);       // Exception (.pdata) RVA
    wr32(img, opt + 112 + 3 * 8 + 4, 12);       // 1 RUNTIME_FUNCTION entry

    const size_t sec0 = opt + opt_size;
    std::memcpy(&img[sec0], ".text", 5);
    wr32(img, sec0 + 8, 0x400);  wr32(img, sec0 + 12, 0x1000);
    wr32(img, sec0 + 16, 0x400); wr32(img, sec0 + 20, 0x400);
    wr32(img, sec0 + 36, 0x60000020u); // READ | EXEC | CODE

    const size_t sec1 = sec0 + 40;
    std::memcpy(&img[sec1], ".rdata", 6);
    wr32(img, sec1 + 8, 0x400);  wr32(img, sec1 + 12, 0x2000);
    wr32(img, sec1 + 16, 0x400); wr32(img, sec1 + 20, 0x800);
    wr32(img, sec1 + 36, 0x40000040u); // READ

    // Import descriptor for kernel32.dll: GetProcessHeap (IAT @ 0x2140), HeapAlloc (IAT @ 0x2148)
    wr32(img, 0x800 + 0,  0x2100); // OriginalFirstThunk
    wr32(img, 0x800 + 12, 0x2080); // Name RVA
    wr32(img, 0x800 + 16, 0x2140); // FirstThunk (IAT)
    std::memcpy(&img[0x880], "kernel32.dll", 13);
    wr64(img, 0x900, 0x2200);
    wr64(img, 0x908, 0x2220);
    std::memcpy(&img[0xA00 + 2], "GetProcessHeap", 15);
    std::memcpy(&img[0xA20 + 2], "HeapAlloc", 10);

    // .pdata entry at RVA 0x2300 (file off 0xB00): covers [0x1000, 0x1080)
    wr32(img, 0xB00 + 0, 0x1000);
    wr32(img, 0xB00 + 4, 0x1080);
    wr32(img, 0xB00 + 8, 0x2320);

    // Emit real x86_64 machine code at .text (RVA 0x1000, file offset 0x400):
    //   0x1000: 48 83 EC 28                 sub rsp, 0x28          (shadow space + alignment)
    //   0x1004: 65 48 8B 04 25 30 00 00 00  mov rax, gs:[0x30]     (read TEB self_ptr)
    //   0x100D: FF 15 2D 11 00 00           call [rip + 0x112D]    (0x1013 + 0x112D = 0x2140 GetProcessHeap)
    //   0x1013: 48 89 C1                    mov rcx, rax           (hHeap)
    //   0x1016: 48 BA 08 00 00 00 00 00 00 00 mov rdx, 8           (HEAP_ZERO_MEMORY)
    //   0x1020: 49 B8 00 01 00 00 00 00 00 00 mov r8, 256          (dwBytes = 256)
    //   0x102A: FF 15 18 11 00 00           call [rip + 0x1118]    (0x1030 + 0x1118 = 0x2148 HeapAlloc)
    //   0x1030: 48 83 C4 28                 add rsp, 0x28
    //   0x1034: C3                          ret
    const uint8_t code[] = {
        0x48, 0x83, 0xEC, 0x28,
        0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,
        0xFF, 0x15, 0x2D, 0x11, 0x00, 0x00,
        0x48, 0x89, 0xC1,
        0x48, 0xBA, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x49, 0xB8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0x15, 0x18, 0x11, 0x00, 0x00,
        0x48, 0x83, 0xC4, 0x28,
        0xC3
    };
    std::memcpy(&img[0x400], code, sizeof(code));

    {
        std::ofstream f(exe_path, std::ios::binary | std::ios::trunc);
        f.write(reinterpret_cast<const char*>(img.data()), static_cast<std::streamsize>(img.size()));
    }

    mobiro::validator::VfsMapper vfs;
    assert(vfs.index_root(tmp.string()));
    mobiro::mem::GuestArena arena;
    assert(arena.reserve(0x0000000100000000ULL, 128ULL * 1024 * 1024));
    mobiro::cpu::Box64Bridge bridge;
    assert(bridge.initialize(&arena, &vfs));

    auto loaded = mobiro::cpu::PeLoader::load_pe64(exe_path.string(), arena, bridge, true);
    assert(loaded.ok && loaded.imports_resolved == 2 && loaded.pdata_size == 12);
    bridge.seh().register_image(loaded.mapped_base, loaded.pdata_va, loaded.pdata_size);

    mobiro::cpu::Win64ThreadEnv tenv;
    assert(tenv.init_main_thread(arena, loaded.mapped_base, 8, 9001, 9002));
    bridge.set_main_teb(tenv.teb);

    // Execute real x86_64 machine code from entry point
    auto exec = mobiro::cpu::GuestExecutor::run_entry(loaded, tenv, bridge);
    assert(exec.ok);
    assert(exec.thunks_dispatched == 2);
    assert(exec.exit_rax != 0);
    assert(arena.contains(static_cast<uintptr_t>(exec.exit_rax), 256));

    // Verify RtlLookupFunctionEntry resolves our .pdata entry
    x64emu_t emu{};
    emu.gs_base = reinterpret_cast<uint64_t>(tenv.teb);
    uintptr_t out_base = 0;
    emu.rcx = loaded.entry_point + 0x10;
    emu.rdx = reinterpret_cast<uint64_t>(&out_base);
    assert(bridge.invoke_thunk("ntdll.dll", "RtlLookupFunctionEntry", &emu));
    assert(emu.rax != 0 && out_base == loaded.mapped_base);

    // Verify Event create/wait-timeout/set/wait-signaled/close + GetSystemInfo + LastError
    emu.rcx = 0; emu.rdx = 1; emu.r8 = 0; // manual_reset=true, initial=false
    assert(bridge.invoke_thunk("kernel32.dll", "CreateEventW", &emu));
    const uint64_t hev = emu.rax;
    assert(hev != 0);

    emu.rcx = hev; emu.rdx = 5; // 5ms timeout -> WAIT_TIMEOUT
    assert(bridge.invoke_thunk("kernel32.dll", "WaitForSingleObject", &emu));
    assert(emu.rax == mobiro::win32::EventTable::kWaitTimeout);

    emu.rcx = hev;
    assert(bridge.invoke_thunk("kernel32.dll", "SetEvent", &emu));
    assert(emu.rax == 1);

    emu.rcx = hev; emu.rdx = 50;
    assert(bridge.invoke_thunk("kernel32.dll", "WaitForSingleObject", &emu));
    assert(emu.rax == mobiro::win32::EventTable::kWaitObject0);

    emu.rcx = hev;
    assert(bridge.invoke_thunk("kernel32.dll", "CloseHandle", &emu));
    assert(emu.rax == 1);

    mobiro::win32::Win64SystemInfo si{};
    emu.rcx = reinterpret_cast<uint64_t>(&si);
    assert(bridge.invoke_thunk("kernel32.dll", "GetSystemInfo", &emu));
    assert(si.page_size == 4096 && si.allocation_granularity == 65536 && si.number_of_processors == 8);

    emu.rcx = 1234;
    assert(bridge.invoke_thunk("kernel32.dll", "SetLastError", &emu));
    assert(bridge.invoke_thunk("kernel32.dll", "GetLastError", &emu));
    assert(emu.rax == 1234);

    bridge.shutdown();
    fs::remove_all(tmp);
}

void test_dxvk_interop_and_ms_x64_marshaling() {
    auto& interop = mobiro::gfx::DxvkInterop::global();
    interop.unload();

    // Surface lifecycle & thermal FPS pacing
    int dummy_win = 0;
    interop.set_native_window(&dummy_win, 2400, 1080);
    auto snap = interop.surface();
    assert(snap.native_window == &dummy_win && snap.width == 2400 && snap.height == 1080);
    assert(interop.target_frame_interval_ns() == 16'666'666LL);
    interop.set_target_fps(30);
    assert(interop.target_frame_interval_ns() == 33'333'333LL);
    interop.set_target_fps(60);

    mobiro::mem::GuestArena arena;
    assert(arena.reserve(0x0000000100000000ULL, 128ULL * 1024 * 1024));
    mobiro::validator::VfsMapper vfs;
    mobiro::cpu::Box64Bridge bridge;
    assert(bridge.initialize(&arena, &vfs));

    // Unloaded DXVK must cleanly return E_NOTIMPL
    x64emu_t emu{};
    assert(bridge.invoke_thunk("dxgi.dll", "CreateDXGIFactory1", &emu));
    assert(static_cast<uint32_t>(emu.rax) == 0x80004001u);

    // Inject test DXVK backend to verify exact 10-arg MS-x64 register+stack marshaling
    static bool saw_expected_args = false;
    mobiro::gfx::DxvkBackendTable mock{};
    mock.create_dxgi_factory1 = [](const void* riid, void** out_factory) -> int32_t {
        if (!riid || !out_factory) return static_cast<int32_t>(0x80070057u);
        *out_factory = reinterpret_cast<void*>(0x11223344ULL);
        return 0; // S_OK
    };
    mock.d3d11_create_device = [](
        void* adapter, uint32_t driver_type, void* software, uint32_t flags,
        const uint32_t* levels, uint32_t num_levels, uint32_t sdk_ver,
        void** out_dev, uint32_t* out_lvl, void** out_ctx) -> int32_t {
        saw_expected_args = (adapter == nullptr && driver_type == 1 && software == nullptr &&
                             flags == 0x20 && levels && num_levels == 1 && levels[0] == 0xB000 &&
                             sdk_ver == 7 && out_dev && out_lvl && out_ctx);
        if (!saw_expected_args) return static_cast<int32_t>(0x80070057u);
        *out_dev = reinterpret_cast<void*>(0xAAAABBBBULL);
        *out_lvl = 0xB000; // D3D_FEATURE_LEVEL_11_0
        *out_ctx = reinterpret_cast<void*>(0xCCCCDDDDULL);
        return 0; // S_OK
    };
    interop.set_backend_override(mock);

    // 1. Test CreateDXGIFactory1
    uint8_t fake_guid[16]{1, 2, 3, 4};
    void* factory_out = nullptr;
    emu = {};
    emu.rcx = reinterpret_cast<uint64_t>(fake_guid);
    emu.rdx = reinterpret_cast<uint64_t>(&factory_out);
    assert(bridge.invoke_thunk("dxgi.dll", "CreateDXGIFactory1", &emu));
    assert(emu.rax == 0 && factory_out == reinterpret_cast<void*>(0x11223344ULL));

    // 2. Test 10-arg D3D11CreateDevice (4 regs + 6 stack args at [RSP+0x28..0x50])
    uint32_t req_levels[1] = {0xB000};
    void* dev_out = nullptr;
    uint32_t fl_out = 0;
    void* ctx_out = nullptr;
    uint64_t stack[12]{};
    stack[5]  = reinterpret_cast<uint64_t>(req_levels); // arg5: pFeatureLevels
    stack[6]  = 1;                                      // arg6: FeatureLevels
    stack[7]  = 7;                                      // arg7: D3D11_SDK_VERSION
    stack[8]  = reinterpret_cast<uint64_t>(&dev_out);   // arg8: ppDevice
    stack[9]  = reinterpret_cast<uint64_t>(&fl_out);    // arg9: pFeatureLevel
    stack[10] = reinterpret_cast<uint64_t>(&ctx_out);   // arg10: ppImmediateContext

    emu = {};
    emu.rcx = 0;    // pAdapter
    emu.rdx = 1;    // D3D_DRIVER_TYPE_HARDWARE
    emu.r8  = 0;    // Software
    emu.r9  = 0x20; // D3D11_CREATE_DEVICE_BGRA_SUPPORT
    emu.rsp = reinterpret_cast<uint64_t>(stack);
    assert(bridge.invoke_thunk("d3d11.dll", "D3D11CreateDevice", &emu));
    assert(emu.rax == 0 && saw_expected_args);
    assert(dev_out == reinterpret_cast<void*>(0xAAAABBBBULL));
    assert(fl_out == 0xB000);
    assert(ctx_out == reinterpret_cast<void*>(0xCCCCDDDDULL));

    interop.unload();
    bridge.shutdown();
}

void test_vfs_write_overlay_threads_wait_and_audio() {
    const fs::path tmp = fs::temp_directory_path() / "mobiro_test_m3";
    const fs::path ro_dir = tmp / "byof_ro";
    const fs::path ov_dir = tmp / "saves_overlay";
    fs::remove_all(tmp);
    fs::create_directories(ro_dir);

    {
        std::ofstream orig(ro_dir / "config.xml", std::ios::binary);
        orig << "ORIGINAL";
    }

    mobiro::validator::VfsMapper vfs;
    assert(vfs.index_root(ro_dir.string()));
    assert(vfs.set_write_overlay(ov_dir.string()));

    // Path traversal must be rejected
    std::string escaped;
    assert(!vfs.resolve_for_write("..\\..\\evil.txt", escaped));

    mobiro::mem::GuestArena arena;
    assert(arena.reserve(0x0000000100000000ULL, 128ULL * 1024 * 1024));
    mobiro::cpu::Box64Bridge bridge;
    assert(bridge.initialize(&arena, &vfs));

    // 1. Copy-on-write save file via CreateFileW(GENERIC_WRITE) + WriteFile + ReadFile
    const uint16_t save_wpath[] = {'S','a','v','e','s','\\','S','0','0','0','0','.','s','l','2', 0};
    uint64_t stack[8]{};
    stack[5] = 2u; // CREATE_ALWAYS
    x64emu_t emu{};
    emu.rcx = reinterpret_cast<uint64_t>(save_wpath);
    emu.rdx = 0x40000000u; // GENERIC_WRITE
    emu.rsp = reinterpret_cast<uint64_t>(stack);
    assert(bridge.invoke_thunk("kernel32.dll", "CreateFileW", &emu));
    const uint64_t hwrite = emu.rax;
    assert(hwrite != mobiro::win32::FileHandleTable::kInvalidHandle);

    const char payload[] = "SEKIRO_SAVE_V1";
    uint32_t written = 0;
    emu = {};
    emu.rcx = hwrite;
    emu.rdx = reinterpret_cast<uint64_t>(payload);
    emu.r8  = 14;
    emu.r9  = reinterpret_cast<uint64_t>(&written);
    assert(bridge.invoke_thunk("kernel32.dll", "WriteFile", &emu));
    assert(emu.rax == 1 && written == 14);
    emu.rcx = hwrite;
    assert(bridge.invoke_thunk("kernel32.dll", "FlushFileBuffers", &emu));
    assert(emu.rax == 1);
    assert(bridge.invoke_thunk("kernel32.dll", "CloseHandle", &emu));
    assert(emu.rax == 1);

    // Ensure BYOF read-only directory remained untouched and overlay read returns new bytes
    assert(!fs::exists(ro_dir / "saves" / "s0000.sl2"));
    emu = {};
    emu.rcx = reinterpret_cast<uint64_t>(save_wpath);
    emu.rdx = 0x80000000u; // GENERIC_READ
    assert(bridge.invoke_thunk("kernel32.dll", "CreateFileW", &emu));
    const uint64_t hread = emu.rax;
    assert(hread != mobiro::win32::FileHandleTable::kInvalidHandle);

    char read_back[16]{};
    uint32_t nread = 0;
    emu = {};
    emu.rcx = hread;
    emu.rdx = reinterpret_cast<uint64_t>(read_back);
    emu.r8  = 14;
    emu.r9  = reinterpret_cast<uint64_t>(&nread);
    assert(bridge.invoke_thunk("kernel32.dll", "ReadFile", &emu));
    assert(emu.rax == 1 && nread == 14 && std::memcmp(read_back, payload, 14) == 0);
    emu.rcx = hread;
    assert(bridge.invoke_thunk("kernel32.dll", "CloseHandle", &emu));

    // 2. CreateThread + WaitForSingleObject + WaitOnAddress/WakeByAddressSingle
    std::atomic<uint32_t> futex_word{0};
    std::atomic<uint64_t> saw_param{0};
    bridge.threads().set_dispatch_callback(
        [&](uintptr_t /*pc*/, uintptr_t param, mobiro::cpu::Win64Teb* teb) -> uint32_t {
            assert(teb != nullptr && teb->unique_thread >= 200);
            saw_param.store(param, std::memory_order_release);
            futex_word.store(1, std::memory_order_release);
            bridge.addr_wait().wake_single(&futex_word);
            return 0;
        });

    uint32_t spawned_tid = 0;
    uint64_t ct_stack[8]{};
    ct_stack[6] = reinterpret_cast<uint64_t>(&spawned_tid); // arg6: lpThreadId
    emu = {};
    emu.r8  = 0x140001000ULL; // lpStartAddress
    emu.r9  = 0xCAFE1234ULL;  // lpParameter
    emu.rsp = reinterpret_cast<uint64_t>(ct_stack);
    assert(bridge.invoke_thunk("kernel32.dll", "CreateThread", &emu));
    const uint64_t hthread = emu.rax;
    assert(hthread != 0 && spawned_tid >= 200);

    uint32_t expected_zero = 0;
    emu = {};
    emu.rcx = reinterpret_cast<uint64_t>(&futex_word);
    emu.rdx = reinterpret_cast<uint64_t>(&expected_zero);
    emu.r8  = sizeof(uint32_t);
    emu.r9  = 2000;
    assert(bridge.invoke_thunk("kernelbase.dll", "WaitOnAddress", &emu));
    assert(emu.rax == 1 && futex_word.load() == 1 && saw_param.load() == 0xCAFE1234ULL);

    emu = {};
    emu.rcx = hthread;
    emu.rdx = 2000;
    assert(bridge.invoke_thunk("kernel32.dll", "WaitForSingleObject", &emu));
    assert(emu.rax == 0);
    emu.rcx = hthread;
    assert(bridge.invoke_thunk("kernel32.dll", "CloseHandle", &emu));
    assert(emu.rax == 1);

    // 3. XAudio2Create -> AAudioXAudioBridge lock-free PCM ring buffer
    void* xa2_ptr = nullptr;
    emu = {};
    emu.rcx = reinterpret_cast<uint64_t>(&xa2_ptr);
    assert(bridge.invoke_thunk("xaudio2_7.dll", "XAudio2Create", &emu));
    assert(emu.rax == 0 && xa2_ptr != nullptr);
    auto* xa2_pr = mobiro::audio::XAudio2ComBridge::global().find_proxy(reinterpret_cast<uintptr_t>(xa2_ptr));
    assert(xa2_pr != nullptr && xa2_pr->native_obj != nullptr);
    auto* xa2_com = static_cast<mobiro::audio::IXAudio2_7Com*>(xa2_pr->native_obj);
    uint32_t dev_count = 0;
    assert(xa2_com->lpVtbl->GetDeviceCount(xa2_com, &dev_count) == 0 && dev_count == 1);
    assert(xa2_com->lpVtbl->Release(xa2_com) == 0);
    mobiro::audio::XAudio2ComBridge::global().clear();

    auto& audio = mobiro::audio::AAudioXAudioBridge::global();
    assert(audio.is_running());
    const float pcm_in[4] = {0.25f, -0.25f, 0.5f, -0.5f};
    assert(audio.submit_pcm_float(pcm_in, 4) == 4);
    float pcm_out[6]{1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f};
    assert(audio.drain_pcm_float(pcm_out, 6) == 4);
    assert(pcm_out[0] == 0.25f && pcm_out[3] == -0.5f && pcm_out[4] == 0.0f && pcm_out[5] == 0.0f);
    audio.stop();

    bridge.shutdown();
    fs::remove_all(tmp);
}

void test_touch_controller_and_cache_warmer() {
    mobiro::input::InputRouter router;
    mobiro::input::TouchController tc;
    tc.set_viewport(1920.0f, 1080.0f);

    // 1. Multi-touch: left floating stick (ptr 1) + L1 Deflect button (ptr 2) + right camera drag (ptr 3)
    tc.on_pointer(1, mobiro::input::TouchAction::Down, 300.0f, 700.0f, router);
    tc.on_pointer(1, mobiro::input::TouchAction::Move, 450.0f, 600.0f, router); // right + up
    tc.on_pointer(2, mobiro::input::TouchAction::Down, 0.86f * 1920.0f, 0.44f * 1080.0f, router); // L1
    tc.on_pointer(3, mobiro::input::TouchAction::Down, 0.54f * 1920.0f, 0.50f * 1080.0f, router);
    tc.on_pointer(3, mobiro::input::TouchAction::Move, 0.59f * 1920.0f, 0.50f * 1080.0f, router);

    auto snap = router.snapshot();
    assert((snap.Gamepad.wButtons & mobiro::input::kLeftShoulder) != 0);
    assert(snap.Gamepad.sThumbLX > 0 && snap.Gamepad.sThumbLY > 0);
    assert(snap.Gamepad.sThumbRX > 0);

    // Active floating stick produces 13 button quads + 2 stick quads = 15 quads
    auto quads = tc.build_hud_quads();
    assert(quads.size() == 15);

    // Release camera & L1, then cancel clears left stick
    tc.on_pointer(2, mobiro::input::TouchAction::Up, 0.86f * 1920.0f, 0.44f * 1080.0f, router);
    tc.on_pointer(3, mobiro::input::TouchAction::Up, 0.59f * 1920.0f, 0.50f * 1080.0f, router);
    snap = router.snapshot();
    assert((snap.Gamepad.wButtons & mobiro::input::kLeftShoulder) == 0);
    assert(snap.Gamepad.sThumbRX == 0);

    tc.on_pointer(0, mobiro::input::TouchAction::Cancel, 0.0f, 0.0f, router);
    snap = router.snapshot();
    assert(snap.Gamepad.sThumbLX == 0 && snap.Gamepad.sThumbLY == 0);
    assert(tc.build_hud_quads().size() == 13);

    // 2. PipelineCacheWarmer: prunes stale build dirs & pre-reads active DXVK/Turnip cache files
    const fs::path cache_root = fs::temp_directory_path() / "mobiro_test_cache_warm";
    fs::remove_all(cache_root);
    fs::create_directories(cache_root / "stale_old_build" / "dxvk");
    fs::create_directories(cache_root / "active_fp_1234" / "dxvk");
    {
        std::ofstream f(cache_root / "active_fp_1234" / "dxvk" / "sekiro.dxvk-cache", std::ios::binary);
        std::string blob(4096, 'P');
        f.write(blob.data(), static_cast<std::streamsize>(blob.size()));
    }

    mobiro::gfx::PipelineCacheWarmer warmer;
    warmer.start_async_warm(cache_root.string(), "active_fp_1234");
    warmer.wait();
    assert(warmer.is_done());
    auto st = warmer.stats();
    assert(st.completed && st.stale_dirs_pruned == 1 && st.files_warmed == 1 && st.bytes_warmed == 4096);
    assert(!fs::exists(cache_root / "stale_old_build"));
    assert(fs::exists(cache_root / "active_fp_1234" / "dxvk" / "sekiro.dxvk-cache"));

    fs::remove_all(cache_root);
}

void test_xaudio2_com_and_touch_overlay_vk() {
    // 1. IXAudio2 COM vtable dispatch -> PCM16 & mono float32 -> AAudioXAudioBridge
    mobiro::mem::GuestArena arena;
    assert(arena.reserve(0x0000000100000000ULL, 128ULL * 1024 * 1024));
    mobiro::validator::VfsMapper vfs;
    mobiro::cpu::Box64Bridge bridge;
    assert(bridge.initialize(&arena, &vfs));

    void* xa2_raw = nullptr;
    x64emu_t emu{};
    emu.rcx = reinterpret_cast<uint64_t>(&xa2_raw);
    assert(bridge.invoke_thunk("xaudio2_9.dll", "XAudio2Create", &emu));
    assert(emu.rax == 0 && xa2_raw != nullptr);

    auto* xa2_proxy = mobiro::audio::XAudio2ComBridge::global().find_proxy(reinterpret_cast<uintptr_t>(xa2_raw));
    assert(xa2_proxy != nullptr && xa2_proxy->native_obj != nullptr);
    auto* xa2 = static_cast<mobiro::audio::IXAudio2Com*>(xa2_proxy->native_obj);
    assert(xa2->lpVtbl->AddRef(xa2) == 2);

    void* master_raw = nullptr;
    assert(xa2->lpVtbl->CreateMasteringVoice(xa2, &master_raw, 2, 48000, 0, nullptr, nullptr, 0) == 0);
    assert(master_raw != nullptr);
    auto* master = static_cast<mobiro::audio::IXAudio2VoiceCom*>(master_raw);

    mobiro::audio::WaveFormatEx fmt{};
    fmt.format_tag = 1; // WAVE_FORMAT_PCM
    fmt.channels = 2;
    fmt.samples_per_sec = 48000;
    fmt.bits_per_sample = 16;
    fmt.block_align = 4;
    fmt.avg_bytes_per_sec = 192000;

    void* src_raw = nullptr;
    assert(xa2->lpVtbl->CreateSourceVoice(xa2, &src_raw, &fmt, 0, 2.0f, nullptr, nullptr, nullptr) == 0);
    assert(src_raw != nullptr);
    auto* src = static_cast<mobiro::audio::IXAudio2SourceVoiceCom*>(src_raw);
    assert(src->lpVtbl->base.SetVolume(src, 0.5f, 0) == 0);
    assert(src->lpVtbl->Start(src, 0, 0) == 0);

    const int16_t pcm16[4] = {16384, -16384, 32767, -32768};
    int ctx_tag = 42;
    mobiro::audio::XAudio2Buffer xbuf{};
    xbuf.audio_bytes = sizeof(pcm16);
    xbuf.audio_data = reinterpret_cast<const uint8_t*>(pcm16);
    xbuf.context = &ctx_tag;
    assert(src->lpVtbl->SubmitSourceBuffer(src, &xbuf, nullptr) == 0);

    mobiro::audio::XAudio2VoiceState vst{};
    src->lpVtbl->GetState(src, &vst, 0);
    assert(vst.samples_played == 2 && vst.current_buffer_context == &ctx_tag);

    float out[4]{};
    auto& aaudio = mobiro::audio::AAudioXAudioBridge::global();
    assert(aaudio.drain_pcm_float(out, 4) == 4);
    assert(std::abs(out[0] - 0.25f) < 1e-3f);
    assert(std::abs(out[1] + 0.25f) < 1e-3f);
    assert(std::abs(out[2] - 0.50f) < 1e-3f);
    assert(std::abs(out[3] + 0.50f) < 1e-3f);

    // Mono IEEE float32 upmix -> stereo
    mobiro::audio::WaveFormatEx mono_flt{};
    mono_flt.format_tag = 3; // WAVE_FORMAT_IEEE_FLOAT
    mono_flt.channels = 1;
    mono_flt.samples_per_sec = 48000;
    mono_flt.bits_per_sample = 32;
    mono_flt.block_align = 4;
    void* mono_raw = nullptr;
    assert(xa2->lpVtbl->CreateSourceVoice(xa2, &mono_raw, &mono_flt, 0, 2.0f, nullptr, nullptr, nullptr) == 0);
    auto* mono = static_cast<mobiro::audio::IXAudio2SourceVoiceCom*>(mono_raw);
    const float mono_sample[1] = {0.75f};
    mobiro::audio::XAudio2Buffer mbuf{};
    mbuf.audio_bytes = sizeof(mono_sample);
    mbuf.audio_data = reinterpret_cast<const uint8_t*>(mono_sample);
    assert(mono->lpVtbl->SubmitSourceBuffer(mono, &mbuf, nullptr) == 0);
    float stereo_out[2]{};
    assert(aaudio.drain_pcm_float(stereo_out, 2) == 2);
    assert(std::abs(stereo_out[0] - 0.75f) < 1e-5f && std::abs(stereo_out[1] - 0.75f) < 1e-5f);

    mono->lpVtbl->base.DestroyVoice(mono);
    src->lpVtbl->base.DestroyVoice(src);
    master->lpVtbl->DestroyVoice(master);
    assert(xa2->lpVtbl->Release(xa2) == 1);
    assert(xa2->lpVtbl->Release(xa2) == 0);
    mobiro::audio::XAudio2ComBridge::global().clear();
    aaudio.stop();
    bridge.shutdown();

    // 2. TouchOverlayVk: 15 quads -> 90 NDC vertices, auto-hides when controller disables overlay
    mobiro::input::InputRouter router;
    mobiro::input::TouchController tc;
    tc.set_viewport(1920.0f, 1080.0f);
    tc.on_pointer(1, mobiro::input::TouchAction::Down, 300.0f, 700.0f, router);
    auto quads = tc.build_hud_quads();
    assert(quads.size() == 15);

    mobiro::gfx::TouchOverlayVk overlay;
    assert(overlay.pack_quads(quads) == 90);
    assert(overlay.vertex_bytes() == 90 * sizeof(mobiro::gfx::HudVertex));
    for (const auto& v : overlay.vertices()) {
        assert(v.x >= -1.0f && v.x <= 1.0f);
        assert(v.y >= -1.0f && v.y <= 1.0f);
        assert(v.a >= 0.0f && v.a <= 1.0f);
    }

    overlay.set_enabled(false);
    assert(overlay.pack_quads(quads) == 0);

    // 3. Validate embedded Vulkan 1.0 SPIR-V vertex & fragment HUD shaders
    assert(mobiro::gfx::spirv::validate_module(
        mobiro::gfx::spirv::kHudVertSpv, std::size(mobiro::gfx::spirv::kHudVertSpv)));
    assert(mobiro::gfx::spirv::validate_module(
        mobiro::gfx::spirv::kHudFragSpv, std::size(mobiro::gfx::spirv::kHudFragSpv)));

    // 4. XAudio2.7 COM vtable + 24 kHz -> 48 kHz linear resampler + MSVC CRT Win32 shims
    mobiro::mem::GuestArena arena2;
    assert(arena2.reserve(0x0000000100000000ULL, 64ULL * 1024 * 1024));
    mobiro::validator::VfsMapper vfs2;
    mobiro::cpu::Box64Bridge b2;
    assert(b2.initialize(&arena2, &vfs2));

    void* xa27_raw = nullptr;
    x64emu_t e2{};
    e2.rcx = reinterpret_cast<uint64_t>(&xa27_raw);
    assert(b2.invoke_thunk("xaudio2_7.dll", "XAudio2Create", &e2));
    assert(e2.rax == 0 && xa27_raw != nullptr);
    auto* xa27_proxy = mobiro::audio::XAudio2ComBridge::global().find_proxy(reinterpret_cast<uintptr_t>(xa27_raw));
    assert(xa27_proxy != nullptr && xa27_proxy->native_obj != nullptr);
    auto* xa27 = static_cast<mobiro::audio::IXAudio2_7Com*>(xa27_proxy->native_obj);
    assert(xa27->lpVtbl->Initialize(xa27, 0, 0) == 0);

    mobiro::audio::WaveFormatEx fmt24{};
    fmt24.format_tag = 3; // IEEE_FLOAT
    fmt24.channels = 2;
    fmt24.samples_per_sec = 24000; // Half of 48 kHz -> resampler doubles frames
    fmt24.bits_per_sample = 32;
    void* v24_raw = nullptr;
    assert(xa27->lpVtbl->CreateSourceVoice(xa27, &v24_raw, &fmt24, 0, 2.0f, nullptr, nullptr, nullptr) == 0);
    auto* v24 = static_cast<mobiro::audio::IXAudio2SourceVoiceCom*>(v24_raw);
    const float src24[4] = {0.0f, 0.0f, 1.0f, 1.0f}; // 2 frames @ 24kHz -> 4 frames (8 floats) @ 48kHz
    mobiro::audio::XAudio2Buffer b24{};
    b24.audio_bytes = sizeof(src24);
    b24.audio_data = reinterpret_cast<const uint8_t*>(src24);
    assert(v24->lpVtbl->SubmitSourceBuffer(v24, &b24, nullptr) == 0);
    float resamp[8]{};
    assert(aaudio.drain_pcm_float(resamp, 8) == 8);
    assert(std::abs(resamp[0] - 0.0f) < 1e-4f && std::abs(resamp[2] - 0.5f) < 1e-4f && std::abs(resamp[4] - 1.0f) < 1e-4f);
    v24->lpVtbl->base.DestroyVoice(v24);
    assert(xa27->lpVtbl->Release(xa27) == 0);
    mobiro::audio::XAudio2ComBridge::global().clear();
    aaudio.stop();

    // CriticalSection (recursive), FileTime, TickCount64, StartupInfoW, CommandLine, CPU features
    uint8_t fake_cs[40]{};
    e2 = {}; e2.rcx = reinterpret_cast<uint64_t>(fake_cs);
    assert(b2.invoke_thunk("kernel32.dll", "InitializeCriticalSectionAndSpinCount", &e2) && e2.rax == 1);
    assert(b2.invoke_thunk("kernel32.dll", "EnterCriticalSection", &e2));
    assert(b2.invoke_thunk("kernel32.dll", "TryEnterCriticalSection", &e2) && e2.rax == 1);
    assert(b2.invoke_thunk("kernel32.dll", "LeaveCriticalSection", &e2));
    assert(b2.invoke_thunk("kernel32.dll", "LeaveCriticalSection", &e2));
    assert(b2.invoke_thunk("kernel32.dll", "DeleteCriticalSection", &e2));

    uint64_t ft = 0;
    e2 = {}; e2.rcx = reinterpret_cast<uint64_t>(&ft);
    assert(b2.invoke_thunk("kernel32.dll", "GetSystemTimeAsFileTime", &e2));
    assert(ft > 130000000000000000ULL);
    assert(b2.invoke_thunk("kernel32.dll", "GetTickCount64", &e2) && e2.rax > 0);

    uint8_t si_buf[104]{};
    e2 = {}; e2.rcx = reinterpret_cast<uint64_t>(si_buf);
    assert(b2.invoke_thunk("kernel32.dll", "GetStartupInfoW", &e2));
    uint32_t si_cb = 0;
    std::memcpy(&si_cb, si_buf, 4);
    assert(si_cb == 104);

    assert(b2.invoke_thunk("kernel32.dll", "GetCommandLineA", &e2) && e2.rax != 0);
    assert(std::strcmp(reinterpret_cast<const char*>(e2.rax), "\"Sekiro.exe\"") == 0);

    e2.rcx = 10; // PF_XMMI64_INSTRUCTIONS_AVAILABLE (SSE2)
    assert(b2.invoke_thunk("kernel32.dll", "IsProcessorFeaturePresent", &e2) && e2.rax == 1);
    b2.shutdown();
}

void write_synthetic_pe64_dll(const fs::path& path) {
    // 2 sections: .text (RVA 0x1000, Raw 0x400), .edata (RVA 0x2000, Raw 0x800)
    std::vector<uint8_t> img(0xC00, 0);
    img[0] = 'M'; img[1] = 'Z';
    const uint32_t pe_off = 0x80;
    wr32(img, 0x3C, pe_off);
    img[pe_off] = 'P'; img[pe_off + 1] = 'E';

    const size_t coff = pe_off + 4;
    wr16(img, coff + 0, 0x8664); // AMD64
    wr16(img, coff + 2, 2);      // 2 sections
    const uint16_t opt_size = 0xF0;
    wr16(img, coff + 16, opt_size);
    wr16(img, coff + 18, 0x2022); // IMAGE_FILE_DLL | EXECUTABLE

    const size_t opt = coff + 20;
    wr16(img, opt + 0, 0x020B);
    wr32(img, opt + 16, 0x1000);
    wr64(img, opt + 24, 0x0000000180000000ULL);
    wr32(img, opt + 56, 0x3000);
    wr32(img, opt + 60, 0x400);
    wr32(img, opt + 108, 16);
    wr32(img, opt + 112 + 0 * 8, 0x2000);     // DataDirectory[0] Export RVA
    wr32(img, opt + 112 + 0 * 8 + 4, 0x100);  // Export Size

    const size_t sec0 = opt + opt_size;
    std::memcpy(&img[sec0], ".text", 5);
    wr32(img, sec0 + 8, 0x400); wr32(img, sec0 + 12, 0x1000);
    wr32(img, sec0 + 16, 0x400); wr32(img, sec0 + 20, 0x400);
    wr32(img, sec0 + 36, 0x60000020u);

    const size_t sec1 = sec0 + 40;
    std::memcpy(&img[sec1], ".edata", 6);
    wr32(img, sec1 + 8, 0x400); wr32(img, sec1 + 12, 0x2000);
    wr32(img, sec1 + 16, 0x400); wr32(img, sec1 + 20, 0x800);
    wr32(img, sec1 + 36, 0x40000040u);

    // .text: single RET (0xC3) at RVA 0x1000
    img[0x400] = 0xC3;

    // Export Directory at RVA 0x2000 (file offset 0x800):
    //   Base = 7, NumberOfFunctions = 1, NumberOfNames = 1
    //   AddressOfFunctions = 0x2040 -> [0x1000]
    //   AddressOfNames     = 0x2050 -> [0x2060]
    //   AddressOfNameOrdinals = 0x2058 -> [0]
    wr32(img, 0x800 + 16, 7);      // Base ordinal
    wr32(img, 0x800 + 20, 1);      // NumberOfFunctions
    wr32(img, 0x800 + 24, 1);      // NumberOfNames
    wr32(img, 0x800 + 28, 0x2040); // AddressOfFunctions
    wr32(img, 0x800 + 32, 0x2050); // AddressOfNames
    wr32(img, 0x800 + 36, 0x2058); // AddressOfNameOrdinals
    wr32(img, 0x840, 0x1000);      // Export[0] RVA
    wr32(img, 0x850, 0x2060);      // Name[0] RVA
    wr16(img, 0x858, 0);           // Ordinal index 0 -> ordinal 7
    std::memcpy(&img[0x860], "MobiroExportedFn", 17);

    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(img.data()), static_cast<std::streamsize>(img.size()));
}

void test_module_loader_and_headless_win32_ui() {
    const fs::path tmp = fs::temp_directory_path() / "mobiro_test_m7";
    fs::remove_all(tmp);
    fs::create_directories(tmp);
    write_synthetic_pe64_dll(tmp / "helper_guest.dll");

    mobiro::validator::VfsMapper vfs;
    assert(vfs.index_root(tmp.string()));
    mobiro::mem::GuestArena arena;
    assert(arena.reserve(0x0000000100000000ULL, 128ULL * 1024 * 1024));
    mobiro::cpu::Box64Bridge bridge;
    assert(bridge.initialize(&arena, &vfs));

    // 1. LoadLibraryW maps real guest PE64 DLL & GetProcAddress resolves by name + ordinal
    const uint16_t dll_w[] = {'h','e','l','p','e','r','_','g','u','e','s','t','.','d','l','l', 0};
    x64emu_t emu{};
    emu.rcx = reinterpret_cast<uint64_t>(dll_w);
    assert(bridge.invoke_thunk("kernel32.dll", "LoadLibraryW", &emu));
    const uint64_t hdll = emu.rax;
    assert(hdll != 0 && arena.contains(static_cast<uintptr_t>(hdll), 0x3000));

    emu = {};
    emu.rcx = hdll;
    emu.rdx = reinterpret_cast<uint64_t>("MobiroExportedFn");
    assert(bridge.invoke_thunk("kernel32.dll", "GetProcAddress", &emu));
    assert(emu.rax == hdll + 0x1000);

    emu = {};
    emu.rcx = hdll;
    emu.rdx = 7; // Ordinal #7 (IS_INTRESOURCE)
    assert(bridge.invoke_thunk("kernel32.dll", "GetProcAddress", &emu));
    assert(emu.rax == hdll + 0x1000);

    // 2. Native-thunked DLL lookup: LoadLibraryA("kernel32.dll") + GetProcAddress("GetTickCount64")
    emu = {};
    emu.rcx = reinterpret_cast<uint64_t>("kernel32.dll");
    assert(bridge.invoke_thunk("kernel32.dll", "LoadLibraryA", &emu));
    const uint64_t hk32 = emu.rax;
    assert(mobiro::win32::ModuleRegistry::is_native_handle(static_cast<uintptr_t>(hk32)));

    emu = {};
    emu.rcx = hk32;
    emu.rdx = reinterpret_cast<uint64_t>("GetTickCount64");
    assert(bridge.invoke_thunk("kernel32.dll", "GetProcAddress", &emu));
    auto* stub = reinterpret_cast<const mobiro::cpu::NativeBridgeStub*>(emu.rax);
    assert(stub != nullptr && stub->trap_cc == 0xCC && stub->magic[0] == 'S' && stub->magic[1] == 'C' && stub->wrapper_ptr != 0);

    // 3. Headless user32 window + message queue
    bridge.window().set_dimensions(2400, 1080);
    emu = {};
    assert(bridge.invoke_thunk("user32.dll", "CreateWindowExW", &emu));
    assert(emu.rax == mobiro::win32::HeadlessWindowState::kMainHwnd);

    mobiro::win32::Win32Rect rc{};
    emu = {}; emu.rcx = mobiro::win32::HeadlessWindowState::kMainHwnd; emu.rdx = reinterpret_cast<uint64_t>(&rc);
    assert(bridge.invoke_thunk("user32.dll", "GetClientRect", &emu) && emu.rax == 1);
    assert(rc.right == 2400 && rc.bottom == 1080);

    emu = {}; emu.rcx = 0; // SM_CXSCREEN
    assert(bridge.invoke_thunk("user32.dll", "GetSystemMetrics", &emu) && emu.rax == 2400);

    emu = {}; emu.rcx = 0;
    assert(bridge.invoke_thunk("user32.dll", "PostQuitMessage", &emu));
    mobiro::win32::Win64Msg msg{};
    uint64_t pm_stack[8]{};
    pm_stack[5] = 1; // PM_REMOVE
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>(&msg); emu.rsp = reinterpret_cast<uint64_t>(pm_stack);
    assert(bridge.invoke_thunk("user32.dll", "PeekMessageW", &emu) && emu.rax == 1);
    assert(msg.message == mobiro::win32::HeadlessWindowState::kWmQuit);
    assert(bridge.invoke_thunk("user32.dll", "PeekMessageW", &emu) && emu.rax == 0);

    // 4. shell32 SHGetKnownFolderPath + ole32 CoTaskMemFree + winmm + bcrypt
    uint16_t* known_path = nullptr;
    emu = {}; emu.r9 = reinterpret_cast<uint64_t>(&known_path);
    assert(bridge.invoke_thunk("shell32.dll", "SHGetKnownFolderPath", &emu) && emu.rax == 0);
    assert(known_path != nullptr);
    assert(mobiro::win32::utf16le_to_utf8(known_path) == "C:\\Users\\Mobiro\\AppData\\Roaming");
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>(known_path);
    assert(bridge.invoke_thunk("ole32.dll", "CoTaskMemFree", &emu));

    assert(bridge.invoke_thunk("winmm.dll", "timeGetTime", &emu) && emu.rax > 0);

    uint8_t rnd[32]{};
    emu = {}; emu.rdx = reinterpret_cast<uint64_t>(rnd); emu.r8 = sizeof(rnd);
    assert(bridge.invoke_thunk("bcrypt.dll", "BCryptGenRandom", &emu) && emu.rax == 0);
    bool any_nonzero = false;
    for (uint8_t b : rnd) if (b != 0) any_nonzero = true;
    assert(any_nonzero);

    bridge.shutdown();
    fs::remove_all(tmp);
}

void test_d3d11_com_bridge_ext_win32_and_hud_draw() {
    // 1. D3D11ComBridge: proxy wrapping, slot dispatch, IDXGISwapChain::Present hook, auto-free on Release==0
    struct FakeSwapChain {
        const void* const* vtbl;
        uint32_t refs;
        uint32_t present_calls;
        uint32_t last_sync;
    };
    static void* fake_sc_vtbl[mobiro::gfx::d3d11_abi::DXGISwapChainSlots::kSlotCount]{};
    fake_sc_vtbl[2] = reinterpret_cast<void*>(+[](void* self) -> uint64_t {
        auto* sc = static_cast<FakeSwapChain*>(self);
        return --sc->refs;
    });
    fake_sc_vtbl[mobiro::gfx::d3d11_abi::DXGISwapChainSlots::kPresent] =
        reinterpret_cast<void*>(+[](void* self, uint64_t sync, uint64_t /*flags*/) -> uint64_t {
            auto* sc = static_cast<FakeSwapChain*>(self);
            ++sc->present_calls;
            sc->last_sync = static_cast<uint32_t>(sync);
            return 0ULL; // S_OK
        });

    FakeSwapChain native_sc{fake_sc_vtbl, 1, 0, 0};
    auto& com = mobiro::gfx::D3D11ComBridge::global();
    com.clear();

    bool hook_fired = false;
    com.set_present_hook([&](void* nat, uint32_t sync, uint32_t) {
        hook_fired = (nat == &native_sc && sync == 1);
    });

    auto* proxy = com.wrap(&native_sc, mobiro::gfx::d3d11_abi::ComIfaceId::DXGISwapChain);
    assert(proxy != nullptr && com.active_proxy_count() == 1);

    // Invoke Present (slot 8) through NativeBridgeStub in proxy->lpVtbl[8]
    const auto* present_stub = reinterpret_cast<const mobiro::cpu::NativeBridgeStub*>(
        proxy->lpVtbl[mobiro::gfx::d3d11_abi::DXGISwapChainSlots::kPresent]);
    assert(present_stub->trap_cc == 0xCC && present_stub->magic[0] == 'S' && present_stub->magic[1] == 'C' && present_stub->wrapper_ptr != 0);
    x64emu_t emu{};
    emu.rcx = reinterpret_cast<uint64_t>(proxy);
    emu.rdx = 1; // SyncInterval = 1
    emu.r8  = 0; // Flags = 0
    reinterpret_cast<mobiro::cpu::NativeThunkFn>(present_stub->thunk_ptr)(&emu);
    assert(emu.rax == 0 && hook_fired && native_sc.present_calls == 1 && native_sc.last_sync == 1);

    // Invoke Release (slot 2) -> drops native refcount to 0 and reclaims proxy automatically
    const auto* rel_stub = reinterpret_cast<const mobiro::cpu::NativeBridgeStub*>(proxy->lpVtbl[2]);
    emu = {};
    emu.rcx = reinterpret_cast<uint64_t>(proxy);
    reinterpret_cast<mobiro::cpu::NativeThunkFn>(rel_stub->thunk_ptr)(&emu);
    assert(emu.rax == 0 && com.active_proxy_count() == 0);

    // 2. TouchOverlayVk dynamic Vulkan draw-command recording
    mobiro::input::TouchController tc;
    auto quads = tc.build_hud_quads();
    mobiro::gfx::TouchOverlayVk overlay;
    assert(overlay.pack_quads(quads) == 78);

    std::vector<uint8_t> mapped_vbo(4096, 0);
    static uint32_t drawn_vtx_count = 0;
    drawn_vtx_count = 0;
    mobiro::gfx::TouchOverlayVk::VkDrawBindings db{};
    db.pipeline = 0x1234;
    db.vertex_buffer = 0x5678;
    db.mapped_vbo = mapped_vbo.data();
    db.mapped_capacity_bytes = mapped_vbo.size();
    db.cmd_bind_pipeline = [](void*, uint32_t, uint64_t) {};
    db.cmd_bind_vbo = [](void*, uint32_t, uint32_t, const uint64_t*, const uint64_t*) {};
    db.cmd_draw = [](void*, uint32_t vtx, uint32_t, uint32_t, uint32_t) { drawn_vtx_count = vtx; };
    overlay.attach_draw_bindings(db);
    int fake_cmd = 1;
    assert(overlay.record_draw_commands(&fake_cmd) && drawn_vtx_count == 78);

    // 3. Extended Win32 shims (MultiByteToWideChar, GlobalMemoryStatusEx, EncodePointer, DirectInput8)
    mobiro::mem::GuestArena arena;
    assert(arena.reserve(0x0000000100000000ULL, 128ULL * 1024 * 1024));
    mobiro::validator::VfsMapper vfs;
    mobiro::cpu::Box64Bridge bridge;
    assert(bridge.initialize(&arena, &vfs));

    const char* utf8_in = "Sekiro";
    uint16_t utf16_out[16]{};
    uint64_t mb_stack[8]{};
    mb_stack[5] = reinterpret_cast<uint64_t>(utf16_out);
    mb_stack[6] = 16;
    emu = {};
    emu.r8 = reinterpret_cast<uint64_t>(utf8_in);
    emu.r9 = static_cast<uint64_t>(-1);
    emu.rsp = reinterpret_cast<uint64_t>(mb_stack);
    assert(bridge.invoke_thunk("kernel32.dll", "MultiByteToWideChar", &emu) && emu.rax == 7);
    assert(mobiro::win32::utf16le_to_utf8(utf16_out) == "Sekiro");

    mobiro::win32::MemoryStatusEx ms{};
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>(&ms);
    assert(bridge.invoke_thunk("kernel32.dll", "GlobalMemoryStatusEx", &emu) && emu.rax == 1);
    assert(ms.total_phys >= 8ULL * 1024 * 1024 * 1024);

    emu = {}; emu.rcx = 0x12345678ULL;
    assert(bridge.invoke_thunk("kernel32.dll", "EncodePointer", &emu));
    emu.rcx = emu.rax;
    assert(bridge.invoke_thunk("kernel32.dll", "DecodePointer", &emu) && emu.rax == 0x12345678ULL);

    void* di8_raw = nullptr;
    emu = {}; emu.r9 = reinterpret_cast<uint64_t>(&di8_raw);
    assert(bridge.invoke_thunk("dinput8.dll", "DirectInput8Create", &emu) && emu.rax == 0 && di8_raw != nullptr);
    // Invoke IDirectInput8::EnumDevices (slot 4) & Release (slot 2) through Box64 onebridge_t stubs
    const auto* di8_vtbl = *reinterpret_cast<const uintptr_t* const*>(di8_raw);
    const auto* enum_stub = reinterpret_cast<const mobiro::cpu::NativeBridgeStub*>(di8_vtbl[4]);
    const auto* rel_di_stub = reinterpret_cast<const mobiro::cpu::NativeBridgeStub*>(di8_vtbl[2]);
    assert(enum_stub->trap_cc == 0xCC && enum_stub->magic[0] == 'S' && enum_stub->magic[1] == 'C');
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>(di8_raw);
    reinterpret_cast<void(*)(x64emu_t*, uintptr_t)>(enum_stub->wrapper_ptr)(&emu, static_cast<uintptr_t>(enum_stub->thunk_ptr));
    assert(emu.rax == 0);
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>(di8_raw);
    reinterpret_cast<void(*)(x64emu_t*, uintptr_t)>(rel_di_stub->wrapper_ptr)(&emu, static_cast<uintptr_t>(rel_di_stub->thunk_ptr));
    assert(emu.rax == 0);

    bridge.shutdown();
}

void test_m10_xmm_com_auto_wrap_and_dllmain_tls() {
    // 1. D3D11CreateDevice auto-wraps native DXVK objects into ComProxyObjects & forwards XMM3 float to ClearDepthStencilView
    struct FakeD3DContext {
        const void* const* vtbl;
        void* last_dsv;
        uint32_t last_flags;
        float last_depth;
        uint8_t last_stencil;
        uint32_t refs;
    };
    struct FakeD3DDevice {
        const void* const* vtbl;
        uint32_t refs;
    };
    static void* fake_dev_vtbl[mobiro::gfx::d3d11_abi::D3D11DeviceSlots::kSlotCount]{};
    fake_dev_vtbl[2] = reinterpret_cast<void*>(+[](void* self) -> uint64_t {
        return --static_cast<FakeD3DDevice*>(self)->refs;
    });
    static void* fake_ctx_vtbl[mobiro::gfx::d3d11_abi::D3D11DeviceContextSlots::kSlotCount]{};
    fake_ctx_vtbl[2] = reinterpret_cast<void*>(+[](void* self) -> uint64_t {
        return --static_cast<FakeD3DContext*>(self)->refs;
    });
    fake_ctx_vtbl[mobiro::gfx::d3d11_abi::D3D11DeviceContextSlots::kClearDepthStencilView] =
        reinterpret_cast<void*>(+[](void* self, void* dsv, uint32_t flags, float depth, uint8_t stencil) {
            auto* ctx = static_cast<FakeD3DContext*>(self);
            ctx->last_dsv = dsv;
            ctx->last_flags = flags;
            ctx->last_depth = depth;
            ctx->last_stencil = stencil;
        });

    static FakeD3DDevice nat_dev{fake_dev_vtbl, 1};
    static FakeD3DContext nat_ctx{fake_ctx_vtbl, nullptr, 0, 0.0f, 0, 1};
    nat_dev.refs = 1;
    nat_ctx = {fake_ctx_vtbl, nullptr, 0, 0.0f, 0, 1};

    auto& com = mobiro::gfx::D3D11ComBridge::global();
    com.clear();
    auto& dxvk = mobiro::gfx::DxvkInterop::global();
    mobiro::gfx::DxvkBackendTable tbl{};
    tbl.d3d11_create_device = [](void*, uint32_t, void*, uint32_t, const uint32_t*, uint32_t,
                                 uint32_t, void** out_dev, uint32_t* out_fl, void** out_ctx) -> int32_t {
        if (out_dev) *out_dev = &nat_dev;
        if (out_fl) *out_fl = 0xB000;
        if (out_ctx) *out_ctx = &nat_ctx;
        return 0;
    };
    dxvk.set_backend_override(tbl, /*auto_wrap_com=*/true);

    mobiro::mem::GuestArena arena;
    assert(arena.reserve(0x0000000100000000ULL, 128ULL * 1024 * 1024));
    mobiro::validator::VfsMapper vfs;
    mobiro::cpu::Box64Bridge bridge;
    assert(bridge.initialize(&arena, &vfs));

    void* guest_dev = nullptr;
    void* guest_ctx = nullptr;
    uint32_t fl = 0;
    uint64_t stack[12]{};
    stack[5 + 3] = reinterpret_cast<uint64_t>(&guest_dev);
    stack[5 + 4] = reinterpret_cast<uint64_t>(&fl);
    stack[5 + 5] = reinterpret_cast<uint64_t>(&guest_ctx);

    x64emu_t emu{};
    emu.rdx = 1; // D3D_DRIVER_TYPE_HARDWARE
    emu.rsp = reinterpret_cast<uint64_t>(stack);
    assert(bridge.invoke_thunk("d3d11.dll", "D3D11CreateDevice", &emu));
    assert(emu.rax == 0 && guest_dev != nullptr && guest_ctx != nullptr && fl == 0xB000);
    assert(com.active_proxy_count() == 2);

    // Call ID3D11DeviceContext::ClearDepthStencilView (slot 53) via proxy with XMM3 = 0.875f & Stencil = 0x5A
    auto* ctx_proxy = static_cast<mobiro::gfx::ComProxyObject*>(guest_ctx);
    const auto* cdsv_stub = reinterpret_cast<const mobiro::cpu::NativeBridgeStub*>(
        ctx_proxy->lpVtbl[mobiro::gfx::d3d11_abi::D3D11DeviceContextSlots::kClearDepthStencilView]);
    int fake_dsv_marker = 7;
    uint64_t cdsv_stack[8]{};
    cdsv_stack[5] = 0x5A; // Stencil (5th arg on Win64 stack)
    emu = {};
    emu.rcx = reinterpret_cast<uint64_t>(ctx_proxy);
    emu.rdx = reinterpret_cast<uint64_t>(&fake_dsv_marker);
    emu.r8  = 3; // D3D11_CLEAR_DEPTH | D3D11_CLEAR_STENCIL
    mobiro::cpu::emu_set_xmm_f32(&emu, 3, 0.875f);
    emu.rsp = reinterpret_cast<uint64_t>(cdsv_stack);
    reinterpret_cast<mobiro::cpu::NativeThunkFn>(cdsv_stub->thunk_ptr)(&emu);
    assert(nat_ctx.last_dsv == &fake_dsv_marker);
    assert(nat_ctx.last_flags == 3);
    assert(std::abs(nat_ctx.last_depth - 0.875f) < 1e-6f);
    assert(nat_ctx.last_stencil == 0x5A);

    // Release both proxies -> auto-reclaimed
    auto release_proxy = [](void* p) {
        auto* pr = static_cast<mobiro::gfx::ComProxyObject*>(p);
        const auto* st = reinterpret_cast<const mobiro::cpu::NativeBridgeStub*>(pr->lpVtbl[2]);
        x64emu_t e{}; e.rcx = reinterpret_cast<uint64_t>(pr);
        reinterpret_cast<mobiro::cpu::NativeThunkFn>(st->thunk_ptr)(&e);
        assert(e.rax == 0);
    };
    release_proxy(guest_ctx);
    release_proxy(guest_dev);
    assert(com.active_proxy_count() == 0);
    dxvk.set_backend_override({});

    // 2. TLS callback execution + DllMain invocation on LoadLibraryW when main_thread_env is active
    mobiro::cpu::Win64ThreadEnv tenv;
    assert(tenv.init_main_thread(arena, 0x140000000ULL, 8, 1000, 1));
    bridge.set_main_thread_env(&tenv);

    // Build a 1-instruction guest TLS callback (MOV RAX, 0x7777; RET) in guest arena
    const uintptr_t tls_mem = arena.virtual_alloc(0, 4096, mobiro::mem::kProtRead | mobiro::mem::kProtWrite | mobiro::mem::kProtExec, true);
    assert(tls_mem != 0);
    uint8_t cb_code[] = {
        0x48, 0xB8, 0x77, 0x77, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0x7777
        0xC3                                                        // ret
    };
    std::memcpy(reinterpret_cast<void*>(tls_mem + 0x100), cb_code, sizeof(cb_code));
    uint64_t cb_list[2] = { tls_mem + 0x100, 0 };
    std::memcpy(reinterpret_cast<void*>(tls_mem + 0x80), cb_list, sizeof(cb_list));
    uint64_t cb_list_va = tls_mem + 0x80;
    std::memcpy(reinterpret_cast<void*>(tls_mem + 0x18), &cb_list_va, 8); // AddressOfCallBacks

    mobiro::cpu::LoadedPeImage fake_tls_img{};
    fake_tls_img.ok = true;
    fake_tls_img.mapped_base = tls_mem;
    fake_tls_img.tls_dir_va = tls_mem;
    assert(mobiro::cpu::GuestExecutor::run_tls_callbacks(fake_tls_img, tenv) == 1);

    // Frame pacer resets and paces cleanly without hanging
    dxvk.reset_pacer();
    dxvk.set_target_fps(60);
    dxvk.pace_present();

    bridge.shutdown();
}

void test_m11_box64_onebridge_condvar_sem_and_crt() {
    static_assert(sizeof(mobiro::cpu::NativeBridgeStub) == 32);

    const fs::path tmp = fs::temp_directory_path() / "mobiro_test_m11";
    const fs::path save_ov = fs::temp_directory_path() / "mobiro_test_m11_saves";
    fs::remove_all(tmp);
    fs::remove_all(save_ov);
    fs::create_directories(tmp);
    fs::create_directories(save_ov);

    mobiro::validator::VfsMapper vfs;
    assert(vfs.index_root(tmp.string()));
    vfs.set_write_overlay(save_ov.string());
    mobiro::mem::GuestArena arena;
    assert(arena.reserve(0x0000000100000000ULL, 128ULL * 1024 * 1024));
    mobiro::cpu::Box64Bridge bridge;
    assert(bridge.initialize(&arena, &vfs));

    // 1. Verify Box64-compatible wrapper_t dispatch on a resolved IAT stub
    const uintptr_t stub_va = bridge.resolve_import("kernel32.dll", "GetACP");
    assert(stub_va != 0);
    const auto* stub = reinterpret_cast<const mobiro::cpu::NativeBridgeStub*>(stub_va);
    assert(stub->trap_cc == 0xCC && stub->magic[0] == 'S' && stub->magic[1] == 'C');
    x64emu_t emu{};
    reinterpret_cast<void(*)(x64emu_t*, uintptr_t)>(stub->wrapper_ptr)(&emu, static_cast<uintptr_t>(stub->thunk_ptr));
    assert(emu.rax == 65001ULL);

    // 2. Cross-thread ntdll SRWLock + ConditionVariable wake
    uint64_t guest_srw = 0;
    uint64_t guest_cv = 0;
    std::atomic<bool> ready{false};
    std::thread waker([&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(15));
        x64emu_t we{};
        we.rcx = reinterpret_cast<uint64_t>(&guest_srw);
        assert(bridge.invoke_thunk("ntdll.dll", "RtlAcquireSRWLockExclusive", &we));
        ready.store(true, std::memory_order_release);
        we.rcx = reinterpret_cast<uint64_t>(&guest_cv);
        assert(bridge.invoke_thunk("ntdll.dll", "RtlWakeConditionVariable", &we));
        we.rcx = reinterpret_cast<uint64_t>(&guest_srw);
        assert(bridge.invoke_thunk("ntdll.dll", "RtlReleaseSRWLockExclusive", &we));
    });
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>(&guest_srw);
    assert(bridge.invoke_thunk("ntdll.dll", "RtlAcquireSRWLockExclusive", &emu));
    while (!ready.load(std::memory_order_acquire)) {
        emu = {};
        emu.rcx = reinterpret_cast<uint64_t>(&guest_cv);
        emu.rdx = reinterpret_cast<uint64_t>(&guest_srw);
        emu.r8  = 2000; // 2s timeout
        emu.r9  = 0;    // exclusive
        assert(bridge.invoke_thunk("ntdll.dll", "RtlSleepConditionVariableSRW", &emu) && emu.rax == 1);
    }
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>(&guest_srw);
    assert(bridge.invoke_thunk("ntdll.dll", "RtlReleaseSRWLockExclusive", &emu));
    waker.join();

    // 3. Semaphore + WaitForMultipleObjects (wait-any)
    emu = {}; emu.rdx = 0; emu.r8 = 4; // initial=0, max=4
    assert(bridge.invoke_thunk("kernel32.dll", "CreateSemaphoreW", &emu) && emu.rax != 0);
    const uint64_t hsem = emu.rax;
    emu = {}; emu.rdx = 1; emu.r8 = 0; // manual-reset unsignaled event
    assert(bridge.invoke_thunk("kernel32.dll", "CreateEventW", &emu) && emu.rax != 0);
    const uint64_t hevt = emu.rax;

    int32_t prev_cnt = -1;
    emu = {}; emu.rcx = hsem; emu.rdx = 1; emu.r8 = reinterpret_cast<uint64_t>(&prev_cnt);
    assert(bridge.invoke_thunk("kernel32.dll", "ReleaseSemaphore", &emu) && emu.rax == 1 && prev_cnt == 0);

    uint64_t handles[2] = {hevt, hsem};
    emu = {}; emu.rcx = 2; emu.rdx = reinterpret_cast<uint64_t>(handles); emu.r8 = 0; emu.r9 = 1000;
    assert(bridge.invoke_thunk("kernel32.dll", "WaitForMultipleObjects", &emu) && emu.rax == 1); // index 1 = hsem

    // 4. CRT metadata + VFS-overlay MoveFileExW & DeleteFileW
    emu = {};
    assert(bridge.invoke_thunk("kernel32.dll", "GetCurrentProcess", &emu) && emu.rax == ~0ULL);
    uint16_t dir_buf[32]{};
    emu = {}; emu.rcx = 32; emu.rdx = reinterpret_cast<uint64_t>(dir_buf);
    assert(bridge.invoke_thunk("kernel32.dll", "GetCurrentDirectoryW", &emu) && emu.rax == 9);
    assert(mobiro::win32::utf16le_to_utf8(dir_buf) == "C:\\Sekiro");

    {
        std::ofstream f(save_ov / "tmp.sl2", std::ios::binary);
        f << "SAVE";
    }
    const uint16_t src_w[] = {'t','m','p','.','s','l','2', 0};
    const uint16_t dst_w[] = {'S','0','0','0','0','.','s','l','2', 0};
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>(src_w); emu.rdx = reinterpret_cast<uint64_t>(dst_w);
    assert(bridge.invoke_thunk("kernel32.dll", "MoveFileExW", &emu) && emu.rax == 1);
    std::string moved_host;
    assert(vfs.resolve("S0000.sl2", moved_host) && fs::exists(save_ov / "s0000.sl2") && !fs::exists(save_ov / "tmp.sl2"));

    emu = {}; emu.rcx = reinterpret_cast<uint64_t>(dst_w);
    assert(bridge.invoke_thunk("kernel32.dll", "DeleteFileW", &emu) && emu.rax == 1);
    assert(!fs::exists(save_ov / "s0000.sl2") && !vfs.resolve("S0000.sl2", moved_host));

    bridge.shutdown();
    fs::remove_all(tmp);
    fs::remove_all(save_ov);
}

void test_m12_dep_dll_unresolved_trap_and_create_thread_exec() {
    const fs::path tmp = fs::temp_directory_path() / "mobiro_test_m12";
    fs::remove_all(tmp);
    fs::create_directories(tmp);
    write_synthetic_pe64_dll(tmp / "dep_helper.dll");

    // Build an EXE importing dep_helper.dll!MobiroExportedFn AND kernel32.dll!NonExistentFutureApi
    std::vector<uint8_t> exe(0xC00, 0);
    exe[0] = 'M'; exe[1] = 'Z';
    const uint32_t pe_off = 0x80;
    wr32(exe, 0x3C, pe_off);
    exe[pe_off] = 'P'; exe[pe_off + 1] = 'E';
    const size_t coff = pe_off + 4;
    wr16(exe, coff + 0, 0x8664);
    wr16(exe, coff + 2, 2);
    const uint16_t opt_size = 0xF0;
    wr16(exe, coff + 16, opt_size);
    const size_t opt = coff + 20;
    wr16(exe, opt + 0, 0x020B);
    wr32(exe, opt + 16, 0x1000);
    wr64(exe, opt + 24, 0x0000000140000000ULL);
    wr32(exe, opt + 56, 0x3000);
    wr32(exe, opt + 60, 0x400);
    wr32(exe, opt + 108, 16);
    wr32(exe, opt + 112 + 1 * 8, 0x2000);     // Import Dir RVA
    wr32(exe, opt + 112 + 1 * 8 + 4, 0x200);

    const size_t sec0 = opt + opt_size;
    std::memcpy(&exe[sec0], ".text", 5);
    wr32(exe, sec0 + 8, 0x400); wr32(exe, sec0 + 12, 0x1000);
    wr32(exe, sec0 + 16, 0x400); wr32(exe, sec0 + 20, 0x400);
    wr32(exe, sec0 + 36, 0x60000020u);

    const size_t sec1 = sec0 + 40;
    std::memcpy(&exe[sec1], ".idata", 6);
    wr32(exe, sec1 + 8, 0x400); wr32(exe, sec1 + 12, 0x2000);
    wr32(exe, sec1 + 16, 0x400); wr32(exe, sec1 + 20, 0x800);
    wr32(exe, sec1 + 36, 0xC0000040u);

    // .text at RVA 0x1000 (file 0x400):
    //   CALL [RIP + (0x2080 - 0x1006)] -> dep_helper.dll!MobiroExportedFn (RET)
    //   CALL [RIP + (0x2090 - 0x100C)] -> kernel32.dll!NonExistentFutureApi (safe trap -> RAX=0)
    //   RET
    size_t c = 0x400;
    exe[c++] = 0xFF; exe[c++] = 0x15;
    wr32(exe, c, 0x2080 - 0x1006); c += 4;
    exe[c++] = 0xFF; exe[c++] = 0x15;
    wr32(exe, c, 0x2090 - 0x100C); c += 4;
    exe[c++] = 0xC3;

    // Import Descriptor 0: dep_helper.dll -> IAT at 0x2080
    wr32(exe, 0x800 + 0,  0x2080);
    wr32(exe, 0x800 + 12, 0x20B0);
    wr32(exe, 0x800 + 16, 0x2080);
    // Import Descriptor 1: kernel32.dll -> IAT at 0x2090
    wr32(exe, 0x814 + 0,  0x2090);
    wr32(exe, 0x814 + 12, 0x20C0);
    wr32(exe, 0x814 + 16, 0x2090);

    wr64(exe, 0x880, 0x20D0); // IBN for MobiroExportedFn
    wr64(exe, 0x890, 0x20F0); // IBN for NonExistentFutureApi
    std::memcpy(&exe[0x8B0], "dep_helper.dll", 15);
    std::memcpy(&exe[0x8C0], "kernel32.dll", 13);
    std::memcpy(&exe[0x8D2], "MobiroExportedFn", 17);
    std::memcpy(&exe[0x8F2], "NonExistentFutureApi", 21);

    {
        std::ofstream f(tmp / "dep_app.exe", std::ios::binary | std::ios::trunc);
        f.write(reinterpret_cast<const char*>(exe.data()), static_cast<std::streamsize>(exe.size()));
    }

    mobiro::validator::VfsMapper vfs;
    assert(vfs.index_root(tmp.string()));
    mobiro::mem::GuestArena arena;
    assert(arena.reserve(0x0000000100000000ULL, 128ULL * 1024 * 1024));
    mobiro::cpu::Box64Bridge bridge;
    assert(bridge.initialize(&arena, &vfs));

    auto loaded = mobiro::cpu::PeLoader::load_pe64((tmp / "dep_app.exe").string(), arena, bridge, /*force_relocate=*/true);
    assert(loaded.ok);
    assert(loaded.imports_resolved == 1);
    assert(loaded.unresolved_imports.size() == 1);
    assert(bridge.modules().find_module("dep_helper.dll") != 0);

    mobiro::cpu::Win64ThreadEnv tenv;
    assert(tenv.init_main_thread(arena, loaded.mapped_base, 8, 1000, 1));
    auto res = mobiro::cpu::GuestExecutor::run_entry(loaded, tenv, bridge);
    assert(res.ok && res.exit_rax == 0 && res.thunks_dispatched == 1);

    auto called = bridge.called_unresolved_imports();
    assert(called.size() == 1 && called[0] == "kernel32.dll!NonExistentFutureApi");

    // 2. Default CreateThread executes real guest x86_64 code via GuestExecutor without a test override
    const uintptr_t worker_pc = arena.virtual_alloc(
        0, 4096, mobiro::mem::kProtRead | mobiro::mem::kProtWrite | mobiro::mem::kProtExec, true);
    assert(worker_pc != 0);
    const uint8_t worker_code[] = {
        0x48, 0xB8, 0xFE, 0xCA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 0xCAFE
        0xC3                                                        // ret
    };
    std::memcpy(reinterpret_cast<void*>(worker_pc), worker_code, sizeof(worker_code));
    uint32_t tid = 0;
    const uint64_t hth = bridge.threads().create_thread(&arena, loaded.mapped_base, worker_pc, 0, &tid);
    assert(hth != 0 && tid >= 200);
    assert(bridge.threads().wait_single(hth, 2000) == mobiro::win32::EventTable::kWaitObject0);
    assert(bridge.threads().close(hth));

    // 3. TouchOverlayVk pipeline spec + dynamic VkDevice proc resolution
    auto spec = mobiro::gfx::TouchOverlayVk::pipeline_spec();
    assert(spec.vertex_stride == 24 && spec.attrs[0].offset == 0 && spec.attrs[1].offset == 8);
    assert(spec.vert_spv_bytes == sizeof(mobiro::gfx::spirv::kHudVertSpv));
    mobiro::gfx::TouchOverlayVk ov;
    int fake_vk_dev = 1;
    assert(ov.resolve_device_draw_procs(&fake_vk_dev, [](void*, const char* name) -> void* {
        if (std::strcmp(name, "vkCmdBindPipeline") == 0) return reinterpret_cast<void*>(0x1111);
        if (std::strcmp(name, "vkCmdBindVertexBuffers") == 0) return reinterpret_cast<void*>(0x2222);
        if (std::strcmp(name, "vkCmdDraw") == 0) return reinterpret_cast<void*>(0x3333);
        return nullptr;
    }));

    bridge.shutdown();
    fs::remove_all(tmp);
}

void test_m13_com_out_param_wrapping_and_array_unwrapping() {
    auto& com = mobiro::gfx::D3D11ComBridge::global();
    com.clear();

    // 1. Fake native DXGI/D3D11 objects verifying automatic COM out-param wrapping + pointer-array unwrapping
    struct FakeChild { const void* const* vtbl; uint32_t id; uint32_t refs; };
    struct FakeContext {
        const void* const* vtbl;
        void* bound_rtvs[2];
        void* bound_dsv;
        void* bound_vbs[2];
        uint32_t refs;
    };
    struct FakeDevice {
        const void* const* vtbl;
        FakeChild* child_to_return;
        FakeContext* ctx_to_return;
        uint32_t refs;
    };
    struct FakeFactory {
        const void* const* vtbl;
        FakeChild* adapter_to_return;
        uint32_t refs;
    };

    static void* child_vtbl[mobiro::gfx::d3d11_abi::D3D11ResourceChildSlots::kSlotCount]{};
    child_vtbl[2] = reinterpret_cast<void*>(+[](void* s) -> uint64_t { return --static_cast<FakeChild*>(s)->refs; });

    static void* ctx_vtbl[mobiro::gfx::d3d11_abi::D3D11DeviceContextSlots::kSlotCount]{};
    ctx_vtbl[2] = reinterpret_cast<void*>(+[](void* s) -> uint64_t { return --static_cast<FakeContext*>(s)->refs; });
    ctx_vtbl[mobiro::gfx::d3d11_abi::D3D11DeviceContextSlots::kOMSetRenderTargets] =
        reinterpret_cast<void*>(+[](void* s, uint64_t num, uint64_t rtvs_ptr, uint64_t dsv_ptr) -> uint64_t {
            auto* c = static_cast<FakeContext*>(s);
            auto** arr = reinterpret_cast<void**>(rtvs_ptr);
            if (num >= 2 && arr) { c->bound_rtvs[0] = arr[0]; c->bound_rtvs[1] = arr[1]; }
            c->bound_dsv = reinterpret_cast<void*>(dsv_ptr);
            return 0;
        });
    ctx_vtbl[mobiro::gfx::d3d11_abi::D3D11DeviceContextSlots::kIASetVertexBuffers] =
        reinterpret_cast<void*>(+[](void* s, uint64_t /*start*/, uint64_t num, uint64_t vbs_ptr) -> uint64_t {
            auto* c = static_cast<FakeContext*>(s);
            auto** arr = reinterpret_cast<void**>(vbs_ptr);
            if (num >= 2 && arr) { c->bound_vbs[0] = arr[0]; c->bound_vbs[1] = arr[1]; }
            return 0;
        });

    static void* dev_vtbl[mobiro::gfx::d3d11_abi::D3D11DeviceSlots::kSlotCount]{};
    dev_vtbl[2] = reinterpret_cast<void*>(+[](void* s) -> uint64_t { return --static_cast<FakeDevice*>(s)->refs; });
    dev_vtbl[mobiro::gfx::d3d11_abi::D3D11DeviceSlots::kCreateBuffer] =
        reinterpret_cast<void*>(+[](void* s, uint64_t, uint64_t, uint64_t out_pp) -> uint64_t {
            *reinterpret_cast<void**>(out_pp) = static_cast<FakeDevice*>(s)->child_to_return;
            return 0; // S_OK
        });
    dev_vtbl[mobiro::gfx::d3d11_abi::D3D11DeviceSlots::kGetImmediateContext] =
        reinterpret_cast<void*>(+[](void* s, uint64_t out_pp) -> uint64_t {
            *reinterpret_cast<void**>(out_pp) = static_cast<FakeDevice*>(s)->ctx_to_return;
            return 0;
        });

    static void* fac_vtbl[mobiro::gfx::d3d11_abi::DXGIFactory1Slots::kSlotCount]{};
    fac_vtbl[mobiro::gfx::d3d11_abi::DXGIFactory1Slots::kEnumAdapters1] =
        reinterpret_cast<void*>(+[](void* s, uint64_t /*idx*/, uint64_t out_pp) -> uint64_t {
            *reinterpret_cast<void**>(out_pp) = static_cast<FakeFactory*>(s)->adapter_to_return;
            return 0; // S_OK
        });

    FakeChild nat_adapter{child_vtbl, 10, 1};
    FakeChild nat_rtv0{child_vtbl, 1, 1}, nat_rtv1{child_vtbl, 2, 1}, nat_dsv{child_vtbl, 3, 1};
    FakeChild nat_vb0{child_vtbl, 4, 1}, nat_vb1{child_vtbl, 5, 1};
    FakeContext nat_ctx{ctx_vtbl, {nullptr, nullptr}, nullptr, {nullptr, nullptr}, 1};
    FakeDevice nat_dev{dev_vtbl, &nat_vb0, &nat_ctx, 1};
    FakeFactory nat_fac{fac_vtbl, &nat_adapter, 1};

    auto invoke_slot = [](mobiro::gfx::ComProxyObject* pr, size_t slot, x64emu_t& e) {
        e.rcx = reinterpret_cast<uint64_t>(pr);
        const auto* st = reinterpret_cast<const mobiro::cpu::NativeBridgeStub*>(pr->lpVtbl[slot]);
        reinterpret_cast<void(*)(x64emu_t*, uintptr_t)>(st->wrapper_ptr)(&e, static_cast<uintptr_t>(st->thunk_ptr));
    };

    // EnumAdapters1 -> auto-wraps returned adapter into DXGIAdapter1 proxy
    auto* fac_p = com.wrap(&nat_fac, mobiro::gfx::d3d11_abi::ComIfaceId::DXGIFactory1);
    void* out_adapter = nullptr;
    x64emu_t emu{};
    emu.rdx = 0; emu.r8 = reinterpret_cast<uint64_t>(&out_adapter);
    invoke_slot(fac_p, mobiro::gfx::d3d11_abi::DXGIFactory1Slots::kEnumAdapters1, emu);
    assert(emu.rax == 0 && out_adapter != nullptr);
    auto* adapter_p = com.find_proxy(reinterpret_cast<uintptr_t>(out_adapter));
    assert(adapter_p != nullptr && adapter_p->native_obj == &nat_adapter &&
           adapter_p->iface == mobiro::gfx::d3d11_abi::ComIfaceId::DXGIAdapter1);

    // CreateBuffer + GetImmediateContext -> auto-wraps both child buffer and context
    auto* dev_p = com.wrap(&nat_dev, mobiro::gfx::d3d11_abi::ComIfaceId::D3D11Device);
    void* out_vb0 = nullptr;
    emu = {}; emu.r9 = reinterpret_cast<uint64_t>(&out_vb0);
    invoke_slot(dev_p, mobiro::gfx::d3d11_abi::D3D11DeviceSlots::kCreateBuffer, emu);
    assert(emu.rax == 0 && com.find_proxy(reinterpret_cast<uintptr_t>(out_vb0))->native_obj == &nat_vb0);

    void* out_ctx = nullptr;
    emu = {}; emu.rdx = reinterpret_cast<uint64_t>(&out_ctx);
    invoke_slot(dev_p, mobiro::gfx::d3d11_abi::D3D11DeviceSlots::kGetImmediateContext, emu);
    auto* ctx_p = com.find_proxy(reinterpret_cast<uintptr_t>(out_ctx));
    assert(ctx_p != nullptr && ctx_p->native_obj == &nat_ctx &&
           ctx_p->iface == mobiro::gfx::d3d11_abi::ComIfaceId::D3D11DeviceContext);

    // OMSetRenderTargets + IASetVertexBuffers -> unwraps arrays of guest ComProxyObjects into native pointers
    auto* rtv0_p = com.wrap(&nat_rtv0, mobiro::gfx::d3d11_abi::ComIfaceId::D3D11ResourceChild);
    auto* rtv1_p = com.wrap(&nat_rtv1, mobiro::gfx::d3d11_abi::ComIfaceId::D3D11ResourceChild);
    auto* dsv_p  = com.wrap(&nat_dsv,  mobiro::gfx::d3d11_abi::ComIfaceId::D3D11ResourceChild);
    auto* vb1_p  = com.wrap(&nat_vb1,  mobiro::gfx::d3d11_abi::ComIfaceId::D3D11ResourceChild);

    void* guest_rtvs[2] = {rtv0_p, rtv1_p};
    emu = {}; emu.rdx = 2; emu.r8 = reinterpret_cast<uint64_t>(guest_rtvs); emu.r9 = reinterpret_cast<uint64_t>(dsv_p);
    invoke_slot(ctx_p, mobiro::gfx::d3d11_abi::D3D11DeviceContextSlots::kOMSetRenderTargets, emu);
    assert(nat_ctx.bound_rtvs[0] == &nat_rtv0 && nat_ctx.bound_rtvs[1] == &nat_rtv1 && nat_ctx.bound_dsv == &nat_dsv);

    void* guest_vbs[2] = {out_vb0, vb1_p};
    emu = {}; emu.rdx = 0; emu.r8 = 2; emu.r9 = reinterpret_cast<uint64_t>(guest_vbs);
    invoke_slot(ctx_p, mobiro::gfx::d3d11_abi::D3D11DeviceContextSlots::kIASetVertexBuffers, emu);
    assert(nat_ctx.bound_vbs[0] == &nat_vb0 && nat_ctx.bound_vbs[1] == &nat_vb1);
    com.clear();

    // 2. M13 Win32 shims: CreateMutex/ReleaseMutex, GetMonitorInfoW, EnumDisplaySettingsW, FindFirstFileW
    const fs::path tmp = fs::temp_directory_path() / "mobiro_test_m13";
    fs::remove_all(tmp);
    fs::create_directories(tmp);
    {
        std::ofstream f(tmp / "Data0.bdt", std::ios::binary);
        f << "BDF4DATA";
    }
    mobiro::validator::VfsMapper vfs;
    assert(vfs.index_root(tmp.string()));
    mobiro::mem::GuestArena arena;
    assert(arena.reserve(0x0000000100000000ULL, 128ULL * 1024 * 1024));
    mobiro::cpu::Box64Bridge bridge;
    assert(bridge.initialize(&arena, &vfs));
    bridge.window().set_dimensions(2400, 1080);

    emu = {}; emu.rdx = 1; // bInitialOwner = TRUE
    assert(bridge.invoke_thunk("kernel32.dll", "CreateMutexW", &emu) && emu.rax != 0);
    const uint64_t hmtx = emu.rax;
    emu = {}; emu.rcx = hmtx;
    assert(bridge.invoke_thunk("kernel32.dll", "ReleaseMutex", &emu) && emu.rax == 1);
    emu = {}; emu.rcx = hmtx; emu.rdx = 100;
    assert(bridge.invoke_thunk("kernel32.dll", "WaitForSingleObject", &emu) && emu.rax == 0);

    uint8_t mi[104]{};
    uint32_t mi_cb = 104;
    std::memcpy(mi, &mi_cb, 4);
    emu = {}; emu.rcx = 1; emu.rdx = reinterpret_cast<uint64_t>(mi);
    assert(bridge.invoke_thunk("user32.dll", "GetMonitorInfoW", &emu) && emu.rax == 1);
    int32_t mon_w = 0, mon_h = 0;
    std::memcpy(&mon_w, mi + 12, 4);
    std::memcpy(&mon_h, mi + 16, 4);
    assert(mon_w == 2400 && mon_h == 1080);

    uint8_t find_data[592]{};
    const uint16_t q_w[] = {'D','a','t','a','0','.','b','d','t', 0};
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>(q_w); emu.rdx = reinterpret_cast<uint64_t>(find_data);
    assert(bridge.invoke_thunk("kernel32.dll", "FindFirstFileW", &emu) &&
           emu.rax != mobiro::win32::FileHandleTable::kInvalidHandle);
    uint32_t sz_lo = 0;
    std::memcpy(&sz_lo, find_data + 32, 4);
    assert(sz_lo == 8);

    bridge.shutdown();
    fs::remove_all(tmp);
}

void test_m14_lockfree_com_pool_pacer_and_native_crt_mem() {
    // 1. Lock-free D3D11ComBridge slab: O(1) find/unwrap, misaligned safety, freelist reuse,
    //    concurrent wrap/destroy stress, and 100,000 zero-lock COM dispatches
    auto& com = mobiro::gfx::D3D11ComBridge::global();
    com.clear();

    struct FakeDrawCtx { const void* const* vtbl; uint64_t draws; };
    static void* draw_vtbl[mobiro::gfx::d3d11_abi::D3D11DeviceContextSlots::kSlotCount]{};
    draw_vtbl[mobiro::gfx::d3d11_abi::D3D11DeviceContextSlots::kDrawIndexed] =
        reinterpret_cast<void*>(+[](void* s, uint64_t idx_cnt, uint64_t, uint64_t) -> uint64_t {
            static_cast<FakeDrawCtx*>(s)->draws += idx_cnt;
            return 0;
        });

    FakeDrawCtx nat_ctx{draw_vtbl, 0};
    int dummy_a = 1, dummy_b = 2, dummy_c = 3;
    auto* p0 = com.wrap(&dummy_a, mobiro::gfx::d3d11_abi::ComIfaceId::D3D11ResourceChild);
    auto* p1 = com.wrap(&dummy_b, mobiro::gfx::d3d11_abi::ComIfaceId::D3D11ResourceChild);
    assert(p0 && p1 && com.active_proxy_count() == 2);

    // Arbitrary ints & misaligned in-slab pointers must never match or fault
    assert(com.find_proxy(0) == nullptr);
    assert(com.find_proxy(0xDEADBEEFULL) == nullptr);
    assert(com.find_proxy(reinterpret_cast<uintptr_t>(p0) + 8) == nullptr);
    assert(com.unwrap_arg(42) == 42);
    assert(com.unwrap_arg(reinterpret_cast<uint64_t>(p0) + 8) == reinterpret_cast<uint64_t>(p0) + 8);
    assert(com.unwrap_arg(reinterpret_cast<uint64_t>(p0)) == reinterpret_cast<uint64_t>(&dummy_a));

    // O(1) intrusive freelist reuse
    com.destroy_proxy(p0);
    assert(com.find_proxy(reinterpret_cast<uintptr_t>(p0)) == nullptr);
    assert(com.unwrap_arg(reinterpret_cast<uint64_t>(p0)) == reinterpret_cast<uint64_t>(p0));
    auto* p2 = com.wrap(&dummy_c, mobiro::gfx::d3d11_abi::ComIfaceId::D3D11ResourceChild);
    assert(p2 == p0 && p2->native_obj == &dummy_c && com.active_proxy_count() == 2);
    com.destroy_proxy(p1);
    com.destroy_proxy(p2);
    assert(com.active_proxy_count() == 0);

    auto* ctx_p = com.wrap(&nat_ctx, mobiro::gfx::d3d11_abi::ComIfaceId::D3D11DeviceContext);
    assert(ctx_p != nullptr);

    // Concurrent multi-thread wrap/find/destroy alongside 100k lock-free DrawIndexed dispatches
    std::vector<std::thread> workers;
    for (int t = 0; t < 4; ++t) {
        workers.emplace_back([&com, t]() {
            int local_obj = t + 100;
            for (int i = 0; i < 400; ++i) {
                auto* pr = com.wrap(&local_obj, mobiro::gfx::d3d11_abi::ComIfaceId::D3D11ResourceChild);
                assert(pr != nullptr);
                assert(com.find_proxy(reinterpret_cast<uintptr_t>(pr)) == pr);
                assert(com.unwrap_arg(reinterpret_cast<uint64_t>(pr)) == reinterpret_cast<uint64_t>(&local_obj));
                com.destroy_proxy(pr);
            }
        });
    }
    const auto* draw_stub = reinterpret_cast<const mobiro::cpu::NativeBridgeStub*>(
        ctx_p->lpVtbl[mobiro::gfx::d3d11_abi::D3D11DeviceContextSlots::kDrawIndexed]);
    auto draw_wrap = reinterpret_cast<void(*)(x64emu_t*, uintptr_t)>(draw_stub->wrapper_ptr);
    x64emu_t emu{};
    emu.rcx = reinterpret_cast<uint64_t>(ctx_p);
    emu.rdx = 3; // 3 indices per draw
    for (int i = 0; i < 100000; ++i) {
        draw_wrap(&emu, static_cast<uintptr_t>(draw_stub->thunk_ptr));
    }
    for (auto& w : workers) w.join();
    assert(nat_ctx.draws == 300000ULL);
    assert(com.active_proxy_count() == 1);
    com.clear();
    assert(com.active_proxy_count() == 0);

    // 2. Hybrid 60 FPS frame pacer telemetry + DXVK UMA pipeline lifetime config
    auto& interop = mobiro::gfx::DxvkInterop::global();
    interop.reset_pacer();
    interop.set_target_fps(60);
    assert(interop.pace_present() == 0);
    const int64_t work_ns = interop.pace_present();
    assert(work_ns >= 0);
    const auto pstats = interop.pacing_stats();
    assert(pstats.frames_presented == 2 && pstats.frames_dropped == 0);
    interop.reset_pacer();

    const std::string conf = mobiro::gfx::render_dxvk_conf({16384, 3, 60, false});
    assert(conf.find("dxvk.trackPipelineLifetime = True") != std::string::npos);

    // 3. Native ARM64 NEON-backed CRT & ntdll bulk memory/string thunks
    mobiro::mem::GuestArena arena;
    assert(arena.reserve(0x0000000100000000ULL, 128ULL * 1024 * 1024));
    mobiro::validator::VfsMapper vfs;
    mobiro::cpu::Box64Bridge bridge;
    assert(bridge.initialize(&arena, &vfs));

    char buf_a[32] = "SekiroShadowsDieTwice";
    char buf_b[32]{};
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>(buf_b); emu.rdx = reinterpret_cast<uint64_t>(buf_a); emu.r8 = 22;
    assert(bridge.invoke_thunk("vcruntime140.dll", "memcpy", &emu) && emu.rax == reinterpret_cast<uint64_t>(buf_b));
    assert(std::strcmp(buf_b, "SekiroShadowsDieTwice") == 0);

    // Overlapping memmove (shift right by 2)
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>(buf_b + 2); emu.rdx = reinterpret_cast<uint64_t>(buf_b); emu.r8 = 6;
    assert(bridge.invoke_thunk("ucrtbase.dll", "memmove", &emu));
    assert(std::memcmp(buf_b, "SeSekiro", 8) == 0);

    // memset / RtlFillMemory / RtlZeroMemory
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>(buf_b); emu.rdx = 0x5A; emu.r8 = 16;
    assert(bridge.invoke_thunk("msvcrt.dll", "memset", &emu) && buf_b[0] == 0x5A && buf_b[15] == 0x5A);
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>(buf_b); emu.rdx = 16; emu.r8 = 0x3C;
    assert(bridge.invoke_thunk("ntdll.dll", "RtlFillMemory", &emu) && buf_b[0] == 0x3C && buf_b[15] == 0x3C);
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>(buf_b); emu.rdx = 16;
    assert(bridge.invoke_thunk("ntdll.dll", "RtlZeroMemory", &emu) && buf_b[0] == 0 && buf_b[15] == 0);

    // strlen, wcslen, strcmp, strncmp, memcmp
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>(buf_a);
    assert(bridge.invoke_thunk("api-ms-win-crt-string-l1-1-0.dll", "strlen", &emu) && emu.rax == 21);
    const uint16_t w_str[] = {'A','s','h','i','n','a', 0};
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>(w_str);
    assert(bridge.invoke_thunk("ucrtbase.dll", "wcslen", &emu) && emu.rax == 6);
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>("Ashina"); emu.rdx = reinterpret_cast<uint64_t>("Ashina");
    assert(bridge.invoke_thunk("ucrtbase.dll", "strcmp", &emu) && emu.rax == 0);
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>("Ashina1"); emu.rdx = reinterpret_cast<uint64_t>("Ashina2"); emu.r8 = 6;
    assert(bridge.invoke_thunk("ucrtbase.dll", "strncmp", &emu) && emu.rax == 0);
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>("abcd"); emu.rdx = reinterpret_cast<uint64_t>("abce"); emu.r8 = 4;
    assert(bridge.invoke_thunk("vcruntime140.dll", "memcmp", &emu) && static_cast<int64_t>(emu.rax) < 0);

    bridge.shutdown();
}

void test_m15_segregated_heap_sharded_sync_and_parallel_io() {
    // 1. O(1) power-of-2 segregated GuestHeap: bucket reuse, double-free rejection, invalid ptr safety & MT churn
    mobiro::mem::GuestArena arena;
    assert(arena.reserve(0x0000000100000000ULL, 128ULL * 1024 * 1024));
    mobiro::win32::GuestHeap heap;
    assert(heap.initialize(&arena, 16 * 1024 * 1024));

    const uintptr_t p512 = heap.alloc(400, true);
    const uintptr_t p64k = heap.alloc(60000, false);
    assert(p512 && p64k);
    assert(heap.size_of(p512) == 512 && heap.size_of(p64k) == 65536);
    assert(!heap.free(0x123456ULL)); // Bogus pointer rejected safely
    assert(heap.free(p512));
    assert(!heap.free(p512));        // Double-free rejected safely
    assert(heap.size_of(p512) == ~size_t(0));

    // Reallocating 300B must pop the exact freed 512B bucket slot (O(1))
    const uintptr_t p512_reused = heap.alloc(300, true);
    assert(p512_reused == p512);
    const uintptr_t p_grown = heap.realloc(p512_reused, 2000, false);
    assert(p_grown != 0 && heap.size_of(p_grown) == 2048);
    assert(heap.free(p_grown) && heap.free(p64k));

    std::vector<std::thread> heap_threads;
    for (int t = 0; t < 4; ++t) {
        heap_threads.emplace_back([&heap, t]() {
            for (int i = 0; i < 600; ++i) {
                const size_t sz = 24u + static_cast<size_t>((i * 73 + t * 17) % 4096);
                const uintptr_t p = heap.alloc(sz, false);
                assert(p != 0 && heap.size_of(p) >= sz);
                std::memset(reinterpret_cast<void*>(p), static_cast<int>(t + 1), sz);
                assert(heap.free(p));
            }
        });
    }
    for (auto& th : heap_threads) th.join();

    // 2. 64-shard SrwLockTable + CriticalSectionTable concurrent correctness
    mobiro::win32::SrwLockTable srws;
    mobiro::win32::CriticalSectionTable css;
    constexpr int kLocks = 16;
    uint64_t srw_addrs[kLocks]{};
    uint64_t cs_addrs[kLocks]{};
    uint64_t srw_counts[kLocks]{};
    uint64_t cs_counts[kLocks]{};

    std::vector<std::thread> sync_threads;
    for (int t = 0; t < 4; ++t) {
        sync_threads.emplace_back([&]() {
            for (int i = 0; i < 500; ++i) {
                const int idx = i & (kLocks - 1);
                const uintptr_t s_addr = reinterpret_cast<uintptr_t>(&srw_addrs[idx]);
                const uintptr_t c_addr = reinterpret_cast<uintptr_t>(&cs_addrs[idx]);
                srws.acquire_exclusive(s_addr);
                ++srw_counts[idx];
                srws.release_exclusive(s_addr);

                css.enter(c_addr);
                css.enter(c_addr); // recursive lock check
                ++cs_counts[idx];
                css.leave(c_addr);
                css.leave(c_addr);
            }
        });
    }
    for (auto& th : sync_threads) th.join();
    uint64_t srw_sum = 0, cs_sum = 0;
    for (int i = 0; i < kLocks; ++i) { srw_sum += srw_counts[i]; cs_sum += cs_counts[i]; }
    assert(srw_sum == 2000ULL && cs_sum == 2000ULL);
    srws.clear();
    css.clear();

    // 3. Per-file parallel FileHandleTable streaming reads
    const fs::path tmp = fs::temp_directory_path() / "mobiro_test_m15";
    fs::remove_all(tmp);
    fs::create_directories(tmp);
    {
        std::ofstream f0(tmp / "Data0.bdt", std::ios::binary);
        std::ofstream f1(tmp / "Data1.bdt", std::ios::binary);
        std::string s0(4096, 'A'), s1(4096, 'B');
        f0.write(s0.data(), static_cast<std::streamsize>(s0.size()));
        f1.write(s1.data(), static_cast<std::streamsize>(s1.size()));
    }
    mobiro::validator::VfsMapper vfs;
    assert(vfs.index_root(tmp.string()));
    mobiro::win32::FileHandleTable files;
    const uint64_t h0 = files.open_read(&vfs, "Data0.bdt");
    const uint64_t h1 = files.open_read(&vfs, "Data1.bdt");
    assert(h0 != mobiro::win32::FileHandleTable::kInvalidHandle &&
           h1 != mobiro::win32::FileHandleTable::kInvalidHandle);

    std::vector<std::thread> io_threads;
    for (int t = 0; t < 4; ++t) {
        io_threads.emplace_back([&files, h0, h1, t]() {
            const uint64_t h = (t & 1) ? h1 : h0;
            const char expected = (t & 1) ? 'B' : 'A';
            char buf[64]{};
            for (int i = 0; i < 60; ++i) {
                mobiro::win32::Win64Overlapped ov{};
                ov.offset = static_cast<uint32_t>((i * 64) % 4032);
                uint32_t nread = 0;
                assert(files.read_file(h, buf, sizeof(buf), &nread, &ov) && nread == sizeof(buf));
                assert(buf[0] == expected && buf[63] == expected);
            }
        });
    }
    for (auto& th : io_threads) th.join();
    files.close_all();
    fs::remove_all(tmp);
}

void test_m16_init_once_slist_time_query_and_xinput_caps() {
    mobiro::mem::GuestArena arena;
    assert(arena.reserve(0x0000000100000000ULL, 128ULL * 1024 * 1024));
    mobiro::validator::VfsMapper vfs;
    mobiro::cpu::Box64Bridge bridge;
    assert(bridge.initialize(&arena, &vfs));

    // 1. SList push/pop/depth/flush (MSVC CRT & FromSoft lock-free pools)
    alignas(16) uint64_t slist_hdr[2]{};
    alignas(16) uint64_t node_a[2]{}, node_b[2]{};
    x64emu_t emu{};
    emu.rcx = reinterpret_cast<uint64_t>(slist_hdr);
    assert(bridge.invoke_thunk("kernel32.dll", "InitializeSListHead", &emu));
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>(slist_hdr); emu.rdx = reinterpret_cast<uint64_t>(node_a);
    assert(bridge.invoke_thunk("kernel32.dll", "InterlockedPushEntrySList", &emu) && emu.rax == 0);
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>(slist_hdr); emu.rdx = reinterpret_cast<uint64_t>(node_b);
    assert(bridge.invoke_thunk("ntdll.dll", "RtlInterlockedPushEntrySList", &emu) &&
           emu.rax == reinterpret_cast<uint64_t>(node_a));
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>(slist_hdr);
    assert(bridge.invoke_thunk("kernel32.dll", "QueryDepthSList", &emu) && emu.rax == 2);
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>(slist_hdr);
    assert(bridge.invoke_thunk("kernel32.dll", "InterlockedPopEntrySList", &emu) &&
           emu.rax == reinterpret_cast<uint64_t>(node_b));
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>(slist_hdr);
    assert(bridge.invoke_thunk("kernel32.dll", "InterlockedFlushSList", &emu) &&
           emu.rax == reinterpret_cast<uint64_t>(node_a));
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>(slist_hdr);
    assert(bridge.invoke_thunk("kernel32.dll", "QueryDepthSList", &emu) && emu.rax == 0);

    // 2. InitOnceBeginInitialize / InitOnceComplete (MSVC std::call_once)
    uint64_t once = 0;
    uint32_t pending = 0;
    void* out_ctx = nullptr;
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>(&once); emu.rdx = 0;
    emu.r8 = reinterpret_cast<uint64_t>(&pending); emu.r9 = reinterpret_cast<uint64_t>(&out_ctx);
    assert(bridge.invoke_thunk("kernel32.dll", "InitOnceBeginInitialize", &emu) && emu.rax == 1 && pending == 1);

    int sentinel_ctx = 99;
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>(&once); emu.rdx = 0;
    emu.r8 = reinterpret_cast<uint64_t>(&sentinel_ctx);
    assert(bridge.invoke_thunk("kernel32.dll", "InitOnceComplete", &emu) && emu.rax == 1);

    pending = 1;
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>(&once); emu.rdx = 0;
    emu.r8 = reinterpret_cast<uint64_t>(&pending); emu.r9 = reinterpret_cast<uint64_t>(&out_ctx);
    assert(bridge.invoke_thunk("kernel32.dll", "InitOnceBeginInitialize", &emu) &&
           emu.rax == 1 && pending == 0 && out_ctx == &sentinel_ctx);

    // 3. GetLocalTime, VirtualQuery, GetUserDefaultLCID, XInputGetCapabilities
    uint16_t st[8]{};
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>(st);
    assert(bridge.invoke_thunk("kernel32.dll", "GetLocalTime", &emu) && st[0] >= 2024 && st[1] >= 1 && st[1] <= 12);

    uint64_t mbi[6]{};
    emu = {}; emu.rcx = 0x100001234ULL; emu.rdx = reinterpret_cast<uint64_t>(mbi); emu.r8 = sizeof(mbi);
    assert(bridge.invoke_thunk("kernel32.dll", "VirtualQuery", &emu) && emu.rax == 48 && mbi[0] == 0x100001000ULL);

    emu = {};
    assert(bridge.invoke_thunk("kernel32.dll", "GetUserDefaultLCID", &emu) && emu.rax == 0x0409ULL);

    uint8_t xcaps[20]{};
    emu = {}; emu.rcx = 0; emu.rdx = 1; emu.r8 = reinterpret_cast<uint64_t>(xcaps);
    assert(bridge.invoke_thunk("xinput1_4.dll", "XInputGetCapabilities", &emu) &&
           emu.rax == 0 && xcaps[0] == 1 && xcaps[1] == 1);

    bridge.shutdown();
}

void test_m17_xaudio2_onebridge_ring_and_gourd_touch() {
    auto& xa_br = mobiro::audio::XAudio2ComBridge::global();
    xa_br.clear();
    auto& aaudio = mobiro::audio::AAudioXAudioBridge::global();
    aaudio.stop();

    // 1. End-to-end Win64 Box64 onebridge_t XAudio2.9 dispatch (including XMM1 SetVolume + 5.1 EXTENSIBLE downmix)
    mobiro::mem::GuestArena arena;
    assert(arena.reserve(0x0000000100000000ULL, 128ULL * 1024 * 1024));
    mobiro::validator::VfsMapper vfs;
    mobiro::cpu::Box64Bridge bridge;
    assert(bridge.initialize(&arena, &vfs));

    auto invoke_xa = [](mobiro::audio::XAudioProxyObject* pr, size_t slot, x64emu_t& e) {
        e.rcx = reinterpret_cast<uint64_t>(pr);
        const auto* st = reinterpret_cast<const mobiro::cpu::NativeBridgeStub*>(pr->lpVtbl[slot]);
        assert(st->trap_cc == 0xCC && st->magic[0] == 'S' && st->magic[1] == 'C');
        reinterpret_cast<void(*)(x64emu_t*, uintptr_t)>(st->wrapper_ptr)(&e, static_cast<uintptr_t>(st->thunk_ptr));
    };

    void* xa_guest = nullptr;
    x64emu_t emu{};
    emu.rcx = reinterpret_cast<uint64_t>(&xa_guest);
    assert(bridge.invoke_thunk("xaudio2_9.dll", "XAudio2Create", &emu) && emu.rax == 0);
    auto* xa_p = xa_br.find_proxy(reinterpret_cast<uintptr_t>(xa_guest));
    assert(xa_p != nullptr && xa_br.active_proxy_count() == 1);

    // CreateMasteringVoice (slot 7) -> auto-wraps mastering voice proxy
    void* mv_guest = nullptr;
    emu = {}; emu.rdx = reinterpret_cast<uint64_t>(&mv_guest); emu.r8 = 2; emu.r9 = 48000;
    invoke_xa(xa_p, 7, emu);
    auto* mv_p = xa_br.find_proxy(reinterpret_cast<uintptr_t>(mv_guest));
    assert(emu.rax == 0 && mv_p != nullptr);

    // CreateSourceVoice (slot 5) with 6-channel WAVE_FORMAT_EXTENSIBLE (0xFFFE) float32 -> auto-wraps voice proxy
    mobiro::audio::WaveFormatEx fmt51{};
    fmt51.format_tag = 0xFFFEu;
    fmt51.channels = 6;
    fmt51.samples_per_sec = 48000;
    fmt51.bits_per_sample = 32;
    void* sv_guest = nullptr;
    emu = {}; emu.rdx = reinterpret_cast<uint64_t>(&sv_guest); emu.r8 = reinterpret_cast<uint64_t>(&fmt51);
    invoke_xa(xa_p, 5, emu);
    auto* sv_p = xa_br.find_proxy(reinterpret_cast<uintptr_t>(sv_guest));
    assert(emu.rax == 0 && sv_p != nullptr && xa_br.active_proxy_count() == 3);

    // SetVolume (slot 12) via XMM1 = 0.5f
    emu = {};
    mobiro::cpu::emu_set_xmm_f32(&emu, 1, 0.5f);
    invoke_xa(sv_p, 12, emu);
    assert(emu.rax == 0);

    // SubmitSourceBuffer (slot 21): 1 frame of 6-ch audio (L=0.4, R=0.8, C=0.0, ...) * 0.5 gain -> L=0.2, R=0.4
    const float frame51[6] = {0.4f, 0.8f, 0.0f, 0.0f, 0.0f, 0.0f};
    mobiro::audio::XAudio2Buffer xbuf{};
    xbuf.audio_bytes = sizeof(frame51);
    xbuf.audio_data = reinterpret_cast<const uint8_t*>(frame51);
    emu = {}; emu.rdx = reinterpret_cast<uint64_t>(&xbuf);
    invoke_xa(sv_p, 21, emu);
    assert(emu.rax == 0);

    float drained[2]{};
    assert(aaudio.drain_pcm_float(drained, 2) == 2);
    assert(std::abs(drained[0] - 0.2f) < 1e-4f && std::abs(drained[1] - 0.4f) < 1e-4f);

    // DestroyVoice (slot 18) + Release (slot 2) reclaim all proxies automatically
    emu = {}; invoke_xa(sv_p, 18, emu);
    emu = {}; invoke_xa(mv_p, 18, emu);
    emu = {}; invoke_xa(xa_p, 2, emu);
    assert(xa_br.active_proxy_count() == 0);
    aaudio.stop();

    // 2. PcmRingBuffer wrap-around bulk memcpy integrity
    mobiro::audio::PcmRingBuffer ring(16);
    float in10[10] = {1,2,3,4,5,6,7,8,9,10};
    float out10[10]{};
    assert(ring.write(in10, 10) == 10 && ring.read(out10, 10) == 10);
    assert(ring.write(in10, 10) == 10 && ring.read(out10, 10) == 10); // wraps across end->0 boundary
    assert(out10[0] == 1.0f && out10[9] == 10.0f);

    // 3. TouchController Healing Gourd (D-Pad Up), Crouch (L3) & camera look decay
    mobiro::input::InputRouter router;
    mobiro::input::TouchController tc;
    tc.set_viewport(1920.0f, 1080.0f);
    tc.on_pointer(10, mobiro::input::TouchAction::Down, 0.25f * 1920.0f, 0.22f * 1080.0f, router); // D-Pad Up (Gourd)
    tc.on_pointer(11, mobiro::input::TouchAction::Down, 0.14f * 1920.0f, 0.48f * 1080.0f, router); // L3 (Crouch)
    auto snap = router.snapshot();
    assert((snap.Gamepad.wButtons & mobiro::input::kDpadUp) != 0);
    assert((snap.Gamepad.wButtons & mobiro::input::kLeftThumb) != 0);

    tc.on_pointer(12, mobiro::input::TouchAction::Down, 0.55f * 1920.0f, 0.50f * 1080.0f, router);
    tc.on_pointer(12, mobiro::input::TouchAction::Move, 0.60f * 1920.0f, 0.50f * 1080.0f, router);
    assert(router.snapshot().Gamepad.sThumbRX > 0);
    tc.decay_camera_look(router);
    assert(router.snapshot().Gamepad.sThumbRX == 0);

    bridge.shutdown();
}

void test_m18_winmm_waveout_xinput_ordinals_and_sekiro_compat() {
    auto& aaudio = mobiro::audio::AAudioXAudioBridge::global();
    aaudio.stop();

    mobiro::mem::GuestArena arena;
    assert(arena.reserve(0x0000000100000000ULL, 128ULL * 1024 * 1024));
    mobiro::validator::VfsMapper vfs;
    mobiro::cpu::Box64Bridge bridge;
    assert(bridge.initialize(&arena, &vfs));

    // 1. xinput1_3.dll ordinals #2 (XInputGetState) and #3 (XInputSetState) + dxgi!CreateDXGIFactory
    mobiro::input::InputRouter::global().set_button(mobiro::input::kRightShoulder, true);
    mobiro::input::XInputState xi{};
    x64emu_t emu{};
    emu.rcx = 0; emu.rdx = reinterpret_cast<uint64_t>(&xi);
    assert(bridge.invoke_thunk("xinput1_3.dll", "#2", &emu) && emu.rax == 0);
    assert((xi.Gamepad.wButtons & mobiro::input::kRightShoulder) != 0);
    mobiro::input::InputRouter::global().set_button(mobiro::input::kRightShoulder, false);
    emu = {}; emu.rcx = 0;
    assert(bridge.invoke_thunk("xinput1_3.dll", "#3", &emu) && emu.rax == 0);
    assert(bridge.resolve_import("dxgi.dll", "CreateDXGIFactory") != 0);

    // 2. WinMM waveOut* -> AAudioXAudioBridge (FMODEx & Bink2 real audio path)
    emu = {};
    assert(bridge.invoke_thunk("winmm.dll", "waveOutGetNumDevs", &emu) && emu.rax == 1);

    uint64_t hwo = 0;
    mobiro::audio::WaveFormatEx wfmt{};
    wfmt.format_tag = 1; wfmt.channels = 2; wfmt.samples_per_sec = 48000;
    wfmt.bits_per_sample = 16; wfmt.block_align = 4; wfmt.avg_bytes_per_sec = 192000;
    const uint64_t ev = bridge.events().create_event(true, false);
    uint64_t wo_stack[8]{};
    wo_stack[5] = 0;                                             // dwInstance
    wo_stack[6] = mobiro::audio::WinmmWaveOutBridge::kCallbackEvent; // fdwOpen
    emu = {};
    emu.rcx = reinterpret_cast<uint64_t>(&hwo);
    emu.rdx = 0xFFFFFFFFu; // WAVE_MAPPER
    emu.r8  = reinterpret_cast<uint64_t>(&wfmt);
    emu.r9  = ev;
    emu.rsp = reinterpret_cast<uint64_t>(wo_stack);
    assert(bridge.invoke_thunk("winmm.dll", "waveOutOpen", &emu) && emu.rax == 0 && hwo != 0);

    int16_t pcm[4] = {16384, -16384, 32767, -32768};
    mobiro::audio::Win64WaveHdr hdr{};
    hdr.lpData = reinterpret_cast<uint8_t*>(pcm);
    hdr.dwBufferLength = sizeof(pcm);
    emu = {}; emu.rcx = hwo; emu.rdx = reinterpret_cast<uint64_t>(&hdr); emu.r8 = sizeof(hdr);
    assert(bridge.invoke_thunk("winmm.dll", "waveOutPrepareHeader", &emu) && emu.rax == 0);
    assert((hdr.dwFlags & mobiro::audio::WinmmWaveOutBridge::kWhdrPrepared) != 0);

    emu = {}; emu.rcx = hwo; emu.rdx = reinterpret_cast<uint64_t>(&hdr); emu.r8 = sizeof(hdr);
    assert(bridge.invoke_thunk("winmm.dll", "waveOutWrite", &emu) && emu.rax == 0);
    assert((hdr.dwFlags & mobiro::audio::WinmmWaveOutBridge::kWhdrDone) != 0);
    assert(bridge.events().wait_single(ev, 0) == mobiro::win32::EventTable::kWaitObject0);

    float drained[4]{};
    assert(aaudio.drain_pcm_float(drained, 4) == 4);
    assert(std::abs(drained[0] - 0.5f) < 1e-3f && std::abs(drained[1] + 0.5f) < 1e-3f);

    mobiro::audio::Win64MmTime mmt{};
    mmt.wType = 4; // TIME_BYTES
    emu = {}; emu.rcx = hwo; emu.rdx = reinterpret_cast<uint64_t>(&mmt); emu.r8 = sizeof(mmt);
    assert(bridge.invoke_thunk("winmm.dll", "waveOutGetPosition", &emu) && emu.rax == 0 && mmt.value == 8);

    emu = {}; emu.rcx = hwo;
    assert(bridge.invoke_thunk("winmm.dll", "waveOutClose", &emu) && emu.rax == 0);
    aaudio.stop();

    // 3. Key retail Sekiro kernel32 / oleaut32 / advapi32 thunks
    emu = {};
    assert(bridge.invoke_thunk("kernel32.dll", "GetVersion", &emu) && (emu.rax & 0xFF) == 10);
    const uint16_t bstr_in[] = {'W','o','l','f', 0};
    emu = {}; emu.rcx = reinterpret_cast<uint64_t>(bstr_in);
    assert(bridge.invoke_thunk("oleaut32.dll", "#2", &emu) && emu.rax != 0);
    const uint64_t bstr = emu.rax;
    emu = {}; emu.rcx = bstr;
    assert(bridge.invoke_thunk("oleaut32.dll", "#6", &emu));

    bridge.shutdown();
}

} // namespace

int main(int argc, char** argv) {
    if (argc == 3 && std::strcmp(argv[1], "--dump-spirv") == 0) {
        const fs::path out_dir(argv[2]);
        fs::create_directories(out_dir);
        std::ofstream vf(out_dir / "hud.vert.spv", std::ios::binary | std::ios::trunc);
        vf.write(reinterpret_cast<const char*>(mobiro::gfx::spirv::kHudVertSpv),
                 sizeof(mobiro::gfx::spirv::kHudVertSpv));
        std::ofstream ff(out_dir / "hud.frag.spv", std::ios::binary | std::ios::trunc);
        ff.write(reinterpret_cast<const char*>(mobiro::gfx::spirv::kHudFragSpv),
                 sizeof(mobiro::gfx::spirv::kHudFragSpv));
        return 0;
    }
    if (argc == 3 && std::strcmp(argv[1], "--verify-byof") == 0) {
        mobiro::validator::VfsMapper vfs;
        auto rep = mobiro::validator::validate_byof_directory(argv[2], vfs);
        if (!rep.ok) {
            std::cerr << "BYOF validation failed: " << rep.error << "\n";
            return 1;
        }
        mobiro::mem::GuestArena arena;
        if (!arena.reserve(0x0000000100000000ULL, 2ULL * 1024 * 1024 * 1024)) {
            std::cerr << "GuestArena reserve failed\n";
            return 2;
        }
        mobiro::cpu::Box64Bridge bridge;
        if (!bridge.initialize(&arena, &vfs)) {
            std::cerr << "Box64Bridge init failed\n";
            return 3;
        }
        std::string exe_host;
        vfs.resolve("sekiro.exe", exe_host);
        auto pe = mobiro::cpu::PeLoader::load_pe64(exe_host, arena, bridge);
        std::cout << "BYOF OK: archives=" << rep.verified_archive_pairs
                  << " pe_ok=" << (pe.ok ? 1 : 0)
                  << " base=0x" << std::hex << pe.mapped_base << std::dec
                  << " relocs=" << pe.relocations_applied
                  << " dep_dlls=" << pe.dep_dlls.size()
                  << " iat_resolved=" << pe.imports_resolved
                  << " iat_unresolved=" << pe.unresolved_imports.size() << "\n";
        for (const auto& u : pe.unresolved_imports) std::cout << "  UNRESOLVED: " << u << "\n";
        bridge.shutdown();
        return (pe.ok && pe.unresolved_imports.empty()) ? 0 : 4;
    }
    test_byof_validator_and_vfs();
    test_pe_loader_teb_and_win32_thunks();
    test_dxvk_config_and_topology();
    test_x86_64_guest_execution_and_seh();
    test_dxvk_interop_and_ms_x64_marshaling();
    test_vfs_write_overlay_threads_wait_and_audio();
    test_touch_controller_and_cache_warmer();
    test_xaudio2_com_and_touch_overlay_vk();
    test_module_loader_and_headless_win32_ui();
    test_d3d11_com_bridge_ext_win32_and_hud_draw();
    test_m10_xmm_com_auto_wrap_and_dllmain_tls();
    test_m11_box64_onebridge_condvar_sem_and_crt();
    test_m12_dep_dll_unresolved_trap_and_create_thread_exec();
    test_m13_com_out_param_wrapping_and_array_unwrapping();
    test_m14_lockfree_com_pool_pacer_and_native_crt_mem();
    test_m15_segregated_heap_sharded_sync_and_parallel_io();
    test_m16_init_once_slist_time_query_and_xinput_caps();
    test_m17_xaudio2_onebridge_ring_and_gourd_touch();
    test_m18_winmm_waveout_xinput_ordinals_and_sekiro_compat();
    std::cout << "All Mobiro core unit tests passed.\n";
    return 0;
}
