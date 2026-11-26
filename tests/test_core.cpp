#undef NDEBUG
#include "audio/aaudio_xaudio_bridge.hpp"
#include "audio/xaudio2_com.hpp"
#include "cpu_mem/box64_bridge.hpp"
#include "cpu_mem/guest_arena.hpp"
#include "cpu_mem/guest_executor.hpp"
#include "cpu_mem/pe_loader.hpp"
#include "cpu_mem/win64_teb.hpp"
#include "gfx/dxvk_config_gen.hpp"
#include "gfx/dxvk_interop.hpp"
#include "gfx/pipeline_cache_warmer.hpp"
#include "gfx/touch_overlay_vk.hpp"
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

    // Corrupt BDF4 magic should fail cleanly
    {
        std::ofstream bad_bdt(tmp / "Data2.bdt", std::ios::binary | std::ios::trunc);
        bad_bdt.write("XXXX000000000000", 16);
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
    assert(stub->trap_cc == 0xCC && stub->magic[0] == 'M' && stub->magic[1] == 'B');

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
    assert(arena.reserve(0x0000000100000000ULL, 64ULL * 1024 * 1024));
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
    assert(arena.reserve(0x0000000100000000ULL, 64ULL * 1024 * 1024));
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
    auto* xa2_com = static_cast<mobiro::audio::IXAudio2Com*>(xa2_ptr);
    assert(xa2_com->lpVtbl->Release(xa2_com) == 0);

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

    // Active floating stick produces 10 button quads + 2 stick quads = 12 quads
    auto quads = tc.build_hud_quads();
    assert(quads.size() == 12);

    // Release camera & L1, then cancel clears left stick
    tc.on_pointer(2, mobiro::input::TouchAction::Up, 0.86f * 1920.0f, 0.44f * 1080.0f, router);
    tc.on_pointer(3, mobiro::input::TouchAction::Up, 0.59f * 1920.0f, 0.50f * 1080.0f, router);
    snap = router.snapshot();
    assert((snap.Gamepad.wButtons & mobiro::input::kLeftShoulder) == 0);
    assert(snap.Gamepad.sThumbRX == 0);

    tc.on_pointer(0, mobiro::input::TouchAction::Cancel, 0.0f, 0.0f, router);
    snap = router.snapshot();
    assert(snap.Gamepad.sThumbLX == 0 && snap.Gamepad.sThumbLY == 0);
    assert(tc.build_hud_quads().size() == 10);

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
    assert(arena.reserve(0x0000000100000000ULL, 64ULL * 1024 * 1024));
    mobiro::validator::VfsMapper vfs;
    mobiro::cpu::Box64Bridge bridge;
    assert(bridge.initialize(&arena, &vfs));

    void* xa2_raw = nullptr;
    x64emu_t emu{};
    emu.rcx = reinterpret_cast<uint64_t>(&xa2_raw);
    assert(bridge.invoke_thunk("xaudio2_9.dll", "XAudio2Create", &emu));
    assert(emu.rax == 0 && xa2_raw != nullptr);

    auto* xa2 = static_cast<mobiro::audio::IXAudio2Com*>(xa2_raw);
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
    aaudio.stop();
    bridge.shutdown();

    // 2. TouchOverlayVk: 12 quads -> 72 NDC vertices, auto-hides when controller disables overlay
    mobiro::input::InputRouter router;
    mobiro::input::TouchController tc;
    tc.set_viewport(1920.0f, 1080.0f);
    tc.on_pointer(1, mobiro::input::TouchAction::Down, 300.0f, 700.0f, router);
    auto quads = tc.build_hud_quads();
    assert(quads.size() == 12);

    mobiro::gfx::TouchOverlayVk overlay;
    assert(overlay.pack_quads(quads) == 72);
    assert(overlay.vertex_bytes() == 72 * sizeof(mobiro::gfx::HudVertex));
    for (const auto& v : overlay.vertices()) {
        assert(v.x >= -1.0f && v.x <= 1.0f);
        assert(v.y >= -1.0f && v.y <= 1.0f);
        assert(v.a >= 0.0f && v.a <= 1.0f);
    }

    overlay.set_enabled(false);
    assert(overlay.pack_quads(quads) == 0);
}

} // namespace

int main() {
    test_byof_validator_and_vfs();
    test_pe_loader_teb_and_win32_thunks();
    test_dxvk_config_and_topology();
    test_x86_64_guest_execution_and_seh();
    test_dxvk_interop_and_ms_x64_marshaling();
    test_vfs_write_overlay_threads_wait_and_audio();
    test_touch_controller_and_cache_warmer();
    test_xaudio2_com_and_touch_overlay_vk();
    std::cout << "All Mobiro core unit tests passed.\n";
    return 0;
}
