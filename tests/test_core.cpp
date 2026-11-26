#include "cpu_mem/box64_bridge.hpp"
#include "cpu_mem/guest_arena.hpp"
#include "cpu_mem/guest_executor.hpp"
#include "cpu_mem/pe_loader.hpp"
#include "cpu_mem/win64_teb.hpp"
#include "gfx/dxvk_config_gen.hpp"
#include "input/input_router.hpp"
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

} // namespace

int main() {
    test_byof_validator_and_vfs();
    test_pe_loader_teb_and_win32_thunks();
    test_dxvk_config_and_topology();
    test_x86_64_guest_execution_and_seh();
    std::cout << "All Mobiro core unit tests passed.\n";
    return 0;
}
