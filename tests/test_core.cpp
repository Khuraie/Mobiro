#include "cpu_mem/box64_bridge.hpp"
#include "cpu_mem/guest_arena.hpp"
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

// Constructs a clean synthetic minimal PE32+ binary (x86_64) with one section importing d3d11.dll
void write_synthetic_pe64(const fs::path& path, bool include_d3d11_import) {
    std::vector<uint8_t> img(0x1000, 0);
    // DOS header
    img[0] = 'M'; img[1] = 'Z';
    const uint32_t pe_off = 0x80;
    wr32(img, 0x3C, pe_off);

    // PE signature
    img[pe_off] = 'P'; img[pe_off + 1] = 'E';
    const size_t coff = pe_off + 4;
    wr16(img, coff + 0, 0x8664); // AMD64
    wr16(img, coff + 2, 1);      // NumberOfSections = 1
    const uint16_t opt_size = 0xF0;
    wr16(img, coff + 16, opt_size);

    // Optional Header (PE32+)
    const size_t opt = coff + 20;
    wr16(img, opt + 0, 0x020B);                   // PE32+ magic
    wr32(img, opt + 16, 0x1000);                  // AddressOfEntryPoint
    wr64(img, opt + 24, 0x0000000140000000ULL);   // ImageBase
    wr32(img, opt + 56, 0x4000);                  // SizeOfImage
    wr32(img, opt + 108, 16);                     // NumberOfRvaAndSizes
    if (include_d3d11_import) {
        wr32(img, opt + 120, 0x1000);             // DataDirectory[1] Import RVA
        wr32(img, opt + 124, 40);                 // Import Size
    }

    // Section 0 (.rdata): VA=0x1000, RawPtr=0x400, RawSize=0x400
    const size_t sec = opt + opt_size;
    std::memcpy(&img[sec], ".rdata", 6);
    wr32(img, sec + 8, 0x400);   // VirtualSize
    wr32(img, sec + 12, 0x1000); // VirtualAddress
    wr32(img, sec + 16, 0x400);  // SizeOfRawData
    wr32(img, sec + 20, 0x400);  // PointerToRawData

    if (include_d3d11_import) {
        // Import descriptor at file offset 0x400 (RVA 0x1000)
        wr32(img, 0x400 + 12, 0x1040); // Name RVA -> file offset 0x440
        wr32(img, 0x400 + 16, 0x1080); // FirstThunk non-zero
        std::memcpy(&img[0x440], "d3d11.dll", 10);
    }

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
        bdt.write("BDF4\0\0\0\0\0\0\0\0\0\0\0\0", 16);
    }

    mobiro::validator::VfsMapper vfs;
    auto rep = mobiro::validator::validate_byof_directory(tmp.string(), vfs);
    assert(rep.ok);
    assert(rep.verified_archive_pairs == 6);
    assert(rep.pe.preferred_image_base == 0x0000000140000000ULL);
    assert(!rep.pe.build_fingerprint.empty());

    // Case-insensitive Windows path resolution
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

void test_guest_arena_and_thunks() {
    mobiro::mem::GuestArena arena;
    assert(arena.reserve(0x0000000100000000ULL, 1024ULL * 1024 * 1024));

    mobiro::validator::VfsMapper vfs;
    mobiro::cpu::Box64Bridge bridge;
    assert(bridge.initialize(&arena, &vfs));

    // Verify IAT stub creation
    uintptr_t stub = bridge.resolve_import("KERNEL32.DLL", "VirtualAlloc");
    assert(stub != 0);

    // Invoke VirtualAlloc thunk (MEM_COMMIT | MEM_RESERVE, 128 KiB, PAGE_READWRITE)
    x64emu_t emu{};
    emu.rcx = 0;
    emu.rdx = 128 * 1024;
    emu.r8 = 0x3000;
    emu.r9 = 0x04;
    assert(bridge.invoke_thunk("kernel32.dll", "VirtualAlloc", &emu));
    assert(emu.rax != 0);
    assert(arena.committed_bytes() >= 128 * 1024);

    // Invoke VirtualFree thunk
    x64emu_t free_emu{};
    free_emu.rcx = emu.rax;
    free_emu.rdx = 128 * 1024;
    assert(bridge.invoke_thunk("kernel32.dll", "VirtualFree", &free_emu));
    assert(free_emu.rax == 1);
    assert(arena.committed_bytes() == 0);

    // Invoke XInputGetState thunk after updating InputRouter
    auto& router = mobiro::input::InputRouter::global();
    router.set_button(mobiro::input::kLeftShoulder, true); // Deflect
    router.set_left_stick(0.05f, 0.05f, 0.12f);            // Inside deadzone -> (0,0)
    router.set_right_stick(1.0f, 0.0f, 0.10f);             // Full right -> (32767, 0)

    mobiro::input::XInputState xi{};
    x64emu_t xi_emu{};
    xi_emu.rcx = 0;
    xi_emu.rdx = reinterpret_cast<uint64_t>(&xi);
    assert(bridge.invoke_thunk("xinput1_4.dll", "XInputGetState", &xi_emu));
    assert(xi_emu.rax == 0);
    assert((xi.Gamepad.wButtons & mobiro::input::kLeftShoulder) != 0);
    assert(xi.Gamepad.sThumbLX == 0 && xi.Gamepad.sThumbLY == 0);
    assert(xi.Gamepad.sThumbRX == 32767 && xi.Gamepad.sThumbRY == 0);

    bridge.shutdown();
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

    // Simulate Snapdragon 8 Gen 3 topology: 1 Prime + 5 Perf + 2 Eff
    auto topo = mobiro::sched::CpuTopology::classify({
        {0, 2265600}, {1, 2265600},
        {2, 2956800}, {3, 2956800}, {4, 3148800}, {5, 3148800}, {6, 3148800},
        {7, 3302400}
    });
    assert(topo.prime_cores.size() == 1 && topo.prime_cores[0] == 7);
    assert(topo.eff_cores.size() == 2);
    assert(topo.perf_cores.size() == 5);
}

} // namespace

int main() {
    test_byof_validator_and_vfs();
    test_guest_arena_and_thunks();
    test_dxvk_config_and_topology();
    std::cout << "All Mobiro core unit tests passed.\n";
    return 0;
}
