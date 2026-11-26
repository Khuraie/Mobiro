#pragma once

#include "box64_bridge.hpp"
#include "guest_arena.hpp"
#include "../validator/pe_validator.hpp"

#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace mobiro::cpu {

struct DepDllInitEntry {
    uintptr_t mapped_base = 0;
    uintptr_t entry_point = 0;
    uintptr_t tls_dir_va = 0;
};

struct LoadedPeImage {
    bool ok = false;
    std::string error;
    uintptr_t mapped_base = 0;
    uintptr_t preferred_base = 0;
    uintptr_t entry_point = 0;
    size_t image_size = 0;
    uintptr_t pdata_va = 0;      // Exception Directory (.pdata) for SEH unwind
    uint32_t pdata_size = 0;
    uintptr_t tls_dir_va = 0;    // TLS Directory for static TLS callbacks
    size_t relocations_applied = 0;
    size_t imports_resolved = 0;
    std::vector<std::string> unresolved_imports;
    std::vector<DepDllInitEntry> dep_dlls; // Topological init order for auto-loaded BYOF DLLs
    std::unordered_map<std::string, uintptr_t> exports_by_name;
    std::unordered_map<uint16_t, uintptr_t> exports_by_ordinal;
};

// Maps a validated Win64 PE32+ image into GuestArena, applies DIR64/HIGHLOW relocations
// when mapped away from ImageBase, and patches IAT entries with Box64 native thunk stubs.
class PeLoader {
public:
    static LoadedPeImage load_pe64(const std::string& exe_path,
                                   mem::GuestArena& arena,
                                   Box64Bridge& bridge,
                                   bool force_relocate = false) {
        std::unordered_set<std::string> active_stack;
        return load_pe64_impl(exe_path, arena, bridge, force_relocate, active_stack);
    }

private:
    static LoadedPeImage load_pe64_impl(const std::string& exe_path,
                                        mem::GuestArena& arena,
                                        Box64Bridge& bridge,
                                        bool force_relocate,
                                        std::unordered_set<std::string>& active_stack) {
        LoadedPeImage res;
        std::ifstream f(exe_path, std::ios::binary | std::ios::ate);
        if (!f) {
            res.error = "Unable to open PE file: " + exe_path;
            return res;
        }
        const auto file_size = static_cast<size_t>(f.tellg());
        if (file_size < 0x200) {
            res.error = "PE file truncated.";
            return res;
        }
        std::vector<uint8_t> raw(file_size);
        f.seekg(0);
        f.read(reinterpret_cast<char*>(raw.data()), static_cast<std::streamsize>(file_size));

        using validator::detail::rd16;
        using validator::detail::rd32;
        using validator::detail::rd64;

        if (raw[0] != 'M' || raw[1] != 'Z') {
            res.error = "Missing MZ header.";
            return res;
        }
        const uint32_t pe_off = rd32(&raw[0x3C]);
        if (pe_off + 0x108 > raw.size()) {
            res.error = "Invalid PE header offset.";
            return res;
        }
        const uint8_t* coff = &raw[pe_off + 4];
        const uint16_t machine = rd16(coff + 0);
        const uint16_t num_sections = rd16(coff + 2);
        const uint16_t opt_size = rd16(coff + 16);
        if (machine != 0x8664) {
            res.error = "Not an x86_64 PE binary.";
            return res;
        }

        const uint8_t* opt = coff + 20;
        if (rd16(opt + 0) != 0x020B) {
            res.error = "Not a PE32+ optional header.";
            return res;
        }

        const uint32_t ep_rva = rd32(opt + 16);
        const uintptr_t pref_base = static_cast<uintptr_t>(rd64(opt + 24));
        const uint32_t size_of_image = rd32(opt + 56);
        const uint32_t size_of_headers = rd32(opt + 60);
        const uint32_t num_rvas = rd32(opt + 108);

        // Allocate contiguous RW region inside GuestArena (preferred base first unless forced)
        uintptr_t target_va = 0;
        if (!force_relocate && arena.contains(pref_base, size_of_image)) {
            target_va = arena.virtual_alloc(pref_base, size_of_image,
                                            mem::kProtRead | mem::kProtWrite, true);
        }
        if (!target_va) {
            target_va = arena.virtual_alloc(0, size_of_image,
                                            mem::kProtRead | mem::kProtWrite, true);
        }
        if (!target_va) {
            res.error = "GuestArena out of virtual space for PE image.";
            return res;
        }

        auto* base_ptr = reinterpret_cast<uint8_t*>(target_va);
        std::memset(base_ptr, 0, size_of_image);

        // Copy PE headers
        const size_t hdr_copy = std::min<size_t>({size_of_headers, raw.size(), size_of_image});
        std::memcpy(base_ptr, raw.data(), hdr_copy);

        // Copy sections
        const size_t sec_table_off = pe_off + 24 + opt_size;
        struct SecProt { uint32_t va; uint32_t size; int prot; };
        std::vector<SecProt> sec_prots;
        sec_prots.reserve(num_sections);

        for (uint16_t i = 0; i < num_sections; ++i) {
            const size_t off = sec_table_off + static_cast<size_t>(i) * 40;
            if (off + 40 > raw.size()) break;
            const uint8_t* s = &raw[off];
            const uint32_t vsize = rd32(s + 8);
            const uint32_t vaddr = rd32(s + 12);
            const uint32_t rsize = rd32(s + 16);
            const uint32_t rptr  = rd32(s + 20);
            const uint32_t chars = rd32(s + 36);

            if (rsize > 0 && rptr + rsize <= raw.size() && vaddr + rsize <= size_of_image) {
                std::memcpy(base_ptr + vaddr, raw.data() + rptr, rsize);
            }

            int prot = 0;
            if (chars & 0x40000000u) prot |= mem::kProtRead;  // IMAGE_SCN_MEM_READ
            if (chars & 0x80000000u) prot |= mem::kProtWrite; // IMAGE_SCN_MEM_WRITE
            if (chars & 0x20000000u) prot |= mem::kProtExec;  // IMAGE_SCN_MEM_EXECUTE
            sec_prots.push_back({vaddr, vsize ? vsize : rsize, prot});
        }

        // Helper for DataDirectory[idx] -> (rva, size)
        auto data_dir = [&](uint32_t idx, uint32_t& rva, uint32_t& sz) -> bool {
            if (idx >= num_rvas || 112 + (idx + 1) * 8 > opt_size) return false;
            rva = rd32(opt + 112 + idx * 8);
            sz  = rd32(opt + 112 + idx * 8 + 4);
            return rva != 0 && sz != 0 && (rva + sz) <= size_of_image;
        };

        // 1. Apply Base Relocations (DataDirectory[5]) if mapped away from preferred_base
        const int64_t delta = static_cast<int64_t>(target_va) - static_cast<int64_t>(pref_base);
        uint32_t reloc_rva = 0, reloc_sz = 0;
        if (delta != 0 && data_dir(5, reloc_rva, reloc_sz)) {
            uint32_t cursor = reloc_rva;
            const uint32_t end = reloc_rva + reloc_sz;
            while (cursor + 8 <= end) {
                const uint32_t page_rva = rd32(base_ptr + cursor);
                const uint32_t blk_size = rd32(base_ptr + cursor + 4);
                if (blk_size < 8 || cursor + blk_size > end) break;

                const uint32_t count = (blk_size - 8) / 2;
                for (uint32_t k = 0; k < count; ++k) {
                    const uint16_t entry = rd16(base_ptr + cursor + 8 + k * 2);
                    const uint16_t type = entry >> 12;
                    const uint16_t offset = entry & 0x0FFF;
                    const uint32_t fix_rva = page_rva + offset;
                    if (type == 10 && fix_rva + 8 <= size_of_image) { // IMAGE_REL_BASED_DIR64
                        uint64_t val = 0;
                        std::memcpy(&val, base_ptr + fix_rva, 8);
                        val = static_cast<uint64_t>(static_cast<int64_t>(val) + delta);
                        std::memcpy(base_ptr + fix_rva, &val, 8);
                        ++res.relocations_applied;
                    } else if (type == 3 && fix_rva + 4 <= size_of_image) { // IMAGE_REL_BASED_HIGHLOW
                        uint32_t val = 0;
                        std::memcpy(&val, base_ptr + fix_rva, 4);
                        val = static_cast<uint32_t>(static_cast<int64_t>(val) + delta);
                        std::memcpy(base_ptr + fix_rva, &val, 4);
                        ++res.relocations_applied;
                    }
                }
                cursor += blk_size;
            }
        }

        // 2. Patch Import Address Table (DataDirectory[1]) with Box64 native thunk stubs
        uint32_t imp_rva = 0, imp_sz = 0;
        if (data_dir(1, imp_rva, imp_sz)) {
            for (uint32_t off = imp_rva; off + 20 <= size_of_image; off += 20) {
                const uint32_t orig_thunk = rd32(base_ptr + off + 0);
                const uint32_t name_rva   = rd32(base_ptr + off + 12);
                const uint32_t first_thunk = rd32(base_ptr + off + 16);
                if (name_rva == 0 && first_thunk == 0) break;
                if (name_rva >= size_of_image || first_thunk >= size_of_image) break;

                const std::string dll_name(reinterpret_cast<const char*>(base_ptr + name_rva));
                const std::string dll_key = win32::ModuleRegistry::basename_lower(dll_name);
                // Auto-load dependent BYOF guest DLLs (e.g. oo2core_6_win64.dll, bink2w64.dll) before patching IAT
                if (!bridge.has_dll_thunks(dll_name) &&
                    !bridge.modules().find_module(dll_name) &&
                    active_stack.find(dll_key) == active_stack.end() &&
                    bridge.vfs()) {
                    std::string dep_host;
                    if (bridge.vfs()->resolve(dll_name, dep_host)) {
                        active_stack.insert(dll_key);
                        auto dep = load_pe64_impl(dep_host, arena, bridge, /*force_relocate=*/true, active_stack);
                        if (dep.ok) {
                            if (dep.pdata_va && dep.pdata_size) {
                                bridge.seh().register_image(dep.mapped_base, dep.pdata_va, dep.pdata_size);
                            }
                            for (const auto& sub : dep.dep_dlls) res.dep_dlls.push_back(sub);
                            if (dep.entry_point != dep.mapped_base || dep.tls_dir_va) {
                                res.dep_dlls.push_back({dep.mapped_base, dep.entry_point, dep.tls_dir_va});
                            }
                            bridge.modules().register_guest_module(
                                dll_name, dep.mapped_base, dep.image_size,
                                std::move(dep.exports_by_name), std::move(dep.exports_by_ordinal));
                        }
                    }
                }
                const uint32_t lookup_base = orig_thunk ? orig_thunk : first_thunk;

                for (uint32_t idx = 0; ; ++idx) {
                    const uint32_t l_rva = lookup_base + idx * 8;
                    const uint32_t i_rva = first_thunk + idx * 8;
                    if (l_rva + 8 > size_of_image || i_rva + 8 > size_of_image) break;

                    const uint64_t thunk_val = rd64(base_ptr + l_rva);
                    if (thunk_val == 0) break;

                    std::string sym_name;
                    if (thunk_val & (1ULL << 63)) {
                        sym_name = "#" + std::to_string(thunk_val & 0xFFFFu);
                    } else {
                        const uint32_t ibn_rva = static_cast<uint32_t>(thunk_val & 0xFFFFFFFFu);
                        if (ibn_rva + 2 < size_of_image) {
                            sym_name = reinterpret_cast<const char*>(base_ptr + ibn_rva + 2);
                        }
                    }

                    uintptr_t stub = bridge.resolve_import(dll_name, sym_name);
                    if (stub == 0) {
                        stub = bridge.modules().resolve_guest_export_by_dll(dll_name, sym_name);
                    }
                    if (stub != 0) {
                        uint64_t patched = static_cast<uint64_t>(stub);
                        std::memcpy(base_ptr + i_rva, &patched, 8);
                        ++res.imports_resolved;
                    } else {
                        res.unresolved_imports.push_back(dll_name + "!" + sym_name);
                        // Patch with a safe logging onebridge_t trap instead of leaving an unmapped RVA in IAT
                        if (const uintptr_t trap = bridge.resolve_unresolved_trap(dll_name, sym_name)) {
                            uint64_t patched = static_cast<uint64_t>(trap);
                            std::memcpy(base_ptr + i_rva, &patched, 8);
                        }
                    }
                }
            }
        }

        // 2b. Parse Export Directory (DataDirectory[0]) for guest DLL GetProcAddress resolution
        uint32_t exp_rva = 0, exp_sz = 0;
        if (data_dir(0, exp_rva, exp_sz) && exp_rva + 40 <= size_of_image) {
            const uint8_t* ed = base_ptr + exp_rva;
            const uint32_t ord_base   = rd32(ed + 16);
            const uint32_t num_funcs  = rd32(ed + 20);
            const uint32_t num_names  = rd32(ed + 24);
            const uint32_t funcs_rva  = rd32(ed + 28);
            const uint32_t names_rva  = rd32(ed + 32);
            const uint32_t ords_rva   = rd32(ed + 36);

            auto resolve_export_rva = [&](uint32_t fn_rva) -> uintptr_t {
                if (fn_rva == 0 || fn_rva >= size_of_image) return 0;
                // Forwarded export: RVA falls inside [exp_rva, exp_rva + exp_sz) and names "DLL.Symbol"
                if (fn_rva >= exp_rva && fn_rva < exp_rva + exp_sz) {
                    const std::string fwd(reinterpret_cast<const char*>(base_ptr + fn_rva));
                    const size_t dot = fwd.find('.');
                    if (dot != std::string::npos && dot + 1 < fwd.size()) {
                        const std::string target_dll = fwd.substr(0, dot) + ".dll";
                        const std::string target_sym = fwd.substr(dot + 1);
                        uintptr_t dst = bridge.resolve_import(target_dll, target_sym);
                        if (!dst) dst = bridge.modules().resolve_guest_export_by_dll(target_dll, target_sym);
                        return dst;
                    }
                    return 0;
                }
                return target_va + fn_rva;
            };

            if (funcs_rva && funcs_rva + num_funcs * 4 <= size_of_image) {
                for (uint32_t i = 0; i < num_funcs; ++i) {
                    const uintptr_t addr = resolve_export_rva(rd32(base_ptr + funcs_rva + i * 4));
                    if (addr) {
                        res.exports_by_ordinal[static_cast<uint16_t>(ord_base + i)] = addr;
                    }
                }
                if (names_rva && ords_rva &&
                    names_rva + num_names * 4 <= size_of_image &&
                    ords_rva + num_names * 2 <= size_of_image) {
                    for (uint32_t i = 0; i < num_names; ++i) {
                        const uint32_t sym_rva = rd32(base_ptr + names_rva + i * 4);
                        const uint16_t ord_idx = rd16(base_ptr + ords_rva + i * 2);
                        if (sym_rva < size_of_image && ord_idx < num_funcs) {
                            const uintptr_t addr = resolve_export_rva(rd32(base_ptr + funcs_rva + ord_idx * 4));
                            if (addr) {
                                const std::string sym(reinterpret_cast<const char*>(base_ptr + sym_rva));
                                res.exports_by_name[sym] = addr;
                            }
                        }
                    }
                }
            }
        }

        // 3. Record Exception (.pdata) and TLS directories for Box64 / SEH setup
        uint32_t pdata_rva = 0, pdata_sz = 0;
        if (data_dir(3, pdata_rva, pdata_sz)) {
            res.pdata_va = target_va + pdata_rva;
            res.pdata_size = pdata_sz;
        }
        uint32_t tls_rva = 0, tls_sz = 0;
        if (data_dir(9, tls_rva, tls_sz)) {
            res.tls_dir_va = target_va + tls_rva;
        }

        // 4. Tighten section host memory protections (guest .text becomes PROT_READ)
        for (const auto& sp : sec_prots) {
            if (sp.size > 0 && sp.va + sp.size <= size_of_image) {
                arena.protect(target_va + sp.va, sp.size, sp.prot);
            }
        }

        res.mapped_base = target_va;
        res.preferred_base = pref_base;
        res.entry_point = target_va + ep_rva;
        res.image_size = size_of_image;
        res.ok = true;
        return res;
    }
};

} // namespace mobiro::cpu
