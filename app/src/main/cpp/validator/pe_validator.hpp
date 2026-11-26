#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace mobiro::validator {

struct PeValidationResult {
    bool ok = false;
    std::string error;
    uint64_t preferred_image_base = 0;
    uint32_t size_of_image = 0;
    uint32_t entry_point_rva = 0;
    std::vector<std::string> imported_dlls;
    std::string build_fingerprint; // FNV-1a/SHA-like 64-bit hex of COFF+Optional headers
};

namespace detail {
inline uint16_t rd16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}
inline uint32_t rd32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}
inline uint64_t rd64(const uint8_t* p) {
    return static_cast<uint64_t>(rd32(p)) | (static_cast<uint64_t>(rd32(p + 4)) << 32);
}

struct SectionSpan {
    uint32_t virtual_addr = 0;
    uint32_t virtual_size = 0;
    uint32_t raw_ptr = 0;
    uint32_t raw_size = 0;
};

inline bool rva_to_offset(uint32_t rva, const std::vector<SectionSpan>& secs, uint32_t& out) {
    for (const auto& s : secs) {
        uint32_t span = s.virtual_size ? s.virtual_size : s.raw_size;
        if (rva >= s.virtual_addr && rva < s.virtual_addr + span) {
            uint32_t delta = rva - s.virtual_addr;
            if (delta < s.raw_size) {
                out = s.raw_ptr + delta;
                return true;
            }
        }
    }
    return false;
}

inline std::string hash_header_bytes(const uint8_t* data, size_t len) {
    // Clean-room cache fingerprint (FNV-1a 128-bit split) for invalidating stale JIT/DXVK caches
    uint64_t h1 = 0xcbf29ce484222325ULL;
    uint64_t h2 = 0xaf63dc4c8601ec8cULL;
    for (size_t i = 0; i < len; ++i) {
        h1 ^= data[i];
        h1 *= 0x100000001b3ULL;
        h2 ^= static_cast<uint64_t>(data[i]) + (i & 0xFF);
        h2 *= 0x100000001b3ULL;
    }
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(16) << h1 << std::setw(16) << h2;
    return oss.str();
}
} // namespace detail

// Validates a user-provided Win64 PE32+ executable cleanly without bundling any game data.
inline PeValidationResult validate_pe64(const std::string& exe_path) {
    PeValidationResult res;
    std::ifstream f(exe_path, std::ios::binary | std::ios::ate);
    if (!f) {
        res.error = "Unable to open executable: " + exe_path;
        return res;
    }
    const auto file_size = static_cast<size_t>(f.tellg());
    if (file_size < 0x200) {
        res.error = "File too small to be a valid PE32+ executable.";
        return res;
    }

    const size_t hdr_read = std::min<size_t>(file_size, 16384);
    std::vector<uint8_t> hdr(hdr_read);
    f.seekg(0);
    f.read(reinterpret_cast<char*>(hdr.data()), static_cast<std::streamsize>(hdr_read));

    if (hdr[0] != 'M' || hdr[1] != 'Z') {
        res.error = "Missing DOS MZ header.";
        return res;
    }

    const uint32_t pe_off = detail::rd32(&hdr[0x3C]);
    if (pe_off + 0x108 > hdr.size()) {
        res.error = "PE header offset out of bounds.";
        return res;
    }
    if (hdr[pe_off] != 'P' || hdr[pe_off + 1] != 'E' ||
        hdr[pe_off + 2] != 0 || hdr[pe_off + 3] != 0) {
        res.error = "Missing PE\\0\\0 signature.";
        return res;
    }

    const uint8_t* coff = &hdr[pe_off + 4];
    const uint16_t machine = detail::rd16(coff + 0);
    const uint16_t num_sections = detail::rd16(coff + 2);
    const uint16_t opt_size = detail::rd16(coff + 16);
    if (machine != 0x8664) {
        res.error = "Unsupported architecture (expected x86_64 / 0x8664).";
        return res;
    }

    const uint8_t* opt = coff + 20;
    if (opt_size < 0x78 || pe_off + 24 + opt_size > hdr.size()) {
        res.error = "Truncated PE Optional Header.";
        return res;
    }
    const uint16_t opt_magic = detail::rd16(opt + 0);
    if (opt_magic != 0x020B) {
        res.error = "Expected PE32+ (64-bit) magic 0x020B.";
        return res;
    }

    res.entry_point_rva = detail::rd32(opt + 16);
    res.preferred_image_base = detail::rd64(opt + 24);
    res.size_of_image = detail::rd32(opt + 56);
    const uint32_t num_rvas = detail::rd32(opt + 108);

    // Parse section table to locate Import Directory names
    const size_t sec_table_off = pe_off + 24 + opt_size;
    std::vector<detail::SectionSpan> sections;
    if (sec_table_off + static_cast<size_t>(num_sections) * 40 <= hdr.size()) {
        sections.reserve(num_sections);
        for (uint16_t i = 0; i < num_sections; ++i) {
            const uint8_t* s = &hdr[sec_table_off + i * 40];
            sections.push_back({
                detail::rd32(s + 12),
                detail::rd32(s + 8),
                detail::rd32(s + 20),
                detail::rd32(s + 16)
            });
        }
    }

    // Import Directory is DataDirectory[1] (offset 112 + 8 in PE32+ optional header)
    if (num_rvas > 1 && opt_size >= 128) {
        const uint32_t imp_rva = detail::rd32(opt + 120);
        uint32_t imp_off = 0;
        if (imp_rva != 0 && detail::rva_to_offset(imp_rva, sections, imp_off)) {
            for (size_t idx = 0; idx < 64; ++idx) {
                const uint32_t desc_off = imp_off + static_cast<uint32_t>(idx * 20);
                if (desc_off + 20 > file_size) break;
                uint8_t desc[20];
                f.seekg(desc_off);
                f.read(reinterpret_cast<char*>(desc), 20);
                const uint32_t name_rva = detail::rd32(desc + 12);
                const uint32_t first_thunk = detail::rd32(desc + 16);
                if (name_rva == 0 && first_thunk == 0) break;

                uint32_t name_off = 0;
                if (detail::rva_to_offset(name_rva, sections, name_off) && name_off < file_size) {
                    f.seekg(name_off);
                    std::string dll;
                    std::getline(f, dll, '\0');
                    if (!dll.empty() && dll.size() < 128) {
                        res.imported_dlls.push_back(std::move(dll));
                    }
                }
            }
        }
    }

    res.build_fingerprint = detail::hash_header_bytes(
        coff, std::min<size_t>(20 + opt_size, hdr.size() - (pe_off + 4)));
    res.ok = true;
    return res;
}

} // namespace mobiro::validator
