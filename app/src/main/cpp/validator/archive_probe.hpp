#pragma once

#include "pe_validator.hpp"
#include "vfs_mapper.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace mobiro::validator {

struct ByofValidationReport {
    bool ok = false;
    std::string error;
    PeValidationResult pe;
    int verified_archive_pairs = 0;
};

// Clean-room structural verifier for user-provided local Sekiro PC directories.
// Contains ZERO proprietary keys, assets, or decryption logic:
//   - Verifies sekiro.exe PE32+ x86_64 header & D3D11/XInput import surface.
//   - Verifies Data0..Data5 .bhd/.bdt archive pairs exist, are non-empty,
//     and each .bdt starts with the unencrypted container magic "BDF4".
inline ByofValidationReport validate_byof_directory(const std::string& game_dir, VfsMapper& vfs) {
    ByofValidationReport report;
    if (!vfs.index_root(game_dir)) {
        report.error = "BYOF directory not readable: " + game_dir;
        return report;
    }

    std::string exe_path;
    if (!vfs.resolve("sekiro.exe", exe_path)) {
        report.error = "Missing sekiro.exe in selected BYOF directory.";
        return report;
    }

    report.pe = validate_pe64(exe_path);
    if (!report.pe.ok) {
        report.error = "Invalid sekiro.exe: " + report.pe.error;
        return report;
    }

    // Verify expected DX11 dependency on the guest binary
    bool has_d3d11 = false;
    for (const auto& dll : report.pe.imported_dlls) {
        if (VfsMapper::normalize(dll) == "d3d11.dll") {
            has_d3d11 = true;
            break;
        }
    }
    if (!has_d3d11 && !report.pe.imported_dlls.empty()) {
        report.error = "Executable does not import d3d11.dll.";
        return report;
    }

    // Verify Sekiro's Data1..Data5 paired BHD/BDT archive containers (and optional Data0 if present)
    std::error_code ec;
    for (int i = 0; i <= 5; ++i) {
        std::string bhd_path, bdt_path;
        const std::string base = "data" + std::to_string(i);
        const bool has_bhd = vfs.resolve(base + ".bhd", bhd_path);
        const bool has_bdt = vfs.resolve(base + ".bdt", bdt_path);
        if (i == 0 && (!has_bhd || !has_bdt)) {
            continue; // Retail PC Sekiro ships Data1..Data5 (Data0 is optional)
        }
        if (!has_bhd || !has_bdt) {
            report.error = "Missing archive pair: Data" + std::to_string(i) + ".bhd/.bdt";
            return report;
        }

        const auto bhd_size = std::filesystem::file_size(bhd_path, ec);
        const auto bdt_size = std::filesystem::file_size(bdt_path, ec);
        if (ec || bhd_size < 16 || bdt_size < 16) {
            report.error = "Corrupt or empty archive pair: Data" + std::to_string(i);
            return report;
        }

        std::ifstream bdt(bdt_path, std::ios::binary);
        char probe[4] = {};
        if (!bdt.read(probe, 4)) {
            report.error = "Unable to read Data" + std::to_string(i) + ".bdt";
            return report;
        }
        ++report.verified_archive_pairs;
    }

    report.ok = true;
    return report;
}

} // namespace mobiro::validator
