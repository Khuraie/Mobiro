#pragma once

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <mutex>
#include <string>
#include <unordered_map>

namespace mobiro::validator {

// Maps Windows-style case-insensitive relative paths ("Data0.bdt", "AppData\\Roaming\\Sekiro\\S0000.sl2")
// onto exact POSIX paths on Android's case-sensitive ext4/F2FS storage.
// Supports a writable copy-on-write overlay root so save games & configs never mutate the read-only BYOF dir.
class VfsMapper {
public:
    bool index_root(const std::string& root_dir) {
        std::lock_guard<std::mutex> lock(mu_);
        root_ = std::filesystem::path(root_dir);
        map_.clear();
        std::error_code ec;
        if (!std::filesystem::is_directory(root_, ec)) return false;

        for (auto it = std::filesystem::recursive_directory_iterator(
                 root_, std::filesystem::directory_options::skip_permission_denied, ec);
             it != std::filesystem::recursive_directory_iterator();
             it.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            auto rel = std::filesystem::relative(it->path(), root_, ec);
            if (ec) continue;
            map_[normalize(rel.generic_string())] = it->path().string();
        }
        return true;
    }

    bool set_write_overlay(const std::string& overlay_dir) {
        std::lock_guard<std::mutex> lock(mu_);
        overlay_root_ = std::filesystem::path(overlay_dir);
        overlay_map_.clear();
        std::error_code ec;
        std::filesystem::create_directories(overlay_root_, ec);
        if (ec) return false;

        for (auto it = std::filesystem::recursive_directory_iterator(
                 overlay_root_, std::filesystem::directory_options::skip_permission_denied, ec);
             it != std::filesystem::recursive_directory_iterator();
             it.increment(ec)) {
            if (ec) { ec.clear(); continue; }
            auto rel = std::filesystem::relative(it->path(), overlay_root_, ec);
            if (ec) continue;
            overlay_map_[normalize(rel.generic_string())] = it->path().string();
        }
        return true;
    }

    // Read lookup checks writable overlay first (copy-on-write), then read-only BYOF directory.
    bool resolve(const std::string& guest_path, std::string& out_host_path) const {
        const std::string key = strip_prefix(normalize(guest_path));
        std::lock_guard<std::mutex> lock(mu_);
        if (auto oit = overlay_map_.find(key); oit != overlay_map_.end()) {
            std::error_code ec;
            if (std::filesystem::exists(oit->second, ec)) {
                out_host_path = oit->second;
                return true;
            }
        }
        if (!overlay_root_.empty() && !key.empty() && key.find("..") == std::string::npos) {
            const auto direct = overlay_root_ / std::filesystem::path(key);
            std::error_code ec;
            if (std::filesystem::exists(direct, ec)) {
                out_host_path = direct.string();
                return true;
            }
        }
        if (auto it = map_.find(key); it != map_.end()) {
            out_host_path = it->second;
            return true;
        }
        return false;
    }

    void erase_overlay_entry(const std::string& guest_path) {
        const std::string key = strip_prefix(normalize(guest_path));
        std::lock_guard<std::mutex> lock(mu_);
        overlay_map_.erase(key);
    }

    // Resolves a target path inside the writable overlay directory (creating parent dirs).
    bool resolve_for_write(const std::string& guest_path, std::string& out_host_path) {
        const std::string key = strip_prefix(normalize(guest_path));
        if (key.empty() || key.find("..") != std::string::npos) return false; // Path traversal guard

        std::lock_guard<std::mutex> lock(mu_);
        if (overlay_root_.empty()) return false;

        const std::filesystem::path target = overlay_root_ / std::filesystem::path(key);
        std::error_code ec;
        std::filesystem::create_directories(target.parent_path(), ec);
        if (ec) return false;

        out_host_path = target.string();
        overlay_map_[key] = out_host_path;
        return true;
    }

    size_t entry_count() const {
        std::lock_guard<std::mutex> lock(mu_);
        return map_.size();
    }

    static std::string normalize(std::string p) {
        std::replace(p.begin(), p.end(), '\\', '/');
        std::transform(p.begin(), p.end(), p.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return p;
    }

private:
    static std::string strip_prefix(std::string key) {
        if (key.rfind("//?/", 0) == 0 || key.rfind("//./", 0) == 0) key.erase(0, 4);
        if (key.size() >= 2 && key[1] == ':') key.erase(0, 2);
        while (!key.empty() && key.front() == '/') key.erase(0, 1);
        if (key.rfind("./", 0) == 0) key.erase(0, 2);
        // Strip canonical virtual game-root prefix returned by GetModuleFileName/GetCurrentDirectory
        if (key.rfind("sekiro/", 0) == 0) key.erase(0, 7);
        return key;
    }

    mutable std::mutex mu_;
    std::filesystem::path root_;
    std::filesystem::path overlay_root_;
    std::unordered_map<std::string, std::string> map_;
    std::unordered_map<std::string, std::string> overlay_map_;
};

} // namespace mobiro::validator
