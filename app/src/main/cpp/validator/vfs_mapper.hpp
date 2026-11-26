#pragma once

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <string>
#include <unordered_map>

namespace mobiro::validator {

// Maps Windows-style case-insensitive relative paths ("Data0.bdt", "movie\\intro.bk2")
// onto exact POSIX paths on Android's case-sensitive ext4/F2FS storage.
class VfsMapper {
public:
    bool index_root(const std::string& root_dir) {
        root_ = std::filesystem::path(root_dir);
        map_.clear();
        std::error_code ec;
        if (!std::filesystem::is_directory(root_, ec)) return false;

        for (auto it = std::filesystem::recursive_directory_iterator(
                 root_, std::filesystem::directory_options::skip_permission_denied, ec);
             it != std::filesystem::recursive_directory_iterator();
             it.increment(ec)) {
            if (ec) {
                ec.clear();
                continue;
            }
            auto rel = std::filesystem::relative(it->path(), root_, ec);
            if (ec) continue;
            map_[normalize(rel.generic_string())] = it->path().string();
        }
        return true;
    }

    // Resolves a Windows or POSIX relative path (or stripped drive path) to host path.
    bool resolve(const std::string& guest_path, std::string& out_host_path) const {
        std::string key = normalize(guest_path);
        // Strip leading "./" or drive prefixes like "c:/sekiro/"
        if (key.size() >= 2 && key[1] == ':') key.erase(0, 2);
        while (!key.empty() && key.front() == '/') key.erase(0, 1);
        if (key.rfind("./", 0) == 0) key.erase(0, 2);

        auto it = map_.find(key);
        if (it == map_.end()) return false;
        out_host_path = it->second;
        return true;
    }

    size_t entry_count() const { return map_.size(); }

    static std::string normalize(std::string p) {
        std::replace(p.begin(), p.end(), '\\', '/');
        std::transform(p.begin(), p.end(), p.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return p;
    }

private:
    std::filesystem::path root_;
    std::unordered_map<std::string, std::string> map_;
};

} // namespace mobiro::validator
