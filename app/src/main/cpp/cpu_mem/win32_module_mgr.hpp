#pragma once

#include "../validator/vfs_mapper.hpp"

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace mobiro::win32 {

// Tracks loaded guest PE64 modules (and their parsed export tables) alongside synthetic
// HMODULE handles for built-in native-thunked Win32 DLLs (LoadLibrary / GetProcAddress).
class ModuleRegistry {
public:
    static constexpr uintptr_t kNativeModuleTag  = 0x7FF000000000ULL;
    static constexpr uintptr_t kNativeModuleMask = 0xFFFF00000000ULL;

    struct GuestModule {
        std::string name_lower;
        uintptr_t base = 0;
        size_t size = 0;
        std::unordered_map<std::string, uintptr_t> exports_by_name;
        std::unordered_map<uint16_t, uintptr_t> exports_by_ordinal;
    };

    static std::string basename_lower(const std::string& path) {
        std::string norm = validator::VfsMapper::normalize(path);
        const size_t slash = norm.find_last_of('/');
        if (slash != std::string::npos) norm = norm.substr(slash + 1);
        return norm;
    }

    static bool is_native_handle(uintptr_t hmod) {
        return (hmod & kNativeModuleMask) == kNativeModuleTag;
    }

    void register_guest_module(const std::string& name,
                               uintptr_t base,
                               size_t size,
                               std::unordered_map<std::string, uintptr_t> by_name,
                               std::unordered_map<uint16_t, uintptr_t> by_ord) {
        const std::string key = basename_lower(name);
        std::lock_guard<std::mutex> lk(mu_);
        GuestModule mod;
        mod.name_lower = key;
        mod.base = base;
        mod.size = size;
        mod.exports_by_name = std::move(by_name);
        mod.exports_by_ordinal = std::move(by_ord);
        guest_by_name_[key] = base;
        guest_by_handle_[base] = std::move(mod);
    }

    uintptr_t get_or_register_native(const std::string& dll_name) {
        const std::string key = basename_lower(dll_name);
        std::lock_guard<std::mutex> lk(mu_);
        auto it = native_by_name_.find(key);
        if (it != native_by_name_.end()) return it->second;
        const uintptr_t h = kNativeModuleTag + (next_native_idx_++ * 0x10000ULL);
        native_by_name_[key] = h;
        native_by_handle_[h] = key;
        return h;
    }

    uintptr_t find_module(const std::string& name) const {
        const std::string key = basename_lower(name);
        std::lock_guard<std::mutex> lk(mu_);
        if (auto it = guest_by_name_.find(key); it != guest_by_name_.end()) return it->second;
        if (auto it = native_by_name_.find(key); it != native_by_name_.end()) return it->second;
        return 0;
    }

    bool native_name_for_handle(uintptr_t hmod, std::string& out_name) const {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = native_by_handle_.find(hmod);
        if (it == native_by_handle_.end()) return false;
        out_name = it->second;
        return true;
    }

    uintptr_t resolve_guest_export(uintptr_t hmod, const char* name_or_ord) const {
        if (!name_or_ord) return 0;
        std::lock_guard<std::mutex> lk(mu_);
        auto it = guest_by_handle_.find(hmod);
        if (it == guest_by_handle_.end()) return 0;

        const uintptr_t raw = reinterpret_cast<uintptr_t>(name_or_ord);
        if (raw < 0x10000ULL) { // IS_INTRESOURCE ordinal lookup
            auto oit = it->second.exports_by_ordinal.find(static_cast<uint16_t>(raw));
            return (oit != it->second.exports_by_ordinal.end()) ? oit->second : 0;
        }
        auto nit = it->second.exports_by_name.find(name_or_ord);
        return (nit != it->second.exports_by_name.end()) ? nit->second : 0;
    }

    uintptr_t resolve_guest_export_by_dll(const std::string& dll_name, const std::string& sym) const {
        const std::string key = basename_lower(dll_name);
        std::lock_guard<std::mutex> lk(mu_);
        auto it = guest_by_name_.find(key);
        if (it == guest_by_name_.end()) return 0;
        auto mit = guest_by_handle_.find(it->second);
        if (mit == guest_by_handle_.end()) return 0;
        if (!sym.empty() && sym[0] == '#') {
            const uint16_t ord = static_cast<uint16_t>(std::stoul(sym.substr(1)));
            auto oit = mit->second.exports_by_ordinal.find(ord);
            return (oit != mit->second.exports_by_ordinal.end()) ? oit->second : 0;
        }
        auto nit = mit->second.exports_by_name.find(sym);
        return (nit != mit->second.exports_by_name.end()) ? nit->second : 0;
    }

    void clear() {
        std::lock_guard<std::mutex> lk(mu_);
        guest_by_name_.clear();
        guest_by_handle_.clear();
        native_by_name_.clear();
        native_by_handle_.clear();
        next_native_idx_ = 1;
    }

private:
    mutable std::mutex mu_;
    uint64_t next_native_idx_ = 1;
    std::unordered_map<std::string, uintptr_t> guest_by_name_;
    std::unordered_map<uintptr_t, GuestModule> guest_by_handle_;
    std::unordered_map<std::string, uintptr_t> native_by_name_;
    std::unordered_map<uintptr_t, std::string> native_by_handle_;
};

} // namespace mobiro::win32
