#pragma once

#include "../validator/vfs_mapper.hpp"

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>

namespace mobiro::win32 {

// Binary-compatible Win64 OVERLAPPED prefix used by ReadFile for random-access .bdt reads
struct Win64Overlapped {
    uint64_t internal = 0;
    uint64_t internal_high = 0;
    uint32_t offset = 0;
    uint32_t offset_high = 0;
    uint64_t event_handle = 0;
};

// Minimal UTF-16LE -> UTF-8 converter (ASCII + BMP) for Win32 *W APIs
inline std::string utf16le_to_utf8(const uint16_t* wstr) {
    if (!wstr) return {};
    std::string out;
    for (size_t i = 0; wstr[i] != 0 && i < 4096; ++i) {
        uint16_t c = wstr[i];
        if (c < 0x80) {
            out.push_back(static_cast<char>(c));
        } else if (c < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (c >> 6)));
            out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xE0 | (c >> 12)));
            out.push_back(static_cast<char>(0x80 | ((c >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (c & 0x3F)));
        }
    }
    return out;
}

// VFS-backed Win32 file handle table for streaming Data0..Data5 .bhd/.bdt archives
// without pinning multi-GB files into resident RAM.
class FileHandleTable {
public:
    static constexpr uint64_t kInvalidHandle = ~0ULL;

    ~FileHandleTable() { close_all(); }

    uint64_t open_read(const validator::VfsMapper* vfs, const std::string& guest_path) {
        if (!vfs) return kInvalidHandle;
        std::string host_path;
        if (!vfs->resolve(guest_path, host_path)) return kInvalidHandle;

        FILE* fp = std::fopen(host_path.c_str(), "rb");
        if (!fp) return kInvalidHandle;

        std::lock_guard<std::mutex> lock(mu_);
        const uint64_t handle = next_handle_++;
        files_[handle] = fp;
        return handle;
    }

    uint64_t open_write(validator::VfsMapper* vfs, const std::string& guest_path, bool truncate) {
        if (!vfs) return kInvalidHandle;
        std::string host_path;
        if (!vfs->resolve_for_write(guest_path, host_path)) return kInvalidHandle;

        const char* mode = truncate ? "w+b" : "r+b";
        FILE* fp = std::fopen(host_path.c_str(), mode);
        if (!fp && !truncate) {
            fp = std::fopen(host_path.c_str(), "w+b");
        }
        if (!fp) return kInvalidHandle;

        std::lock_guard<std::mutex> lock(mu_);
        const uint64_t handle = next_handle_++;
        files_[handle] = fp;
        return handle;
    }

    bool write_file(uint64_t handle, const void* src, uint32_t to_write,
                    uint32_t* out_written, const Win64Overlapped* ov) {
        if (out_written) *out_written = 0;
        if (!src && to_write > 0) return false;

        std::lock_guard<std::mutex> lock(mu_);
        auto it = files_.find(handle);
        if (it == files_.end() || !it->second) return false;
        FILE* fp = it->second;

        if (ov) {
            const int64_t off = static_cast<int64_t>(
                static_cast<uint64_t>(ov->offset) | (static_cast<uint64_t>(ov->offset_high) << 32));
            if (seek64(fp, off, SEEK_SET) != 0) return false;
        }
        const size_t n = std::fwrite(src, 1, to_write, fp);
        if (out_written) *out_written = static_cast<uint32_t>(n);
        return n == to_write;
    }

    bool flush_file(uint64_t handle) {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = files_.find(handle);
        if (it == files_.end() || !it->second) return false;
        return std::fflush(it->second) == 0;
    }

    bool read_file(uint64_t handle, void* dst, uint32_t to_read,
                   uint32_t* out_read, const Win64Overlapped* ov) {
        if (out_read) *out_read = 0;
        if (!dst && to_read > 0) return false;

        std::lock_guard<std::mutex> lock(mu_);
        auto it = files_.find(handle);
        if (it == files_.end() || !it->second) return false;
        FILE* fp = it->second;

        if (ov) {
            const int64_t off = static_cast<int64_t>(
                static_cast<uint64_t>(ov->offset) | (static_cast<uint64_t>(ov->offset_high) << 32));
            if (seek64(fp, off, SEEK_SET) != 0) return false;
        }
        const size_t n = std::fread(dst, 1, to_read, fp);
        if (out_read) *out_read = static_cast<uint32_t>(n);
        return (n == to_read) || (std::ferror(fp) == 0);
    }

    bool seek_file(uint64_t handle, int64_t distance, uint32_t move_method, int64_t* new_pos) {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = files_.find(handle);
        if (it == files_.end() || !it->second) return false;
        int origin = SEEK_SET;
        if (move_method == 1) origin = SEEK_CUR;
        else if (move_method == 2) origin = SEEK_END;
        if (seek64(it->second, distance, origin) != 0) return false;
        if (new_pos) *new_pos = tell64(it->second);
        return true;
    }

    bool get_file_size(uint64_t handle, int64_t* out_size) {
        if (!out_size) return false;
        std::lock_guard<std::mutex> lock(mu_);
        auto it = files_.find(handle);
        if (it == files_.end() || !it->second) return false;
        FILE* fp = it->second;
        const int64_t cur = tell64(fp);
        if (seek64(fp, 0, SEEK_END) != 0) return false;
        *out_size = tell64(fp);
        seek64(fp, cur, SEEK_SET);
        return *out_size >= 0;
    }

    bool close_handle(uint64_t handle) {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = files_.find(handle);
        if (it == files_.end()) return false;
        if (it->second) std::fclose(it->second);
        files_.erase(it);
        return true;
    }

    void close_all() {
        std::lock_guard<std::mutex> lock(mu_);
        for (auto& [_, fp] : files_) {
            if (fp) std::fclose(fp);
        }
        files_.clear();
    }

private:
    static int seek64(FILE* fp, int64_t off, int origin) {
#if defined(_WIN32)
        return _fseeki64(fp, off, origin);
#else
        return fseeko(fp, static_cast<off_t>(off), origin);
#endif
    }
    static int64_t tell64(FILE* fp) {
#if defined(_WIN32)
        return _ftelli64(fp);
#else
        return static_cast<int64_t>(ftello(fp));
#endif
    }

    std::mutex mu_;
    uint64_t next_handle_ = 0x100;
    std::unordered_map<uint64_t, FILE*> files_;
};

// Maps guest SRWLOCK pointers (8 bytes in guest memory) to native C++ shared_mutexes
class SrwLockTable {
public:
    ~SrwLockTable() { clear(); }

    void acquire_exclusive(uintptr_t guest_srw) { get_or_create(guest_srw)->lock(); }
    void release_exclusive(uintptr_t guest_srw) { get_or_create(guest_srw)->unlock(); }
    void acquire_shared(uintptr_t guest_srw)    { get_or_create(guest_srw)->lock_shared(); }
    void release_shared(uintptr_t guest_srw)    { get_or_create(guest_srw)->unlock_shared(); }

    void clear() {
        std::lock_guard<std::mutex> lock(mu_);
        for (auto& [_, m] : locks_) delete m;
        locks_.clear();
    }

private:
    std::shared_mutex* get_or_create(uintptr_t key) {
        std::lock_guard<std::mutex> lock(mu_);
        auto& ptr = locks_[key];
        if (!ptr) ptr = new std::shared_mutex();
        return ptr;
    }

    std::mutex mu_;
    std::unordered_map<uintptr_t, std::shared_mutex*> locks_;
};

} // namespace mobiro::win32
