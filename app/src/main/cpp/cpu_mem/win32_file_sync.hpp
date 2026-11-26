#pragma once

#include "../validator/vfs_mapper.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
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

// VFS-backed Win32 file handle table with per-file I/O locking so concurrent reads across
// Data0..Data5 .bdt archives and saves stream in parallel without blocking a global table mutex.
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

        auto entry = std::make_shared<OpenFile>(fp);
        std::lock_guard<std::mutex> lock(mu_);
        const uint64_t handle = next_handle_++;
        files_[handle] = std::move(entry);
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

        auto entry = std::make_shared<OpenFile>(fp);
        std::lock_guard<std::mutex> lock(mu_);
        const uint64_t handle = next_handle_++;
        files_[handle] = std::move(entry);
        return handle;
    }

    bool write_file(uint64_t handle, const void* src, uint32_t to_write,
                    uint32_t* out_written, const Win64Overlapped* ov) {
        if (out_written) *out_written = 0;
        if (!src && to_write > 0) return false;
        auto f = find(handle);
        if (!f) return false;

        std::lock_guard<std::mutex> io(f->io_mu);
        if (!f->fp) return false;
        if (ov) {
            const int64_t off = static_cast<int64_t>(
                static_cast<uint64_t>(ov->offset) | (static_cast<uint64_t>(ov->offset_high) << 32));
            if (seek64(f->fp, off, SEEK_SET) != 0) return false;
        }
        const size_t n = std::fwrite(src, 1, to_write, f->fp);
        if (out_written) *out_written = static_cast<uint32_t>(n);
        return n == to_write;
    }

    bool flush_file(uint64_t handle) {
        auto f = find(handle);
        if (!f) return false;
        std::lock_guard<std::mutex> io(f->io_mu);
        return f->fp && (std::fflush(f->fp) == 0);
    }

    bool read_file(uint64_t handle, void* dst, uint32_t to_read,
                   uint32_t* out_read, const Win64Overlapped* ov) {
        if (out_read) *out_read = 0;
        if (!dst && to_read > 0) return false;
        auto f = find(handle);
        if (!f) return false;

        std::lock_guard<std::mutex> io(f->io_mu);
        if (!f->fp) return false;
        if (ov) {
            const int64_t off = static_cast<int64_t>(
                static_cast<uint64_t>(ov->offset) | (static_cast<uint64_t>(ov->offset_high) << 32));
            if (seek64(f->fp, off, SEEK_SET) != 0) return false;
        }
        const size_t n = std::fread(dst, 1, to_read, f->fp);
        if (out_read) *out_read = static_cast<uint32_t>(n);
        return (n == to_read) || (std::ferror(f->fp) == 0);
    }

    bool seek_file(uint64_t handle, int64_t distance, uint32_t move_method, int64_t* new_pos) {
        auto f = find(handle);
        if (!f) return false;
        std::lock_guard<std::mutex> io(f->io_mu);
        if (!f->fp) return false;
        int origin = SEEK_SET;
        if (move_method == 1) origin = SEEK_CUR;
        else if (move_method == 2) origin = SEEK_END;
        if (seek64(f->fp, distance, origin) != 0) return false;
        if (new_pos) *new_pos = tell64(f->fp);
        return true;
    }

    bool get_file_size(uint64_t handle, int64_t* out_size) {
        if (!out_size) return false;
        auto f = find(handle);
        if (!f) return false;
        std::lock_guard<std::mutex> io(f->io_mu);
        if (!f->fp) return false;
        const int64_t cur = tell64(f->fp);
        if (seek64(f->fp, 0, SEEK_END) != 0) return false;
        *out_size = tell64(f->fp);
        seek64(f->fp, cur, SEEK_SET);
        return *out_size >= 0;
    }

    bool close_handle(uint64_t handle) {
        std::shared_ptr<OpenFile> f;
        {
            std::lock_guard<std::mutex> lock(mu_);
            auto it = files_.find(handle);
            if (it == files_.end()) return false;
            f = std::move(it->second);
            files_.erase(it);
        }
        if (f) {
            std::lock_guard<std::mutex> io(f->io_mu);
            if (f->fp) {
                std::fclose(f->fp);
                f->fp = nullptr;
            }
        }
        return true;
    }

    void close_all() {
        std::unordered_map<uint64_t, std::shared_ptr<OpenFile>> copy;
        {
            std::lock_guard<std::mutex> lock(mu_);
            copy.swap(files_);
        }
        for (auto& [_, f] : copy) {
            if (f) {
                std::lock_guard<std::mutex> io(f->io_mu);
                if (f->fp) {
                    std::fclose(f->fp);
                    f->fp = nullptr;
                }
            }
        }
    }

private:
    struct OpenFile {
        explicit OpenFile(FILE* f) : fp(f) {}
        ~OpenFile() { if (fp) std::fclose(fp); }
        std::mutex io_mu;
        FILE* fp = nullptr;
    };

    std::shared_ptr<OpenFile> find(uint64_t handle) {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = files_.find(handle);
        return (it != files_.end()) ? it->second : nullptr;
    }

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
    std::unordered_map<uint64_t, std::shared_ptr<OpenFile>> files_;
};

// 64-shard cache-line-aligned concurrent map with reader-lock fast path for high-frequency
// Win32 synchronization primitives (SRWLOCK, CRITICAL_SECTION, CONDITION_VARIABLE).
template <typename T, size_t Shards = 64>
class ShardedObjectMap {
public:
    ~ShardedObjectMap() { clear(); }

    T* get_or_create(uintptr_t key) {
        auto& s = shard(key);
        {
            std::shared_lock<std::shared_mutex> rlk(s.mu);
            auto it = s.map.find(key);
            if (it != s.map.end()) return it->second;
        }
        std::unique_lock<std::shared_mutex> wlk(s.mu);
        auto& ptr = s.map[key];
        if (!ptr) ptr = new T();
        return ptr;
    }

    void destroy(uintptr_t key) {
        auto& s = shard(key);
        std::unique_lock<std::shared_mutex> wlk(s.mu);
        auto it = s.map.find(key);
        if (it != s.map.end()) {
            delete it->second;
            s.map.erase(it);
        }
    }

    void clear() {
        for (auto& s : shards_) {
            std::unique_lock<std::shared_mutex> wlk(s.mu);
            for (auto& [_, v] : s.map) delete v;
            s.map.clear();
        }
    }

private:
    struct alignas(64) Shard {
        std::shared_mutex mu;
        std::unordered_map<uintptr_t, T*> map;
    };

    Shard& shard(uintptr_t key) noexcept {
        return shards_[((key >> 3) ^ (key >> 11)) & (Shards - 1)];
    }

    std::array<Shard, Shards> shards_;
};

// Maps guest SRWLOCK pointers (8 bytes in guest memory) to native C++ shared_mutexes
class SrwLockTable {
public:
    void acquire_exclusive(uintptr_t guest_srw) { map_.get_or_create(guest_srw)->lock(); }
    void release_exclusive(uintptr_t guest_srw) { map_.get_or_create(guest_srw)->unlock(); }
    void acquire_shared(uintptr_t guest_srw)    { map_.get_or_create(guest_srw)->lock_shared(); }
    void release_shared(uintptr_t guest_srw)    { map_.get_or_create(guest_srw)->unlock_shared(); }
    std::shared_mutex* native_lock(uintptr_t guest_srw) { return map_.get_or_create(guest_srw); }
    void clear() { map_.clear(); }

private:
    ShardedObjectMap<std::shared_mutex> map_;
};

// Maps guest CRITICAL_SECTION* addresses to native recursive mutexes (MSVC CRT / FromSoft engine locks)
class CriticalSectionTable {
public:
    void initialize(uintptr_t cs) { if (cs) (void)map_.get_or_create(cs); }
    void enter(uintptr_t cs)      { if (cs) map_.get_or_create(cs)->lock(); }
    bool try_enter(uintptr_t cs)  { return cs && map_.get_or_create(cs)->try_lock(); }
    void leave(uintptr_t cs)      { if (cs) map_.get_or_create(cs)->unlock(); }
    std::recursive_mutex* native_lock(uintptr_t cs) { return cs ? map_.get_or_create(cs) : nullptr; }
    void destroy(uintptr_t cs)    { if (cs) map_.destroy(cs); }
    void clear()                  { map_.clear(); }

private:
    ShardedObjectMap<std::recursive_mutex> map_;
};

// Maps guest CONDITION_VARIABLE* addresses to condition_variable_any (supports both SRWLOCK & CRITICAL_SECTION)
class ConditionVariableTable {
public:
    void wake_one(uintptr_t cv) {
        if (cv) map_.get_or_create(cv)->notify_one();
    }
    void wake_all(uintptr_t cv) {
        if (cv) map_.get_or_create(cv)->notify_all();
    }

    bool sleep_srw(uintptr_t cv, SrwLockTable& srws, uintptr_t srw, uint32_t timeout_ms, bool shared) {
        if (!cv || !srw) return false;
        auto* c = map_.get_or_create(cv);
        auto* m = srws.native_lock(srw);
        if (!c || !m) return false;
        if (shared) {
            std::shared_lock<std::shared_mutex> lk(*m, std::adopt_lock);
            bool ok = true;
            if (timeout_ms == 0xFFFFFFFFu) { c->wait(lk); }
            else { ok = (c->wait_for(lk, std::chrono::milliseconds(timeout_ms)) == std::cv_status::no_timeout); }
            lk.release();
            return ok;
        }
        std::unique_lock<std::shared_mutex> lk(*m, std::adopt_lock);
        bool ok = true;
        if (timeout_ms == 0xFFFFFFFFu) { c->wait(lk); }
        else { ok = (c->wait_for(lk, std::chrono::milliseconds(timeout_ms)) == std::cv_status::no_timeout); }
        lk.release();
        return ok;
    }

    bool sleep_cs(uintptr_t cv, CriticalSectionTable& css, uintptr_t cs, uint32_t timeout_ms) {
        if (!cv || !cs) return false;
        auto* c = map_.get_or_create(cv);
        auto* m = css.native_lock(cs);
        if (!c || !m) return false;
        std::unique_lock<std::recursive_mutex> lk(*m, std::adopt_lock);
        bool ok = true;
        if (timeout_ms == 0xFFFFFFFFu) { c->wait(lk); }
        else { ok = (c->wait_for(lk, std::chrono::milliseconds(timeout_ms)) == std::cv_status::no_timeout); }
        lk.release();
        return ok;
    }

    void clear() { map_.clear(); }

private:
    ShardedObjectMap<std::condition_variable_any> map_;
};

} // namespace mobiro::win32
