#pragma once

#include <algorithm>
#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <vector>

#if defined(__linux__) || defined(__ANDROID__)
#include <sys/mman.h>
#include <unistd.h>
#elif defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace mobiro::mem {

struct RegionRecord {
    uintptr_t base = 0;
    size_t size = 0;
    int prot = 0;
    bool committed = false;
};

// Portable protection flags (independent of POSIX/Win32 headers)
enum MemProt : int {
    kProtNone  = 0,
    kProtRead  = 1,
    kProtWrite = 2,
    kProtExec  = 4, // Tracked for guest metadata; never granted to host on ARM64
};

// Manages the low-47-bit Win64 virtual address arena on ARM64 Android (mmap)
// and real VirtualAlloc memory on Windows host test builds.
class GuestArena {
public:
    static constexpr uint32_t kGuestPageSize = 4096;
    static constexpr uint32_t kWinAllocGranularity = 65536;
    using ProtSyncFn = void (*)(uintptr_t addr, size_t size, int prot);

    ~GuestArena() { release_all(); }

    void set_prot_sync_hook(ProtSyncFn fn) {
        std::lock_guard<std::mutex> lock(mu_);
        prot_sync_hook_ = fn;
    }

    bool reserve(uintptr_t preferred_base, size_t bytes) {
#if defined(__linux__) || defined(__ANDROID__)
        host_page_ = static_cast<size_t>(sysconf(_SC_PAGESIZE));
        size_ = align_up(bytes, std::max<size_t>(host_page_, kWinAllocGranularity));

        int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE;
#ifdef MAP_FIXED_NOREPLACE
        void* p = mmap(reinterpret_cast<void*>(preferred_base), size_, PROT_NONE,
                       flags | MAP_FIXED_NOREPLACE, -1, 0);
        if (p == MAP_FAILED) {
            p = mmap(reinterpret_cast<void*>(preferred_base), size_, PROT_NONE, flags, -1, 0);
        }
#else
        void* p = mmap(reinterpret_cast<void*>(preferred_base), size_, PROT_NONE, flags, -1, 0);
#endif
        if (p == MAP_FAILED) return false;
        base_ = reinterpret_cast<uintptr_t>(p);
        cursor_ = base_ + std::min<size_t>(size_ / 4, 0x10000000ULL);
        return true;
#elif defined(_WIN32)
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        host_page_ = si.dwPageSize ? si.dwPageSize : 4096;
        size_ = align_up(bytes, kWinAllocGranularity);

        void* p = VirtualAlloc(reinterpret_cast<void*>(preferred_base), size_,
                               MEM_RESERVE, PAGE_NOACCESS);
        if (!p) {
            p = VirtualAlloc(nullptr, size_, MEM_RESERVE, PAGE_NOACCESS);
        }
        if (!p) return false;
        base_ = reinterpret_cast<uintptr_t>(p);
        cursor_ = base_ + std::min<size_t>(size_ / 4, 0x10000000ULL);
        return true;
#else
        (void)preferred_base;
        (void)bytes;
        return false;
#endif
    }

    uintptr_t virtual_alloc(uintptr_t desired_va, size_t len, int prot, bool commit) {
        std::lock_guard<std::mutex> lock(mu_);
        if (base_ == 0 || len == 0) return 0;

        const size_t gran = std::max<size_t>(host_page_, kWinAllocGranularity);
        const size_t aligned_len = align_up(len, gran);
        uintptr_t target = desired_va;
        if (target == 0) {
            target = align_up(cursor_, gran);
            if (target + aligned_len > base_ + size_) return 0;
            cursor_ = target + aligned_len;
        } else {
            target = align_down(target, host_page_);
            if (target < base_ || target + aligned_len > base_ + size_) return 0;
        }

        if (commit && !apply_host_commit(target, aligned_len, prot)) {
            return 0;
        }
        regions_[target] = {target, aligned_len, prot, commit};
        return target;
    }

    bool protect(uintptr_t guest_va, size_t len, int prot) {
        std::lock_guard<std::mutex> lock(mu_);
        if (base_ == 0 || len == 0) return false;
        uintptr_t target = align_down(guest_va, host_page_);
        size_t aligned_len = align_up((guest_va - target) + len, host_page_);
        if (target < base_ || target + aligned_len > base_ + size_) return false;
        return apply_host_protect(target, aligned_len, prot);
    }

    bool virtual_decommit(uintptr_t guest_va, size_t len) {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = regions_.find(align_down(guest_va, host_page_));
        if (it == regions_.end()) return false;

        const size_t span = len ? align_up(len, host_page_) : it->second.size;
#if defined(__linux__) || defined(__ANDROID__)
        madvise(reinterpret_cast<void*>(it->second.base), span, MADV_DONTNEED);
        mprotect(reinterpret_cast<void*>(it->second.base), span, PROT_NONE);
#elif defined(_WIN32)
        VirtualFree(reinterpret_cast<void*>(it->second.base), span, MEM_DECOMMIT);
#endif
        it->second.committed = false;
        if (prot_sync_hook_) prot_sync_hook_(it->second.base, span, kProtNone);
        return true;
    }

    void trim_unused_pages() {
        std::lock_guard<std::mutex> lock(mu_);
#if defined(__linux__) || defined(__ANDROID__)
        for (const auto& [addr, rec] : regions_) {
            if (!rec.committed) {
                madvise(reinterpret_cast<void*>(addr), rec.size, MADV_DONTNEED);
            }
        }
#endif
    }

    void release_all() {
        std::lock_guard<std::mutex> lock(mu_);
        if (base_ != 0 && size_ != 0) {
#if defined(__linux__) || defined(__ANDROID__)
            munmap(reinterpret_cast<void*>(base_), size_);
#elif defined(_WIN32)
            VirtualFree(reinterpret_cast<void*>(base_), 0, MEM_RELEASE);
#endif
        }
        base_ = 0;
        cursor_ = 0;
        size_ = 0;
        regions_.clear();
    }

    uintptr_t base() const { return base_; }
    size_t size() const { return size_; }
    size_t host_page_size() const { return host_page_; }
    bool contains(uintptr_t addr, size_t len = 1) const {
        return base_ != 0 && addr >= base_ && (addr + len) <= (base_ + size_);
    }

    size_t committed_bytes() const {
        std::lock_guard<std::mutex> lock(mu_);
        size_t total = 0;
        for (const auto& [_, r] : regions_) {
            if (r.committed) total += r.size;
        }
        return total;
    }

    static size_t align_up(size_t v, size_t a) { return (v + a - 1) & ~(a - 1); }
    static uintptr_t align_down(uintptr_t v, size_t a) { return v & ~(static_cast<uintptr_t>(a) - 1); }

    static int from_win32_protect(uint32_t win_prot) {
        switch (win_prot & 0xFF) {
            case 0x01: return kProtNone;                    // PAGE_NOACCESS
            case 0x02: return kProtRead;                    // PAGE_READONLY
            case 0x04: return kProtRead | kProtWrite;       // PAGE_READWRITE
            case 0x20: return kProtRead | kProtExec;        // PAGE_EXECUTE_READ
            case 0x40: return kProtRead | kProtWrite | kProtExec; // PAGE_EXECUTE_READWRITE
            default:   return kProtRead | kProtWrite;
        }
    }

private:
    bool apply_host_commit(uintptr_t target, size_t aligned_len, int prot) {
#if defined(__linux__) || defined(__ANDROID__)
        return apply_host_protect(target, aligned_len, prot);
#elif defined(_WIN32)
        DWORD wprot = to_win32_host_prot(prot);
        return VirtualAlloc(reinterpret_cast<void*>(target), aligned_len, MEM_COMMIT, wprot) != nullptr;
#else
        (void)target; (void)aligned_len; (void)prot;
        return false;
#endif
    }

    bool apply_host_protect(uintptr_t target, size_t aligned_len, int prot) {
#if defined(__linux__) || defined(__ANDROID__)
        // Guest x86_64 code pages are NEVER host-executable on ARM64; strip EXEC for host mprotect,
        // while forwarding the full guest prot (including kProtExec) to Box64's memprot table.
        int p = PROT_NONE;
        if (prot & kProtRead)  p |= PROT_READ;
        if (prot & kProtWrite) p |= PROT_WRITE;
        if (mprotect(reinterpret_cast<void*>(target), aligned_len, p) != 0) return false;
        if (prot_sync_hook_) prot_sync_hook_(target, aligned_len, prot);
        return true;
#elif defined(_WIN32)
        DWORD old_prot = 0;
        if (VirtualProtect(reinterpret_cast<void*>(target), aligned_len,
                           to_win32_host_prot(prot), &old_prot) == 0) return false;
        if (prot_sync_hook_) prot_sync_hook_(target, aligned_len, prot);
        return true;
#else
        (void)target; (void)aligned_len; (void)prot;
        return false;
#endif
    }

#if defined(_WIN32)
    static DWORD to_win32_host_prot(int prot) {
        if (prot & kProtWrite) return PAGE_READWRITE;
        if (prot & kProtRead)  return PAGE_READONLY;
        return PAGE_NOACCESS;
    }
#endif

    mutable std::mutex mu_;
    uintptr_t base_ = 0;
    uintptr_t cursor_ = 0;
    size_t size_ = 0;
    size_t host_page_ = 4096;
    ProtSyncFn prot_sync_hook_ = nullptr;
    std::unordered_map<uintptr_t, RegionRecord> regions_;
};

} // namespace mobiro::mem
