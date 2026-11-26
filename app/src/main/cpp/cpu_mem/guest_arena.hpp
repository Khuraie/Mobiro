#pragma once

#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <vector>

#if defined(__linux__) || defined(__ANDROID__)
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace mobiro::mem {

struct RegionRecord {
    uintptr_t base = 0;
    size_t size = 0;
    int prot = 0;
    bool committed = false;
};

// Manages the low-47-bit Win64 virtual address arena on ARM64 Android.
// Handles 4KB guest vs 16KB host page alignment and returns physical pages
// via MADV_DONTNEED on decommit/memory pressure to avoid Android lmkd kills.
class GuestArena {
public:
    static constexpr uint32_t kGuestPageSize = 4096;
    static constexpr uint32_t kWinAllocGranularity = 65536;

    ~GuestArena() { release_all(); }

    bool reserve(uintptr_t preferred_base, size_t bytes) {
#if defined(__linux__) || defined(__ANDROID__)
        host_page_ = static_cast<size_t>(sysconf(_SC_PAGESIZE));
        size_ = align_up(bytes, host_page_);

        int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE;
#ifdef MAP_FIXED_NOREPLACE
        void* p = mmap(reinterpret_cast<void*>(preferred_base), size_, PROT_NONE,
                       flags | MAP_FIXED_NOREPLACE, -1, 0);
        if (p == MAP_FAILED) {
            // Fallback to kernel-chosen low-VA hint if preferred base is occupied
            p = mmap(reinterpret_cast<void*>(preferred_base), size_, PROT_NONE, flags, -1, 0);
        }
#else
        void* p = mmap(reinterpret_cast<void*>(preferred_base), size_, PROT_NONE, flags, -1, 0);
#endif
        if (p == MAP_FAILED) return false;
        base_ = reinterpret_cast<uintptr_t>(p);
        cursor_ = base_ + 0x10000000ULL; // Leave lower 256MB open for PE ImageBase mapping
        return true;
#else
        // Portable host-test simulation mode (non-POSIX build)
        host_page_ = 4096;
        base_ = preferred_base;
        size_ = align_up(bytes, kWinAllocGranularity);
        cursor_ = base_ + 0x10000000ULL;
        return true;
#endif
    }

    uintptr_t virtual_alloc(uintptr_t desired_va, size_t len, int posix_prot, bool commit) {
        std::lock_guard<std::mutex> lock(mu_);
        if (base_ == 0 || len == 0) return 0;

        const size_t aligned_len = align_up(len, std::max<size_t>(host_page_, kWinAllocGranularity));
        uintptr_t target = desired_va;
        if (target == 0) {
            target = align_up(cursor_, kWinAllocGranularity);
            if (target + aligned_len > base_ + size_) return 0;
            cursor_ = target + aligned_len;
        } else {
            target = align_down(target, host_page_);
            if (target < base_ || target + aligned_len > base_ + size_) return 0;
        }

#if defined(__linux__) || defined(__ANDROID__)
        if (commit) {
            // Guest x86_64 code pages are NEVER host-executable on ARM64; strip PROT_EXEC.
            int safe_prot = posix_prot & ~PROT_EXEC;
            if (mprotect(reinterpret_cast<void*>(target), aligned_len, safe_prot) != 0) {
                return 0;
            }
        }
#endif
        regions_[target] = {target, aligned_len, posix_prot, commit};
        return target;
    }

    bool virtual_decommit(uintptr_t guest_va, size_t len) {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = regions_.find(align_down(guest_va, host_page_));
        if (it == regions_.end()) return false;

        const size_t span = len ? align_up(len, host_page_) : it->second.size;
#if defined(__linux__) || defined(__ANDROID__)
        madvise(reinterpret_cast<void*>(it->second.base), span, MADV_DONTNEED);
        mprotect(reinterpret_cast<void*>(it->second.base), span, PROT_NONE);
#endif
        it->second.committed = false;
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
#if defined(__linux__) || defined(__ANDROID__)
        if (base_ != 0 && size_ != 0) {
            munmap(reinterpret_cast<void*>(base_), size_);
        }
#endif
        base_ = 0;
        size_ = 0;
        regions_.clear();
    }

    uintptr_t base() const { return base_; }
    size_t size() const { return size_; }
    size_t host_page_size() const { return host_page_; }
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

private:
    mutable std::mutex mu_;
    uintptr_t base_ = 0;
    uintptr_t cursor_ = 0;
    size_t size_ = 0;
    size_t host_page_ = 4096;
    std::unordered_map<uintptr_t, RegionRecord> regions_;
};

} // namespace mobiro::mem
