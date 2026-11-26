#pragma once

#include "guest_arena.hpp"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <unordered_map>

namespace mobiro::win32 {

// Binary-compatible Win64 SYSTEM_INFO layout
struct Win64SystemInfo {
    uint16_t processor_architecture = 9; // PROCESSOR_ARCHITECTURE_AMD64
    uint16_t reserved = 0;
    uint32_t page_size = 4096;
    uint64_t min_app_address = 0x0000000000010000ULL;
    uint64_t max_app_address = 0x00007FFFFFFEFFFFULL;
    uint64_t active_processor_mask = 0xFF;
    uint32_t number_of_processors = 8;
    uint32_t processor_type = 8664;
    uint32_t allocation_granularity = 65536;
    uint16_t processor_level = 6;
    uint16_t processor_revision = 0x0100;
};

// O(1) power-of-2 segregated-freelist heap backed directly by GuestArena.
// Supports MSVC CRT startup & high-churn game allocations (HeapAlloc / HeapReAlloc / HeapFree / HeapSize)
// without hash-map lookups or O(N) freelist scans.
class GuestHeap {
public:
    static constexpr size_t kMinClassShift = 4;  // 16 bytes
    static constexpr size_t kMaxClassShift = 23; // 8 MiB
    static constexpr size_t kNumBuckets = kMaxClassShift - kMinClassShift + 1; // 20 size classes
    static constexpr uint64_t kMagicAlloc = 0x4D4248414C4C4F43ULL;
    static constexpr uint64_t kMagicFree  = 0x4D42484652454544ULL;

    struct alignas(16) BlockHeader {
        uint64_t magic = 0;
        uint64_t size = 0;
    };
    static_assert(sizeof(BlockHeader) == 16);

    bool initialize(mem::GuestArena* arena, size_t initial_bytes = 32 * 1024 * 1024) {
        std::lock_guard<std::mutex> lock(mu_);
        arena_ = arena;
        if (!arena_) return false;
        reset_locked();
        base_ = arena_->virtual_alloc(0, initial_bytes, mem::kProtRead | mem::kProtWrite, true);
        if (!base_) return false;
        chunks_.emplace_back(base_, base_ + initial_bytes);
        cursor_ = base_;
        chunk_end_ = base_ + initial_bytes;
        return true;
    }

    uintptr_t handle() const { return base_; }

    uintptr_t alloc(size_t bytes, bool zero_memory) {
        std::lock_guard<std::mutex> lock(mu_);
        if (!base_) return 0;

        const size_t min_sz = std::max<size_t>(16, (bytes + 15) & ~size_t(15));
        const int bucket = bucket_index(min_sz);
        const size_t cap = (bucket >= 0) ? (size_t(1) << (bucket + kMinClassShift)) : min_sz;

        // O(1) pop from matching power-of-2 segregated freelist
        if (bucket >= 0 && buckets_[bucket] != 0) {
            const uintptr_t ptr = buckets_[bucket];
            uintptr_t next = 0;
            std::memcpy(&next, reinterpret_cast<const void*>(ptr), sizeof(next));
            buckets_[bucket] = next;
            auto* hdr = reinterpret_cast<BlockHeader*>(ptr - sizeof(BlockHeader));
            hdr->magic = kMagicAlloc;
            if (zero_memory) std::memset(reinterpret_cast<void*>(ptr), 0, hdr->size);
            return ptr;
        }
        // Rare >8 MiB reuse
        if (bucket < 0) {
            for (auto it = large_free_.begin(); it != large_free_.end(); ++it) {
                if (it->second >= cap) {
                    const uintptr_t ptr = it->first;
                    const size_t blk_cap = it->second;
                    large_free_.erase(it);
                    auto* hdr = reinterpret_cast<BlockHeader*>(ptr - sizeof(BlockHeader));
                    hdr->magic = kMagicAlloc;
                    if (zero_memory) std::memset(reinterpret_cast<void*>(ptr), 0, blk_cap);
                    return ptr;
                }
            }
        }

        const size_t total = sizeof(BlockHeader) + cap;
        if (cursor_ + total > chunk_end_) {
            const size_t chunk = std::max<size_t>(total, 16 * 1024 * 1024);
            const uintptr_t extra = arena_->virtual_alloc(0, chunk, mem::kProtRead | mem::kProtWrite, true);
            if (!extra) return 0;
            chunks_.emplace_back(extra, extra + chunk);
            cursor_ = extra;
            chunk_end_ = extra + chunk;
        }

        auto* hdr = reinterpret_cast<BlockHeader*>(cursor_);
        hdr->magic = kMagicAlloc;
        hdr->size = cap;
        const uintptr_t ptr = cursor_ + sizeof(BlockHeader);
        cursor_ += total;
        if (zero_memory) std::memset(reinterpret_cast<void*>(ptr), 0, cap);
        return ptr;
    }

    uintptr_t realloc(uintptr_t old_ptr, size_t new_bytes, bool zero_memory) {
        if (!old_ptr) return alloc(new_bytes, zero_memory);
        const size_t old_sz = size_of(old_ptr);
        if (old_sz == ~size_t(0)) return 0;
        if (new_bytes <= old_sz) return old_ptr;

        const uintptr_t next = alloc(new_bytes, zero_memory);
        if (!next) return 0;
        std::memcpy(reinterpret_cast<void*>(next), reinterpret_cast<const void*>(old_ptr), old_sz);
        free(old_ptr);
        return next;
    }

    bool free(uintptr_t ptr) {
        if (!ptr) return true;
        std::lock_guard<std::mutex> lock(mu_);
        auto* hdr = validate_alloc_locked(ptr);
        if (!hdr) return false;
        hdr->magic = kMagicFree;
        const int bucket = bucket_index(static_cast<size_t>(hdr->size));
        if (bucket >= 0) {
            const uintptr_t prev = buckets_[bucket];
            std::memcpy(reinterpret_cast<void*>(ptr), &prev, sizeof(prev));
            buckets_[bucket] = ptr;
        } else {
            large_free_.emplace_back(ptr, static_cast<size_t>(hdr->size));
        }
        return true;
    }

    size_t size_of(uintptr_t ptr) const {
        if (!ptr) return ~size_t(0);
        std::lock_guard<std::mutex> lock(mu_);
        const auto* hdr = validate_alloc_locked(ptr);
        return hdr ? static_cast<size_t>(hdr->size) : ~size_t(0);
    }

    void reset() {
        std::lock_guard<std::mutex> lock(mu_);
        reset_locked();
    }

private:
    static int bucket_index(size_t sz) noexcept {
        if (sz > (size_t(1) << kMaxClassShift)) return -1;
        size_t cap = size_t(1) << kMinClassShift;
        int idx = 0;
        while (cap < sz && idx < static_cast<int>(kNumBuckets) - 1) {
            cap <<= 1;
            ++idx;
        }
        return idx;
    }

    BlockHeader* validate_alloc_locked(uintptr_t ptr) const noexcept {
        if ((ptr & 15u) != 0 || ptr < sizeof(BlockHeader)) return nullptr;
        const uintptr_t hdr_addr = ptr - sizeof(BlockHeader);
        for (const auto& [lo, hi] : chunks_) {
            if (hdr_addr >= lo && ptr < hi) {
                auto* hdr = reinterpret_cast<BlockHeader*>(hdr_addr);
                return (hdr->magic == kMagicAlloc) ? hdr : nullptr;
            }
        }
        return nullptr;
    }

    void reset_locked() {
        chunks_.clear();
        large_free_.clear();
        for (auto& b : buckets_) b = 0;
        base_ = 0;
        cursor_ = 0;
        chunk_end_ = 0;
    }

    mutable std::mutex mu_;
    mem::GuestArena* arena_ = nullptr;
    uintptr_t base_ = 0;
    uintptr_t cursor_ = 0;
    uintptr_t chunk_end_ = 0;
    std::vector<std::pair<uintptr_t, uintptr_t>> chunks_;
    uintptr_t buckets_[kNumBuckets]{};
    std::vector<std::pair<uintptr_t, size_t>> large_free_;
};

// Native C++ condition_variable-backed Win32 Event object table (manual/auto reset).
class EventTable {
public:
    static constexpr uint64_t kHandleTag = 0x00020000ULL;
    static constexpr uint32_t kWaitObject0 = 0x00000000u;
    static constexpr uint32_t kWaitTimeout = 0x00000102u;
    static constexpr uint32_t kWaitFailed  = 0xFFFFFFFFu;
    static constexpr uint32_t kInfinite    = 0xFFFFFFFFu;

    struct EventObj {
        std::mutex mu;
        std::condition_variable cv;
        bool manual_reset = false;
        bool signaled = false;
        bool is_semaphore = false;
        int32_t sem_count = 0;
        int32_t sem_max = 0;
    };

    uint64_t create_event(bool manual_reset, bool initial_state) {
        auto obj = std::make_shared<EventObj>();
        obj->manual_reset = manual_reset;
        obj->signaled = initial_state;
        std::lock_guard<std::mutex> lock(mu_);
        const uint64_t h = kHandleTag | (next_id_++);
        events_[h] = std::move(obj);
        return h;
    }

    uint64_t create_semaphore(int32_t initial_count, int32_t max_count) {
        if (max_count <= 0 || initial_count < 0 || initial_count > max_count) return 0;
        auto obj = std::make_shared<EventObj>();
        obj->is_semaphore = true;
        obj->sem_count = initial_count;
        obj->sem_max = max_count;
        obj->signaled = (initial_count > 0);
        std::lock_guard<std::mutex> lock(mu_);
        const uint64_t h = kHandleTag | (next_id_++);
        events_[h] = std::move(obj);
        return h;
    }

    bool release_semaphore(uint64_t h, int32_t release_count, int32_t* prev_count) {
        auto obj = find(h);
        if (!obj || !obj->is_semaphore || release_count <= 0) return false;
        {
            std::lock_guard<std::mutex> lk(obj->mu);
            if (obj->sem_count + release_count > obj->sem_max) return false;
            if (prev_count) *prev_count = obj->sem_count;
            obj->sem_count += release_count;
            obj->signaled = (obj->sem_count > 0);
        }
        obj->cv.notify_all();
        return true;
    }

    bool is_event_handle(uint64_t h) const { return (h & 0xFFFF0000ULL) == kHandleTag; }

    bool set_event(uint64_t h) {
        auto obj = find(h);
        if (!obj) return false;
        {
            std::lock_guard<std::mutex> lk(obj->mu);
            obj->signaled = true;
        }
        if (obj->manual_reset) obj->cv.notify_all();
        else                   obj->cv.notify_one();
        return true;
    }

    bool reset_event(uint64_t h) {
        auto obj = find(h);
        if (!obj) return false;
        std::lock_guard<std::mutex> lk(obj->mu);
        obj->signaled = false;
        return true;
    }

    uint32_t wait_single(uint64_t h, uint32_t timeout_ms) {
        auto obj = find(h);
        if (!obj) return kWaitFailed;
        std::unique_lock<std::mutex> lk(obj->mu);
        auto pred = [&] { return obj->is_semaphore ? (obj->sem_count > 0) : obj->signaled; };
        bool ready = false;
        if (timeout_ms == kInfinite) {
            obj->cv.wait(lk, pred);
            ready = true;
        } else {
            ready = obj->cv.wait_for(lk, std::chrono::milliseconds(timeout_ms), pred);
        }
        if (!ready) return kWaitTimeout;
        if (obj->is_semaphore) {
            --obj->sem_count;
            obj->signaled = (obj->sem_count > 0);
        } else if (!obj->manual_reset) {
            obj->signaled = false;
        }
        return kWaitObject0;
    }

    bool close(uint64_t h) {
        std::lock_guard<std::mutex> lock(mu_);
        return events_.erase(h) > 0;
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mu_);
        events_.clear();
    }

private:
    std::shared_ptr<EventObj> find(uint64_t h) const {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = events_.find(h);
        return (it != events_.end()) ? it->second : nullptr;
    }

    mutable std::mutex mu_;
    uint64_t next_id_ = 1;
    std::unordered_map<uint64_t, std::shared_ptr<EventObj>> events_;
};

// Binary-compatible Win64 RUNTIME_FUNCTION (.pdata entry) for SEH stack unwinding
struct RuntimeFunctionEntry {
    uint32_t begin_address = 0;
    uint32_t end_address = 0;
    uint32_t unwind_info_address = 0;
};
static_assert(sizeof(RuntimeFunctionEntry) == 12);

// Lookup registry for PE64 .pdata exception tables (backs RtlLookupFunctionEntry)
class SehUnwindRegistry {
public:
    void register_image(uintptr_t image_base, uintptr_t pdata_va, uint32_t pdata_size) {
        image_base_ = image_base;
        pdata_va_ = pdata_va;
        entry_count_ = pdata_size / sizeof(RuntimeFunctionEntry);
    }

    const RuntimeFunctionEntry* lookup(uintptr_t control_pc, uintptr_t* out_image_base) const {
        if (!pdata_va_ || entry_count_ == 0 || control_pc < image_base_) return nullptr;
        const uint32_t rva = static_cast<uint32_t>(control_pc - image_base_);
        const auto* entries = reinterpret_cast<const RuntimeFunctionEntry*>(pdata_va_);

        size_t lo = 0, hi = entry_count_;
        while (lo < hi) {
            const size_t mid = lo + (hi - lo) / 2;
            const auto& e = entries[mid];
            if (rva < e.begin_address) {
                hi = mid;
            } else if (rva >= e.end_address) {
                lo = mid + 1;
            } else {
                if (out_image_base) *out_image_base = image_base_;
                return &e;
            }
        }
        return nullptr;
    }

    size_t count() const { return entry_count_; }

private:
    uintptr_t image_base_ = 0;
    uintptr_t pdata_va_ = 0;
    size_t entry_count_ = 0;
};

} // namespace mobiro::win32
