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

// Simple thread-safe bump + free-block-reusing heap backed directly by GuestArena.
// Supports MSVC CRT startup (GetProcessHeap / HeapAlloc / HeapReAlloc / HeapFree / HeapSize).
class GuestHeap {
public:
    bool initialize(mem::GuestArena* arena, size_t initial_bytes = 32 * 1024 * 1024) {
        std::lock_guard<std::mutex> lock(mu_);
        arena_ = arena;
        if (!arena_) return false;
        base_ = arena_->virtual_alloc(0, initial_bytes, mem::kProtRead | mem::kProtWrite, true);
        if (!base_) return false;
        capacity_ = initial_bytes;
        cursor_ = base_;
        allocs_.clear();
        return true;
    }

    uintptr_t handle() const { return base_; }

    uintptr_t alloc(size_t bytes, bool zero_memory) {
        std::lock_guard<std::mutex> lock(mu_);
        if (!base_) return 0;
        const size_t req = std::max<size_t>(16, (bytes + 15) & ~size_t(15));

        // First-fit reuse from freed blocks
        for (auto it = free_list_.begin(); it != free_list_.end(); ++it) {
            if (it->second >= req) {
                uintptr_t ptr = it->first;
                size_t cap = it->second;
                free_list_.erase(it);
                allocs_[ptr] = cap;
                if (zero_memory) std::memset(reinterpret_cast<void*>(ptr), 0, cap);
                return ptr;
            }
        }

        if (cursor_ + req > base_ + capacity_) {
            // Grow with an overflow chunk from GuestArena
            const size_t chunk = std::max<size_t>(req, 16 * 1024 * 1024);
            uintptr_t extra = arena_->virtual_alloc(0, chunk, mem::kProtRead | mem::kProtWrite, true);
            if (!extra) return 0;
            base_extra_ = extra;
            cursor_ = extra;
            capacity_ = chunk;
            base_cur_end_ = extra + chunk;
        }
        uintptr_t ptr = cursor_;
        cursor_ += req;
        allocs_[ptr] = req;
        if (zero_memory) std::memset(reinterpret_cast<void*>(ptr), 0, req);
        return ptr;
    }

    uintptr_t realloc(uintptr_t old_ptr, size_t new_bytes, bool zero_memory) {
        if (!old_ptr) return alloc(new_bytes, zero_memory);
        size_t old_sz = size_of(old_ptr);
        if (old_sz == ~size_t(0)) return 0;
        if (new_bytes <= old_sz) return old_ptr;

        uintptr_t next = alloc(new_bytes, zero_memory);
        if (!next) return 0;
        std::memcpy(reinterpret_cast<void*>(next), reinterpret_cast<const void*>(old_ptr), old_sz);
        free(old_ptr);
        return next;
    }

    bool free(uintptr_t ptr) {
        if (!ptr) return true;
        std::lock_guard<std::mutex> lock(mu_);
        auto it = allocs_.find(ptr);
        if (it == allocs_.end()) return false;
        free_list_.emplace_back(it->first, it->second);
        allocs_.erase(it);
        return true;
    }

    size_t size_of(uintptr_t ptr) const {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = allocs_.find(ptr);
        return (it != allocs_.end()) ? it->second : ~size_t(0);
    }

    void reset() {
        std::lock_guard<std::mutex> lock(mu_);
        allocs_.clear();
        free_list_.clear();
        base_ = 0;
        cursor_ = 0;
        capacity_ = 0;
    }

private:
    mutable std::mutex mu_;
    mem::GuestArena* arena_ = nullptr;
    uintptr_t base_ = 0;
    uintptr_t base_extra_ = 0;
    uintptr_t base_cur_end_ = 0;
    uintptr_t cursor_ = 0;
    size_t capacity_ = 0;
    std::unordered_map<uintptr_t, size_t> allocs_;
    std::vector<std::pair<uintptr_t, size_t>> free_list_;
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
        auto pred = [&] { return obj->signaled; };
        bool ready = false;
        if (timeout_ms == kInfinite) {
            obj->cv.wait(lk, pred);
            ready = true;
        } else {
            ready = obj->cv.wait_for(lk, std::chrono::milliseconds(timeout_ms), pred);
        }
        if (!ready) return kWaitTimeout;
        if (!obj->manual_reset) obj->signaled = false;
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
