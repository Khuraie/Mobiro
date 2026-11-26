#pragma once

#include "guest_arena.hpp"
#include "win64_teb.hpp"
#include "../sched/thread_balancer.hpp"

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>

namespace mobiro::win32 {

// Futex-style Win32 WaitOnAddress / WakeByAddressSingle / WakeByAddressAll.
// Used by modern MSVC synchronization primitives and FromSoftware lock-free queues.
class AddressWaitTable {
public:
    bool wait_on_address(const volatile void* address, const void* compare_addr,
                         size_t size, uint32_t timeout_ms) {
        if (!address || !compare_addr || (size != 1 && size != 2 && size != 4 && size != 8)) {
            return false;
        }
        auto& b = bucket(address);
        std::unique_lock<std::mutex> lk(b.mu);
        auto changed = [&] { return !equals_atomic(address, compare_addr, size); };
        if (changed()) return true;

        if (timeout_ms == 0xFFFFFFFFu) {
            b.cv.wait(lk, changed);
            return true;
        }
        return b.cv.wait_for(lk, std::chrono::milliseconds(timeout_ms), changed);
    }

    void wake_single(const void* address) {
        if (!address) return;
        auto& b = bucket(address);
        {
            std::lock_guard<std::mutex> lk(b.mu);
        }
        b.cv.notify_one();
    }

    void wake_all(const void* address) {
        if (!address) return;
        auto& b = bucket(address);
        {
            std::lock_guard<std::mutex> lk(b.mu);
        }
        b.cv.notify_all();
    }

private:
    struct alignas(64) Bucket {
        std::mutex mu;
        std::condition_variable cv;
    };

    Bucket& bucket(const volatile void* addr) {
        const size_t idx = (reinterpret_cast<uintptr_t>(addr) >> 4) & (kBuckets - 1);
        return buckets_[idx];
    }

    static bool equals_atomic(const volatile void* a, const void* b, size_t sz) {
        uint64_t va = 0, vb = 0;
        std::memcpy(&vb, b, sz);
        const void* raw = const_cast<const void*>(a);
        switch (sz) {
            case 1: va = reinterpret_cast<const std::atomic<uint8_t>*>(raw)->load(std::memory_order_acquire); break;
            case 2: va = reinterpret_cast<const std::atomic<uint16_t>*>(raw)->load(std::memory_order_acquire); break;
            case 4: va = reinterpret_cast<const std::atomic<uint32_t>*>(raw)->load(std::memory_order_acquire); break;
            case 8: va = reinterpret_cast<const std::atomic<uint64_t>*>(raw)->load(std::memory_order_acquire); break;
            default: return false;
        }
        return va == vb;
    }

    static constexpr size_t kBuckets = 64;
    std::array<Bucket, kBuckets> buckets_;
};

// Manages Win32 guest threads (CreateThread / SetThreadPriority / WaitForSingleObject)
// and auto-binds spawned worker threads via Mobiro's big.LITTLE ThreadBalancer.
class GuestThreadTable {
public:
    static constexpr uint64_t kHandleTag = 0x00030000ULL;
    using ThreadDispatchFn = std::function<uint32_t(uintptr_t start_pc, uintptr_t param, cpu::Win64Teb* teb)>;
    using EnvDispatchFn = std::function<uint32_t(uintptr_t start_pc, uintptr_t param, const cpu::Win64ThreadEnv& env)>;

    ~GuestThreadTable() { join_all(); }

    void set_balancer(sched::ThreadBalancer* balancer) { balancer_ = balancer; }
    void set_dispatch_callback(ThreadDispatchFn fn) { dispatch_fn_ = std::move(fn); }
    void set_env_dispatch_callback(EnvDispatchFn fn) { env_dispatch_fn_ = std::move(fn); }

    bool is_thread_handle(uint64_t h) const { return (h & 0xFFFF0000ULL) == kHandleTag; }

    uint64_t create_thread(mem::GuestArena* arena,
                           uintptr_t image_base,
                           uintptr_t start_pc,
                           uintptr_t param,
                           uint32_t* out_tid) {
        if (!arena || !start_pc) return 0;

        auto rec = std::make_shared<ThreadRec>();
        const uint32_t tid = next_tid_.fetch_add(1);
        rec->tid = tid;
        if (!rec->env.init_worker_thread(*arena, image_base, 8, 1000, tid, 512 * 1024)) {
            return 0;
        }

        const uint64_t handle = kHandleTag | static_cast<uint64_t>(tid);
        if (out_tid) *out_tid = tid;

        auto dispatch = dispatch_fn_;
        auto env_dispatch = env_dispatch_fn_;
        auto* balancer = balancer_;
        rec->worker = std::thread([rec, dispatch, env_dispatch, balancer, start_pc, param]() {
            if (balancer) {
                balancer->bind_current_thread(sched::ThreadRole::EngineWorker);
            }
            uint32_t code = 0;
            if (dispatch) {
                code = dispatch(start_pc, param, rec->env.teb);
            } else if (env_dispatch) {
                code = env_dispatch(start_pc, param, rec->env);
            }
            {
                std::lock_guard<std::mutex> lk(rec->mu);
                rec->exit_code = code;
                rec->finished = true;
            }
            rec->cv.notify_all();
        });

        std::lock_guard<std::mutex> lk(mu_);
        threads_[handle] = std::move(rec);
        return handle;
    }

    uint32_t wait_single(uint64_t handle, uint32_t timeout_ms) {
        auto rec = find(handle);
        if (!rec) return 0xFFFFFFFFu;
        std::unique_lock<std::mutex> lk(rec->mu);
        auto done = [&] { return rec->finished; };
        bool ok = false;
        if (timeout_ms == 0xFFFFFFFFu) {
            rec->cv.wait(lk, done);
            ok = true;
        } else {
            ok = rec->cv.wait_for(lk, std::chrono::milliseconds(timeout_ms), done);
        }
        return ok ? 0x00000000u : 0x00000102u;
    }

    bool close(uint64_t handle) {
        std::shared_ptr<ThreadRec> rec;
        {
            std::lock_guard<std::mutex> lk(mu_);
            auto it = threads_.find(handle);
            if (it == threads_.end()) return false;
            rec = std::move(it->second);
            threads_.erase(it);
        }
        if (rec && rec->worker.joinable()) rec->worker.join();
        return true;
    }

    void join_all() {
        std::unordered_map<uint64_t, std::shared_ptr<ThreadRec>> copy;
        {
            std::lock_guard<std::mutex> lk(mu_);
            copy.swap(threads_);
        }
        for (auto& [_, rec] : copy) {
            if (rec && rec->worker.joinable()) rec->worker.join();
        }
    }

private:
    struct ThreadRec {
        uint32_t tid = 0;
        uint32_t exit_code = 0;
        bool finished = false;
        cpu::Win64ThreadEnv env;
        std::mutex mu;
        std::condition_variable cv;
        std::thread worker;
    };

    std::shared_ptr<ThreadRec> find(uint64_t h) const {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = threads_.find(h);
        return (it != threads_.end()) ? it->second : nullptr;
    }

    mutable std::mutex mu_;
    std::atomic<uint32_t> next_tid_{200};
    sched::ThreadBalancer* balancer_ = nullptr;
    ThreadDispatchFn dispatch_fn_;
    EnvDispatchFn env_dispatch_fn_;
    std::unordered_map<uint64_t, std::shared_ptr<ThreadRec>> threads_;
};

} // namespace mobiro::win32
