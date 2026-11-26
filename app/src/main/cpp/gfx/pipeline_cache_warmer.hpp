#pragma once

#include "../sched/thread_balancer.hpp"

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

namespace mobiro::gfx {

struct CacheWarmStats {
    size_t files_warmed = 0;
    uint64_t bytes_warmed = 0;
    size_t stale_dirs_pruned = 0;
    bool completed = false;
};

// Manages per-build DXVK & Mesa Turnip shader/pipeline cache directories:
//   1. Prunes stale cache folders from previous PE/driver fingerprints to avoid storage bloat.
//   2. Pre-reads existing DXVK/Turnip cache files into the OS page cache on an Efficiency-core
//      background thread so Sekiro's loading screen & first combat area avoid I/O stalls.
class PipelineCacheWarmer {
public:
    ~PipelineCacheWarmer() { wait(); }

    size_t prune_stale_builds(const std::string& cache_root,
                              const std::string& active_fingerprint) {
        namespace fs = std::filesystem;
        std::error_code ec;
        if (!fs::is_directory(cache_root, ec)) return 0;

        size_t pruned = 0;
        for (const auto& entry : fs::directory_iterator(cache_root, ec)) {
            if (ec) { ec.clear(); continue; }
            if (!entry.is_directory(ec)) continue;
            const std::string name = entry.path().filename().string();
            if (name == active_fingerprint || name == "saves_overlay") continue;
            fs::remove_all(entry.path(), ec);
            if (!ec) ++pruned;
        }
        return pruned;
    }

    void start_async_warm(const std::string& cache_root,
                          const std::string& active_fingerprint,
                          sched::ThreadBalancer* balancer = nullptr) {
        wait();
        done_.store(false, std::memory_order_release);
        stats_ = {};

        worker_ = std::thread([this, cache_root, active_fingerprint, balancer]() {
            if (balancer) {
                balancer->bind_current_thread(sched::ThreadRole::ShaderCompilerAndIO);
            }
            stats_.stale_dirs_pruned = prune_stale_builds(cache_root, active_fingerprint);

            namespace fs = std::filesystem;
            const fs::path active_dir = fs::path(cache_root) / active_fingerprint;
            std::error_code ec;
            std::vector<char> scratch(64 * 1024);
            volatile uint64_t sink = 0;

            if (fs::is_directory(active_dir, ec)) {
                for (auto it = fs::recursive_directory_iterator(
                         active_dir, fs::directory_options::skip_permission_denied, ec);
                     it != fs::recursive_directory_iterator();
                     it.increment(ec)) {
                    if (ec) { ec.clear(); continue; }
                    if (!it->is_regular_file(ec)) continue;
                    std::ifstream f(it->path(), std::ios::binary);
                    if (!f) continue;
                    uint64_t total = 0;
                    while (f.read(scratch.data(), static_cast<std::streamsize>(scratch.size())) ||
                           f.gcount() > 0) {
                        const auto n = static_cast<size_t>(f.gcount());
                        if (n > 0) sink ^= static_cast<uint8_t>(scratch[0]);
                        total += n;
                    }
                    ++stats_.files_warmed;
                    stats_.bytes_warmed += total;
                }
            }
            (void)sink;
            stats_.completed = true;
            done_.store(true, std::memory_order_release);
        });
    }

    void wait() {
        if (worker_.joinable()) worker_.join();
    }

    bool is_done() const { return done_.load(std::memory_order_acquire); }
    CacheWarmStats stats() const { return stats_; }

private:
    std::thread worker_;
    std::atomic<bool> done_{false};
    CacheWarmStats stats_{};
};

} // namespace mobiro::gfx
