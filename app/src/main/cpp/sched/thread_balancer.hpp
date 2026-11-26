#pragma once

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <mutex>
#include <string>
#include <vector>

#if defined(__ANDROID__)
#include <android/performance_hint.h>
#endif
#if defined(__linux__) || defined(__ANDROID__)
#include <sched.h>
#include <sys/resource.h>
#include <unistd.h>
#endif

namespace mobiro::sched {

struct CpuTopology {
    std::vector<int> prime_cores;
    std::vector<int> perf_cores;
    std::vector<int> eff_cores;

    static CpuTopology classify(const std::vector<std::pair<int, long>>& id_khz) {
        CpuTopology topo;
        if (id_khz.empty()) return topo;

        auto sorted = id_khz;
        std::sort(sorted.begin(), sorted.end(),
                  [](const auto& a, const auto& b) { return a.second > b.second; });

        const long top_khz = sorted.front().second;
        const long low_khz = sorted.back().second;

        for (const auto& [id, khz] : sorted) {
            if (khz == top_khz && topo.prime_cores.size() < 2) {
                topo.prime_cores.push_back(id);
            } else if (khz == low_khz && low_khz < top_khz) {
                topo.eff_cores.push_back(id);
            } else {
                topo.perf_cores.push_back(id);
            }
        }
        if (topo.perf_cores.empty()) topo.perf_cores = topo.prime_cores;
        if (topo.eff_cores.empty())  topo.eff_cores  = topo.perf_cores;
        return topo;
    }

    static CpuTopology detect() {
        std::vector<std::pair<int, long>> cores;
#if defined(__linux__) || defined(__ANDROID__)
        const int n = static_cast<int>(sysconf(_SC_NPROCESSORS_CONF));
        for (int i = 0; i < n; ++i) {
            std::ifstream f("/sys/devices/system/cpu/cpu" + std::to_string(i) +
                            "/cpufreq/cpuinfo_max_freq");
            long khz = 0;
            if (f >> khz) cores.emplace_back(i, khz);
        }
#endif
        return classify(cores);
    }
};

enum class ThreadRole {
    MainSimPhysics,
    RenderAndDxvkCs,
    EngineWorker,
    ShaderCompilerAndIO
};

class ThreadBalancer {
public:
    void initialize(int64_t target_frame_ns = 16'666'666) {
        topo_ = CpuTopology::detect();
        target_ns_ = target_frame_ns;
#if defined(__ANDROID__) && __ANDROID_API__ >= 33
        adpf_mgr_ = APerformanceHint_getManager();
#endif
    }

    void bind_current_thread(ThreadRole role) {
#if defined(__linux__) || defined(__ANDROID__)
        const std::vector<int>* pool = &topo_.perf_cores;
        int nice_val = 0;
        switch (role) {
            case ThreadRole::MainSimPhysics:
                pool = &topo_.prime_cores;
                nice_val = -6;
                register_adpf_tid(static_cast<int32_t>(gettid()));
                break;
            case ThreadRole::RenderAndDxvkCs:
                pool = &topo_.perf_cores;
                nice_val = -4;
                register_adpf_tid(static_cast<int32_t>(gettid()));
                break;
            case ThreadRole::EngineWorker:
                pool = &topo_.perf_cores;
                nice_val = 0;
                break;
            case ThreadRole::ShaderCompilerAndIO:
                pool = &topo_.eff_cores;
                nice_val = 10;
                break;
        }
        if (!pool->empty()) {
            cpu_set_t mask;
            CPU_ZERO(&mask);
            for (int cpu : *pool) CPU_SET(cpu, &mask);
            sched_setaffinity(0, sizeof(mask), &mask);
        }
        setpriority(PRIO_PROCESS, 0, nice_val);
#else
        (void)role;
#endif
    }

    void report_frame_work(int64_t actual_work_ns) {
#if defined(__ANDROID__) && __ANDROID_API__ >= 33
        if (actual_work_ns <= 0) return;
        std::lock_guard<std::mutex> lk(adpf_mu_);
        if (adpf_session_) {
            APerformanceHint_reportActualWorkDuration(adpf_session_, actual_work_ns);
        }
#else
        (void)actual_work_ns;
#endif
    }

    void update_target_work_duration(int64_t target_ns) {
        std::lock_guard<std::mutex> lk(adpf_mu_);
        target_ns_ = target_ns;
#if defined(__ANDROID__) && __ANDROID_API__ >= 33
        if (adpf_session_) {
            APerformanceHint_updateTargetWorkDuration(adpf_session_, target_ns_);
        }
#endif
    }

    int recommended_compiler_threads() const {
        return std::clamp<int>(static_cast<int>(topo_.eff_cores.size()), 1, 4);
    }

private:
    void register_adpf_tid(int32_t tid) {
#if defined(__ANDROID__) && __ANDROID_API__ >= 33
        std::lock_guard<std::mutex> lk(adpf_mu_);
        if (!adpf_mgr_) return;
        if (std::find(critical_tids_.begin(), critical_tids_.end(), tid) != critical_tids_.end())
            return;
        critical_tids_.push_back(tid);
        if (adpf_session_) APerformanceHint_closeSession(adpf_session_);
        adpf_session_ = APerformanceHint_createSession(
            adpf_mgr_, critical_tids_.data(), critical_tids_.size(), target_ns_);
#else
        (void)tid;
#endif
    }

    CpuTopology topo_;
    std::mutex adpf_mu_;
    int64_t target_ns_ = 16'666'666;
    std::vector<int32_t> critical_tids_;
#if defined(__ANDROID__) && __ANDROID_API__ >= 33
    APerformanceHintManager* adpf_mgr_ = nullptr;
    APerformanceHintSession* adpf_session_ = nullptr;
#endif
};

} // namespace mobiro::sched
