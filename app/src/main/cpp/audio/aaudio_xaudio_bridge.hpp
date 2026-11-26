#pragma once

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <vector>

#if defined(__ANDROID__)
#include <aaudio/AAudio.h>
#endif

namespace mobiro::audio {

// Lock-free single-producer / single-consumer float32 PCM ring buffer (48 kHz stereo)
// connecting XAudio2 source voice submissions directly into Android's low-latency AAudio callback.
class PcmRingBuffer {
public:
    explicit PcmRingBuffer(size_t capacity_samples = 48000 * 2) // 0.5s stereo headroom
        : cap_(next_pow2(capacity_samples)), mask_(cap_ - 1), buf_(cap_, 0.0f) {}

    size_t write(const float* samples, size_t count) {
        const size_t w = write_idx_.load(std::memory_order_relaxed);
        const size_t r = read_idx_.load(std::memory_order_acquire);
        const size_t avail = cap_ - (w - r);
        const size_t to_copy = std::min(count, avail);
        if (to_copy > 0) {
            const size_t pos = w & mask_;
            const size_t first = std::min(to_copy, cap_ - pos);
            std::memcpy(buf_.data() + pos, samples, first * sizeof(float));
            if (to_copy > first) {
                std::memcpy(buf_.data(), samples + first, (to_copy - first) * sizeof(float));
            }
            write_idx_.store(w + to_copy, std::memory_order_release);
        }
        return to_copy;
    }

    size_t read(float* out, size_t count) {
        const size_t r = read_idx_.load(std::memory_order_relaxed);
        const size_t w = write_idx_.load(std::memory_order_acquire);
        const size_t avail = w - r;
        const size_t to_copy = std::min(count, avail);
        if (to_copy > 0) {
            const size_t pos = r & mask_;
            const size_t first = std::min(to_copy, cap_ - pos);
            std::memcpy(out, buf_.data() + pos, first * sizeof(float));
            if (to_copy > first) {
                std::memcpy(out + first, buf_.data(), (to_copy - first) * sizeof(float));
            }
            read_idx_.store(r + to_copy, std::memory_order_release);
        }
        if (to_copy < count) {
            std::memset(out + to_copy, 0, (count - to_copy) * sizeof(float)); // Zero-fill underruns cleanly
        }
        return to_copy;
    }

    size_t available_samples() const {
        return write_idx_.load(std::memory_order_acquire) - read_idx_.load(std::memory_order_relaxed);
    }

    void clear() {
        read_idx_.store(write_idx_.load(std::memory_order_acquire), std::memory_order_release);
    }

private:
    static size_t next_pow2(size_t v) {
        size_t p = 1;
        while (p < v) p <<= 1;
        return p;
    }

    size_t cap_;
    size_t mask_;
    std::vector<float> buf_;
    std::atomic<size_t> write_idx_{0};
    std::atomic<size_t> read_idx_{0};
};

class AAudioXAudioBridge {
public:
    static AAudioXAudioBridge& global() {
        static AAudioXAudioBridge inst;
        return inst;
    }

    bool start(int32_t sample_rate = 48000, int32_t channels = 2) {
        sample_rate_ = sample_rate;
        channels_ = channels;
#if defined(__ANDROID__)
        if (stream_) return true;
        AAudioStreamBuilder* builder = nullptr;
        if (AAudio_createStreamBuilder(&builder) != AAUDIO_OK || !builder) return false;

        AAudioStreamBuilder_setDirection(builder, AAUDIO_DIRECTION_OUTPUT);
        AAudioStreamBuilder_setFormat(builder, AAUDIO_FORMAT_PCM_FLOAT);
        AAudioStreamBuilder_setSampleRate(builder, sample_rate_);
        AAudioStreamBuilder_setChannelCount(builder, channels_);
        AAudioStreamBuilder_setPerformanceMode(builder, AAUDIO_PERFORMANCE_MODE_LOW_LATENCY);
        AAudioStreamBuilder_setSharingMode(builder, AAUDIO_SHARING_MODE_SHARED);
        AAudioStreamBuilder_setDataCallback(builder, &aaudio_data_callback, this);

        aaudio_result_t res = AAudioStreamBuilder_openStream(builder, &stream_);
        AAudioStreamBuilder_delete(builder);
        if (res != AAUDIO_OK || !stream_) {
            stream_ = nullptr;
            return false;
        }
        if (AAudioStream_requestStart(stream_) != AAUDIO_OK) {
            stop();
            return false;
        }
#endif
        running_.store(true, std::memory_order_release);
        return true;
    }

    void stop() {
        running_.store(false, std::memory_order_release);
#if defined(__ANDROID__)
        if (stream_) {
            AAudioStream_requestStop(stream_);
            AAudioStream_close(stream_);
            stream_ = nullptr;
        }
#endif
        ring_.clear();
    }

    size_t submit_pcm_float(const float* samples, size_t sample_count) {
        return ring_.write(samples, sample_count);
    }

    size_t drain_pcm_float(float* out, size_t sample_count) {
        return ring_.read(out, sample_count);
    }

    bool is_running() const { return running_.load(std::memory_order_acquire); }
    int32_t sample_rate() const { return sample_rate_; }
    int32_t channels() const { return channels_; }

private:
#if defined(__ANDROID__)
    static aaudio_data_callback_result_t aaudio_data_callback(
        AAudioStream* /*stream*/, void* user_data, void* audio_data, int32_t num_frames) {
        auto* self = static_cast<AAudioXAudioBridge*>(user_data);
        self->ring_.read(static_cast<float*>(audio_data),
                         static_cast<size_t>(num_frames) * static_cast<size_t>(self->channels_));
        return AAUDIO_CALLBACK_RESULT_CONTINUE;
    }
    AAudioStream* stream_ = nullptr;
#endif
    PcmRingBuffer ring_;
    int32_t sample_rate_ = 48000;
    int32_t channels_ = 2;
    std::atomic<bool> running_{false};
};

} // namespace mobiro::audio
