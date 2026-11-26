#pragma once

#include "aaudio_xaudio_bridge.hpp"
#include "xaudio2_com.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace mobiro::audio {

// Binary-compatible Win64 WAVEHDR (48 bytes on x64)
struct Win64WaveHdr {
    uint8_t* lpData = nullptr;      // +0x00
    uint32_t dwBufferLength = 0;    // +0x08
    uint32_t dwBytesRecorded = 0;   // +0x0C
    uint64_t dwUser = 0;            // +0x10
    uint32_t dwFlags = 0;           // +0x18 (WHDR_DONE=1, WHDR_PREPARED=2)
    uint32_t dwLoops = 0;           // +0x1C
    void*    lpNext = nullptr;      // +0x20
    uint64_t reserved = 0;          // +0x28
};
static_assert(sizeof(Win64WaveHdr) == 48);

// Binary-compatible Win64 MMTIME (12 bytes)
struct Win64MmTime {
    uint32_t wType = 0;   // TIME_SAMPLES=2, TIME_BYTES=4
    uint32_t value = 0;
    uint32_t pad = 0;
};

// Bridges WinMM waveOut* (used by FMODEx fmodex64.dll and Bink2 bink2w64.dll)
// directly into Mobiro's lock-free Android AAudio low-latency PCM ring buffer.
class WinmmWaveOutBridge {
public:
    static constexpr uint32_t kWhdrDone = 0x01u;
    static constexpr uint32_t kWhdrPrepared = 0x02u;
    static constexpr uint32_t kCallbackEvent = 0x00050000u;

    static WinmmWaveOutBridge& global() {
        static WinmmWaveOutBridge inst;
        return inst;
    }

    struct Stream {
        WaveFormatEx fmt{};
        uint64_t bytes_written = 0;
        uint64_t callback_event = 0;
        float gain = 1.0f;
        bool paused = false;
        std::vector<float> scratch_stereo;
        std::vector<float> scratch_resampled;
    };

    uint32_t open(uint64_t* out_handle, const WaveFormatEx* fmt,
                  uint64_t callback, uint32_t flags,
                  AAudioXAudioBridge* aaudio = &AAudioXAudioBridge::global()) {
        if (!out_handle || !fmt) return 11u; // MMSYSERR_INVALPARAM
        if (aaudio && !aaudio->is_running()) {
            aaudio->start(48000, 2);
        }
        std::lock_guard<std::mutex> lk(mu_);
        const uint64_t h = next_handle_++;
        Stream s{};
        s.fmt = *fmt;
        if ((flags & 0x00070000u) == kCallbackEvent) {
            s.callback_event = callback;
        }
        streams_[h] = std::move(s);
        *out_handle = h;
        return 0u; // MMSYSERR_NOERROR
    }

    uint32_t prepare(Win64WaveHdr* hdr) {
        if (!hdr) return 11u;
        hdr->dwFlags |= kWhdrPrepared;
        hdr->dwFlags &= ~kWhdrDone;
        return 0u;
    }

    uint32_t unprepare(Win64WaveHdr* hdr) {
        if (!hdr) return 11u;
        hdr->dwFlags &= ~kWhdrPrepared;
        return 0u;
    }

    // Converts WAVEHDR PCM16/float32 buffer, pushes into AAudio, marks WHDR_DONE,
    // and returns optional CALLBACK_EVENT handle so caller can signal FMOD's audio thread.
    uint32_t write(uint64_t handle, Win64WaveHdr* hdr, uint64_t* out_event_to_signal,
                   AAudioXAudioBridge* aaudio = &AAudioXAudioBridge::global()) {
        if (out_event_to_signal) *out_event_to_signal = 0;
        if (!hdr || !hdr->lpData) return 11u;

        std::lock_guard<std::mutex> lk(mu_);
        auto it = streams_.find(handle);
        if (it == streams_.end()) return 5u; // MMSYSERR_INVALHANDLE
        auto& s = it->second;

        if (!s.paused && hdr->dwBufferLength > 0 && aaudio) {
            const uint16_t ch = s.fmt.channels ? s.fmt.channels : 2u;
            const bool is_pcm16 = (s.fmt.bits_per_sample == 16) &&
                                  (s.fmt.format_tag == 1 || s.fmt.format_tag == 0xFFFEu);
            const bool is_f32   = (s.fmt.bits_per_sample == 32) &&
                                  (s.fmt.format_tag == 3 || s.fmt.format_tag == 0xFFFEu);
            auto& stereo = s.scratch_stereo;
            stereo.clear();

            if (is_pcm16) {
                const size_t frames = (hdr->dwBufferLength / sizeof(int16_t)) / ch;
                stereo.resize(frames * 2);
                const auto* src = reinterpret_cast<const int16_t*>(hdr->lpData);
                constexpr float kScale = 1.0f / 32768.0f;
                for (size_t i = 0; i < frames; ++i) {
                    const float l = static_cast<float>(src[i * ch + 0]) * kScale * s.gain;
                    const float r = (ch == 1) ? l : static_cast<float>(src[i * ch + 1]) * kScale * s.gain;
                    stereo[i * 2 + 0] = std::clamp(l, -1.0f, 1.0f);
                    stereo[i * 2 + 1] = std::clamp(r, -1.0f, 1.0f);
                }
            } else if (is_f32) {
                const size_t frames = (hdr->dwBufferLength / sizeof(float)) / ch;
                stereo.resize(frames * 2);
                const auto* src = reinterpret_cast<const float*>(hdr->lpData);
                for (size_t i = 0; i < frames; ++i) {
                    const float l = src[i * ch + 0] * s.gain;
                    const float r = (ch == 1) ? l : src[i * ch + 1] * s.gain;
                    stereo[i * 2 + 0] = std::clamp(l, -1.0f, 1.0f);
                    stereo[i * 2 + 1] = std::clamp(r, -1.0f, 1.0f);
                }
            }

            if (!stereo.empty()) {
                const uint32_t src_rate = s.fmt.samples_per_sec ? s.fmt.samples_per_sec : 48000u;
                const uint32_t dst_rate = static_cast<uint32_t>(aaudio->sample_rate() > 0 ? aaudio->sample_rate() : 48000);
                if (src_rate != dst_rate) {
                    const size_t src_frames = stereo.size() / 2;
                    const size_t dst_frames = std::max<size_t>(
                        1, static_cast<size_t>((static_cast<uint64_t>(src_frames) * dst_rate) / src_rate));
                    auto& resamp = s.scratch_resampled;
                    resamp.resize(dst_frames * 2);
                    const double step = static_cast<double>(src_rate) / static_cast<double>(dst_rate);
                    for (size_t i = 0; i < dst_frames; ++i) {
                        const double pos = i * step;
                        const size_t i0 = std::min<size_t>(static_cast<size_t>(pos), src_frames - 1);
                        const size_t i1 = std::min<size_t>(i0 + 1, src_frames - 1);
                        const float frac = static_cast<float>(pos - static_cast<double>(i0));
                        resamp[i * 2 + 0] = stereo[i0 * 2 + 0] + (stereo[i1 * 2 + 0] - stereo[i0 * 2 + 0]) * frac;
                        resamp[i * 2 + 1] = stereo[i0 * 2 + 1] + (stereo[i1 * 2 + 1] - stereo[i0 * 2 + 1]) * frac;
                    }
                    aaudio->submit_pcm_float(resamp.data(), resamp.size());
                } else {
                    aaudio->submit_pcm_float(stereo.data(), stereo.size());
                }
            }
        }

        s.bytes_written += hdr->dwBufferLength;
        hdr->dwFlags |= kWhdrDone;
        if (out_event_to_signal) *out_event_to_signal = s.callback_event;
        return 0u;
    }

    uint32_t get_position(uint64_t handle, Win64MmTime* mmt) {
        if (!mmt) return 11u;
        std::lock_guard<std::mutex> lk(mu_);
        auto it = streams_.find(handle);
        if (it == streams_.end()) return 5u;
        const auto& s = it->second;
        if (mmt->wType == 2u) { // TIME_SAMPLES
            const uint32_t ba = s.fmt.block_align ? s.fmt.block_align : 4u;
            mmt->value = static_cast<uint32_t>(s.bytes_written / ba);
        } else {
            mmt->wType = 4u; // TIME_BYTES
            mmt->value = static_cast<uint32_t>(s.bytes_written);
        }
        return 0u;
    }

    uint32_t set_paused(uint64_t handle, bool paused) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = streams_.find(handle);
        if (it == streams_.end()) return 5u;
        it->second.paused = paused;
        return 0u;
    }

    uint32_t set_volume(uint64_t handle, uint32_t vol_lr) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = streams_.find(handle);
        if (it == streams_.end()) return 5u;
        const float l = static_cast<float>(vol_lr & 0xFFFFu) / 65535.0f;
        const float r = static_cast<float>((vol_lr >> 16) & 0xFFFFu) / 65535.0f;
        it->second.gain = std::clamp((l + r) * 0.5f, 0.0f, 1.0f);
        return 0u;
    }

    uint32_t reset(uint64_t handle) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = streams_.find(handle);
        if (it == streams_.end()) return 5u;
        it->second.bytes_written = 0;
        return 0u;
    }

    uint32_t close(uint64_t handle) {
        std::lock_guard<std::mutex> lk(mu_);
        return streams_.erase(handle) ? 0u : 5u;
    }

private:
    std::mutex mu_;
    uint64_t next_handle_ = 0x00070001ULL;
    std::unordered_map<uint64_t, Stream> streams_;
};

} // namespace mobiro::audio
