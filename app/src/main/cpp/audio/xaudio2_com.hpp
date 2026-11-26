#pragma once

#include "aaudio_xaudio_bridge.hpp"

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <vector>

namespace mobiro::audio {

// Canonical Win32 WAVEFORMATEX (18 bytes packed)
#pragma pack(push, 1)
struct WaveFormatEx {
    uint16_t format_tag = 1;       // 1 = WAVE_FORMAT_PCM, 3 = WAVE_FORMAT_IEEE_FLOAT
    uint16_t channels = 2;
    uint32_t samples_per_sec = 48000;
    uint32_t avg_bytes_per_sec = 192000;
    uint16_t block_align = 4;
    uint16_t bits_per_sample = 16;
    uint16_t cb_size = 0;
};
#pragma pack(pop)
static_assert(sizeof(WaveFormatEx) == 18, "WAVEFORMATEX must be 18 bytes");

// Canonical Win64 XAUDIO2_BUFFER
struct XAudio2Buffer {
    uint32_t flags = 0;
    uint32_t audio_bytes = 0;
    const uint8_t* audio_data = nullptr;
    uint32_t play_begin = 0;
    uint32_t play_length = 0;
    uint32_t loop_begin = 0;
    uint32_t loop_length = 0;
    uint32_t loop_count = 0;
    void* context = nullptr;
};

struct XAudio2VoiceState {
    void* current_buffer_context = nullptr;
    uint32_t buffers_queued = 0;
    uint64_t samples_played = 0;
};

struct IXAudio2VoiceCom;
struct IXAudio2SourceVoiceCom;
struct IXAudio2Com;

// Win64 COM vtable for IXAudio2Voice (19 slots matching xaudio2.h)
struct IXAudio2VoiceVtbl {
    void     (*GetVoiceDetails)(void* self, void* out_details);
    int32_t  (*SetOutputVoices)(void* self, const void* send_list);
    int32_t  (*SetEffectChain)(void* self, const void* effect_chain);
    int32_t  (*EnableEffect)(void* self, uint32_t idx, uint32_t op_set);
    int32_t  (*DisableEffect)(void* self, uint32_t idx, uint32_t op_set);
    void     (*GetEffectState)(void* self, uint32_t idx, int32_t* out_enabled);
    int32_t  (*SetEffectParameters)(void* self, uint32_t idx, const void* params, uint32_t bytes, uint32_t op_set);
    int32_t  (*GetEffectParameters)(void* self, uint32_t idx, void* params, uint32_t bytes);
    int32_t  (*SetFilterParameters)(void* self, const void* params, uint32_t op_set);
    void     (*GetFilterParameters)(void* self, void* params);
    int32_t  (*SetOutputFilterParameters)(void* self, void* dst, const void* params, uint32_t op_set);
    void     (*GetOutputFilterParameters)(void* self, void* dst, void* params);
    int32_t  (*SetVolume)(void* self, float volume, uint32_t op_set);
    void     (*GetVolume)(void* self, float* out_volume);
    int32_t  (*SetChannelVolumes)(void* self, uint32_t channels, const float* volumes, uint32_t op_set);
    void     (*GetChannelVolumes)(void* self, uint32_t channels, float* volumes);
    int32_t  (*SetOutputMatrix)(void* self, void* dst, uint32_t src_ch, uint32_t dst_ch, const float* matrix, uint32_t op_set);
    void     (*GetOutputMatrix)(void* self, void* dst, uint32_t src_ch, uint32_t dst_ch, float* matrix);
    void     (*DestroyVoice)(void* self);
};

// Win64 COM vtable for IXAudio2SourceVoice (extends IXAudio2Voice with slots 19..28)
struct IXAudio2SourceVoiceVtbl {
    IXAudio2VoiceVtbl base;
    int32_t  (*Start)(void* self, uint32_t flags, uint32_t op_set);
    int32_t  (*Stop)(void* self, uint32_t flags, uint32_t op_set);
    int32_t  (*SubmitSourceBuffer)(void* self, const XAudio2Buffer* buf, const void* wma_buf);
    int32_t  (*FlushSourceBuffers)(void* self);
    int32_t  (*Discontinuity)(void* self);
    int32_t  (*ExitLoop)(void* self, uint32_t op_set);
    void     (*GetState)(void* self, XAudio2VoiceState* out_state, uint32_t flags);
    int32_t  (*SetFrequencyRatio)(void* self, float ratio, uint32_t op_set);
    void     (*GetFrequencyRatio)(void* self, float* out_ratio);
    int32_t  (*SetSourceSampleRate)(void* self, uint32_t new_rate);
};

// Win64 COM vtable for IXAudio2 (XAudio2.9 slot layout; 13 slots)
// shortcut: XAudio2.7 has 2 extra device-enum slots before CreateSourceVoice; split vtable if legacy 2.7 path is hit.
struct IXAudio2Vtbl {
    int32_t  (*QueryInterface)(void* self, const void* riid, void** ppv);
    uint32_t (*AddRef)(void* self);
    uint32_t (*Release)(void* self);
    int32_t  (*RegisterForCallbacks)(void* self, void* cb);
    void     (*UnregisterForCallbacks)(void* self, void* cb);
    int32_t  (*CreateSourceVoice)(
        void* self, void** pp_voice, const WaveFormatEx* fmt,
        uint32_t flags, float max_freq_ratio, void* cb, const void* send_list, const void* fx_chain);
    int32_t  (*CreateSubmixVoice)(
        void* self, void** pp_voice, uint32_t in_ch, uint32_t in_rate,
        uint32_t flags, uint32_t stage, const void* send_list, const void* fx_chain);
    int32_t  (*CreateMasteringVoice)(
        void* self, void** pp_voice, uint32_t in_ch, uint32_t in_rate,
        uint32_t flags, const void* device_id, const void* fx_chain, uint32_t stream_cat);
    int32_t  (*StartEngine)(void* self);
    void     (*StopEngine)(void* self);
    int32_t  (*CommitChanges)(void* self, uint32_t op_set);
    void     (*GetPerformanceData)(void* self, void* out_perf);
    void     (*SetDebugConfiguration)(void* self, const void* cfg, void* reserved);
};

struct IXAudio2VoiceCom {
    const IXAudio2VoiceVtbl* lpVtbl = nullptr;
    float volume = 1.0f;
    uint32_t channels = 2;
    uint32_t sample_rate = 48000;
};

struct IXAudio2SourceVoiceCom {
    const IXAudio2SourceVoiceVtbl* lpVtbl = nullptr;
    float volume = 1.0f;
    float freq_ratio = 1.0f;
    WaveFormatEx format{};
    bool playing = false;
    uint64_t samples_played = 0;
    void* last_context = nullptr;
    AAudioXAudioBridge* bridge = nullptr;
};

struct IXAudio2Com {
    const IXAudio2Vtbl* lpVtbl = nullptr;
    std::atomic<uint32_t> ref_count{1};
    AAudioXAudioBridge* bridge = nullptr;
};

namespace detail {

inline void voice_get_details(void*, void*) {}
inline int32_t voice_ok_1(void*, const void*) { return 0; }
inline int32_t voice_ok_2u(void*, uint32_t, uint32_t) { return 0; }
inline void voice_get_fx_state(void*, uint32_t, int32_t* out) { if (out) *out = 0; }
inline int32_t voice_ok_set_fx(void*, uint32_t, const void*, uint32_t, uint32_t) { return 0; }
inline int32_t voice_ok_get_fx(void*, uint32_t, void*, uint32_t) { return 0; }
inline int32_t voice_ok_filter(void*, const void*, uint32_t) { return 0; }
inline void voice_get_filter(void*, void*) {}
inline int32_t voice_ok_out_filter(void*, void*, const void*, uint32_t) { return 0; }
inline void voice_get_out_filter(void*, void*, void*) {}
inline int32_t voice_ok_ch_vol(void*, uint32_t, const float*, uint32_t) { return 0; }
inline void voice_get_ch_vol(void*, uint32_t, float*) {}
inline int32_t voice_ok_matrix(void*, void*, uint32_t, uint32_t, const float*, uint32_t) { return 0; }
inline void voice_get_matrix(void*, void*, uint32_t, uint32_t, float*) {}

inline int32_t mastering_set_vol(void* self, float vol, uint32_t) {
    static_cast<IXAudio2VoiceCom*>(self)->volume = vol;
    return 0;
}
inline void mastering_get_vol(void* self, float* out) {
    if (out) *out = static_cast<IXAudio2VoiceCom*>(self)->volume;
}
inline void mastering_destroy(void* self) {
    delete static_cast<IXAudio2VoiceCom*>(self);
}

inline int32_t source_set_vol(void* self, float vol, uint32_t) {
    static_cast<IXAudio2SourceVoiceCom*>(self)->volume = vol;
    return 0;
}
inline void source_get_vol(void* self, float* out) {
    if (out) *out = static_cast<IXAudio2SourceVoiceCom*>(self)->volume;
}
inline void source_destroy(void* self) {
    delete static_cast<IXAudio2SourceVoiceCom*>(self);
}
inline int32_t source_start(void* self, uint32_t, uint32_t) {
    static_cast<IXAudio2SourceVoiceCom*>(self)->playing = true;
    return 0;
}
inline int32_t source_stop(void* self, uint32_t, uint32_t) {
    static_cast<IXAudio2SourceVoiceCom*>(self)->playing = false;
    return 0;
}
inline int32_t source_flush(void* self) {
    static_cast<IXAudio2SourceVoiceCom*>(self)->last_context = nullptr;
    return 0;
}
inline int32_t source_ok_0(void*) { return 0; }
inline int32_t source_ok_u(void*, uint32_t) { return 0; }

inline void source_get_state(void* self, XAudio2VoiceState* out, uint32_t) {
    if (!out) return;
    auto* v = static_cast<IXAudio2SourceVoiceCom*>(self);
    out->current_buffer_context = v->last_context;
    out->buffers_queued = 0; // Submitted buffers are pushed synchronously into the AAudio ring
    out->samples_played = v->samples_played;
}
inline int32_t source_set_freq(void* self, float r, uint32_t) {
    static_cast<IXAudio2SourceVoiceCom*>(self)->freq_ratio = r;
    return 0;
}
inline void source_get_freq(void* self, float* out) {
    if (out) *out = static_cast<IXAudio2SourceVoiceCom*>(self)->freq_ratio;
}
inline int32_t source_set_rate(void* self, uint32_t rate) {
    static_cast<IXAudio2SourceVoiceCom*>(self)->format.samples_per_sec = rate;
    return 0;
}

// Converts PCM16 or IEEE float32 (mono or stereo) into stereo float32 and pushes into AAudioXAudioBridge.
// shortcut: no sample-rate resampling yet; add linear/sinc resampler if non-48kHz Sekiro SFX voices appear.
inline int32_t source_submit_buffer(void* self, const XAudio2Buffer* buf, const void*) {
    if (!self || !buf || !buf->audio_data || buf->audio_bytes == 0) {
        return static_cast<int32_t>(0x80070057u); // E_INVALIDARG
    }
    auto* v = static_cast<IXAudio2SourceVoiceCom*>(self);
    v->last_context = buf->context;

    const uint16_t ch = (v->format.channels == 1) ? 1u : 2u;
    const float gain = v->volume;
    std::vector<float> stereo;

    if (v->format.format_tag == 1 && v->format.bits_per_sample == 16) {
        const size_t total_samples = buf->audio_bytes / sizeof(int16_t);
        const size_t frames = total_samples / ch;
        stereo.resize(frames * 2);
        const auto* src = reinterpret_cast<const int16_t*>(buf->audio_data);
        constexpr float kScale = 1.0f / 32768.0f;
        for (size_t i = 0; i < frames; ++i) {
            if (ch == 1) {
                const float s = std::clamp(static_cast<float>(src[i]) * kScale * gain, -1.0f, 1.0f);
                stereo[i * 2 + 0] = s;
                stereo[i * 2 + 1] = s;
            } else {
                stereo[i * 2 + 0] = std::clamp(static_cast<float>(src[i * 2 + 0]) * kScale * gain, -1.0f, 1.0f);
                stereo[i * 2 + 1] = std::clamp(static_cast<float>(src[i * 2 + 1]) * kScale * gain, -1.0f, 1.0f);
            }
        }
        v->samples_played += frames;
    } else if (v->format.format_tag == 3 && v->format.bits_per_sample == 32) {
        const size_t total_samples = buf->audio_bytes / sizeof(float);
        const size_t frames = total_samples / ch;
        stereo.resize(frames * 2);
        const auto* src = reinterpret_cast<const float*>(buf->audio_data);
        for (size_t i = 0; i < frames; ++i) {
            if (ch == 1) {
                const float s = std::clamp(src[i] * gain, -1.0f, 1.0f);
                stereo[i * 2 + 0] = s;
                stereo[i * 2 + 1] = s;
            } else {
                stereo[i * 2 + 0] = std::clamp(src[i * 2 + 0] * gain, -1.0f, 1.0f);
                stereo[i * 2 + 1] = std::clamp(src[i * 2 + 1] * gain, -1.0f, 1.0f);
            }
        }
        v->samples_played += frames;
    } else {
        return static_cast<int32_t>(0x88960001u); // XAUDIO2_E_INVALID_CALL
    }

    if (v->bridge && !stereo.empty()) {
        v->bridge->submit_pcm_float(stereo.data(), stereo.size());
    }
    return 0; // S_OK
}

inline const IXAudio2VoiceVtbl kMasteringVoiceVtbl = {
    voice_get_details, voice_ok_1, voice_ok_1, voice_ok_2u, voice_ok_2u,
    voice_get_fx_state, voice_ok_set_fx, voice_ok_get_fx, voice_ok_filter,
    voice_get_filter, voice_ok_out_filter, voice_get_out_filter,
    mastering_set_vol, mastering_get_vol, voice_ok_ch_vol, voice_get_ch_vol,
    voice_ok_matrix, voice_get_matrix, mastering_destroy
};

inline const IXAudio2SourceVoiceVtbl kSourceVoiceVtbl = {
    {
        voice_get_details, voice_ok_1, voice_ok_1, voice_ok_2u, voice_ok_2u,
        voice_get_fx_state, voice_ok_set_fx, voice_ok_get_fx, voice_ok_filter,
        voice_get_filter, voice_ok_out_filter, voice_get_out_filter,
        source_set_vol, source_get_vol, voice_ok_ch_vol, voice_get_ch_vol,
        voice_ok_matrix, voice_get_matrix, source_destroy
    },
    source_start, source_stop, source_submit_buffer, source_flush,
    source_ok_0, source_ok_u, source_get_state,
    source_set_freq, source_get_freq, source_set_rate
};

inline int32_t xa2_query_interface(void* self, const void*, void** ppv) {
    if (!ppv) return static_cast<int32_t>(0x80004003u); // E_POINTER
    *ppv = self;
    static_cast<IXAudio2Com*>(self)->ref_count.fetch_add(1, std::memory_order_relaxed);
    return 0;
}
inline uint32_t xa2_add_ref(void* self) {
    return static_cast<IXAudio2Com*>(self)->ref_count.fetch_add(1, std::memory_order_relaxed) + 1;
}
inline uint32_t xa2_release(void* self) {
    auto* obj = static_cast<IXAudio2Com*>(self);
    const uint32_t rem = obj->ref_count.fetch_sub(1, std::memory_order_acq_rel) - 1;
    if (rem == 0) delete obj;
    return rem;
}
inline int32_t xa2_reg_cb(void*, void*) { return 0; }
inline void xa2_unreg_cb(void*, void*) {}

inline int32_t xa2_create_source_voice(
    void* self, void** pp_voice, const WaveFormatEx* fmt,
    uint32_t, float, void*, const void*, const void*) {
    if (!pp_voice || !fmt) return static_cast<int32_t>(0x80070057u);
    auto* xa2 = static_cast<IXAudio2Com*>(self);
    auto* v = new IXAudio2SourceVoiceCom();
    v->lpVtbl = &kSourceVoiceVtbl;
    v->format = *fmt;
    v->bridge = xa2->bridge;
    *pp_voice = v;
    return 0;
}

inline int32_t xa2_create_submix_voice(
    void*, void** pp_voice, uint32_t ch, uint32_t rate,
    uint32_t, uint32_t, const void*, const void*) {
    if (!pp_voice) return static_cast<int32_t>(0x80070057u);
    auto* v = new IXAudio2VoiceCom();
    v->lpVtbl = &kMasteringVoiceVtbl;
    v->channels = ch ? ch : 2;
    v->sample_rate = rate ? rate : 48000;
    *pp_voice = v;
    return 0;
}

inline int32_t xa2_create_mastering_voice(
    void* self, void** pp_voice, uint32_t ch, uint32_t rate,
    uint32_t, const void*, const void*, uint32_t) {
    if (!pp_voice) return static_cast<int32_t>(0x80070057u);
    auto* xa2 = static_cast<IXAudio2Com*>(self);
    const uint32_t eff_ch = ch ? ch : 2;
    const uint32_t eff_rate = rate ? rate : 48000;
    if (xa2->bridge && !xa2->bridge->is_running()) {
        xa2->bridge->start(static_cast<int32_t>(eff_rate), static_cast<int32_t>(eff_ch));
    }
    auto* v = new IXAudio2VoiceCom();
    v->lpVtbl = &kMasteringVoiceVtbl;
    v->channels = eff_ch;
    v->sample_rate = eff_rate;
    *pp_voice = v;
    return 0;
}

inline int32_t xa2_start_engine(void* self) {
    auto* xa2 = static_cast<IXAudio2Com*>(self);
    if (xa2->bridge && !xa2->bridge->is_running()) {
        return xa2->bridge->start(48000, 2) ? 0 : static_cast<int32_t>(0x80004005u);
    }
    return 0;
}
inline void xa2_stop_engine(void* self) {
    auto* xa2 = static_cast<IXAudio2Com*>(self);
    if (xa2->bridge) xa2->bridge->stop();
}
inline int32_t xa2_commit(void*, uint32_t) { return 0; }
inline void xa2_perf(void*, void*) {}
inline void xa2_debug(void*, const void*, void*) {}

inline const IXAudio2Vtbl kXAudio2Vtbl = {
    xa2_query_interface, xa2_add_ref, xa2_release,
    xa2_reg_cb, xa2_unreg_cb,
    xa2_create_source_voice, xa2_create_submix_voice, xa2_create_mastering_voice,
    xa2_start_engine, xa2_stop_engine, xa2_commit, xa2_perf, xa2_debug
};

} // namespace detail

inline int32_t create_xaudio2_com(void** out_xa2, AAudioXAudioBridge* bridge = &AAudioXAudioBridge::global()) {
    if (!out_xa2 || !bridge) return static_cast<int32_t>(0x80070057u); // E_INVALIDARG
    if (!bridge->start(48000, 2)) return static_cast<int32_t>(0x80004005u); // E_FAIL
    auto* obj = new IXAudio2Com();
    obj->lpVtbl = &detail::kXAudio2Vtbl;
    obj->bridge = bridge;
    *out_xa2 = obj;
    return 0; // S_OK
}

} // namespace mobiro::audio
