#pragma once

#include "xaudio2_com.hpp"
#include "../cpu_mem/box64_bridge.hpp"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <utility>

namespace mobiro::audio {

enum class XAudioIfaceId : uint32_t {
    Unknown = 0,
    IXAudio2 = 1,
    IXAudio2_7 = 2,
    MasteringOrSubmixVoice = 3,
    SourceVoice = 4,
};

struct alignas(32) XAudioProxyObject {
    const uintptr_t* lpVtbl = nullptr;                  // +0x00: Win64 COM vtable (NativeBridgeStub*)
    void* native_obj = nullptr;                         // +0x08: IXAudio2* / IXAudio2Voice*
    XAudioIfaceId iface = XAudioIfaceId::Unknown;       // +0x10
    std::atomic<uint32_t> alive{0};                     // +0x14
    uint32_t next_free = 0xFFFFFFFFu;                   // +0x18
};
static_assert(sizeof(XAudioProxyObject) == 32);
static_assert(offsetof(XAudioProxyObject, lpVtbl) == 0);

// Box64 onebridge_t Win64 -> native ARM64 COM trampoline for XAudio2.7 / XAudio2.9 & Voices.
// Prevents x86_64 guest code from jumping directly into raw AArch64 vtable function pointers.
class XAudio2ComBridge {
public:
    static constexpr size_t kMaxSlots = 29; // IXAudio2SourceVoice has 29 vtable slots
    static constexpr size_t kMaxProxies = 4096;
    static constexpr uint32_t kInvalidSlot = 0xFFFFFFFFu;

    static XAudio2ComBridge& global() {
        static XAudio2ComBridge inst;
        return inst;
    }

    XAudio2ComBridge() : pool_(std::make_unique<XAudioProxyObject[]>(kMaxProxies)) {
        pool_begin_ = reinterpret_cast<uintptr_t>(pool_.get());
        pool_end_ = pool_begin_ + kMaxProxies * sizeof(XAudioProxyObject);
        init_vtables(std::make_index_sequence<kMaxSlots>{});
    }

    XAudioProxyObject* wrap(void* native_obj, XAudioIfaceId iface) {
        if (!native_obj) return nullptr;
        std::lock_guard<std::mutex> lk(mu_);
        uint32_t idx = kInvalidSlot;
        if (free_head_ != kInvalidSlot) {
            idx = free_head_;
            free_head_ = pool_[idx].next_free;
        } else if (bump_next_ < kMaxProxies) {
            idx = static_cast<uint32_t>(bump_next_++);
        } else {
            return nullptr;
        }
        auto* p = &pool_[idx];
        p->lpVtbl = vtable_ptrs_.data();
        p->native_obj = native_obj;
        p->iface = iface;
        p->next_free = kInvalidSlot;
        p->alive.store(1u, std::memory_order_release);
        active_count_.fetch_add(1, std::memory_order_relaxed);
        return p;
    }

    inline XAudioProxyObject* find_proxy(uintptr_t addr) const noexcept {
        if (addr < pool_begin_ || addr >= pool_end_) return nullptr;
        if (((addr - pool_begin_) & (sizeof(XAudioProxyObject) - 1)) != 0) return nullptr;
        auto* p = reinterpret_cast<XAudioProxyObject*>(addr);
        return p->alive.load(std::memory_order_acquire) ? p : nullptr;
    }

    void destroy_proxy(XAudioProxyObject* proxy) {
        if (!proxy) return;
        const uintptr_t addr = reinterpret_cast<uintptr_t>(proxy);
        if (addr < pool_begin_ || addr >= pool_end_) return;
        if (((addr - pool_begin_) & (sizeof(XAudioProxyObject) - 1)) != 0) return;
        std::lock_guard<std::mutex> lk(mu_);
        if (proxy->alive.exchange(0u, std::memory_order_acq_rel) == 0u) return;
        proxy->native_obj = nullptr;
        proxy->next_free = free_head_;
        free_head_ = static_cast<uint32_t>(proxy - pool_.get());
        active_count_.fetch_sub(1, std::memory_order_relaxed);
    }

    void clear() {
        std::lock_guard<std::mutex> lk(mu_);
        for (size_t i = 0; i < bump_next_; ++i) {
            pool_[i].alive.store(0u, std::memory_order_release);
            pool_[i].native_obj = nullptr;
            pool_[i].next_free = kInvalidSlot;
        }
        bump_next_ = 0;
        free_head_ = kInvalidSlot;
        active_count_.store(0, std::memory_order_relaxed);
    }

    size_t active_proxy_count() const noexcept { return active_count_.load(std::memory_order_relaxed); }

    template <size_t Slot>
    static void dispatch_slot(x64emu_t* emu) {
        if (!emu) return;
        uint64_t& rax = cpu::emu_reg_rax(emu);
        const uint64_t rcx = cpu::emu_reg_rcx(emu);
        const uint64_t rdx = cpu::emu_reg_rdx(emu);
        const uint64_t r8  = cpu::emu_reg_r8(emu);
        const uint64_t r9  = cpu::emu_reg_r9(emu);
        const auto* sp = reinterpret_cast<const uint64_t*>(cpu::emu_reg_rsp(emu));

        auto& self = global();
        auto* proxy = self.find_proxy(static_cast<uintptr_t>(rcx));
        if (!proxy || !proxy->native_obj) {
            rax = 0x80070057ULL; // E_INVALIDARG
            return;
        }

        const auto* native_vtbl = *reinterpret_cast<void* const* const*>(proxy->native_obj);
        if (!native_vtbl || !native_vtbl[Slot]) {
            rax = 0x80004001ULL;
            return;
        }

        // Handle XMM float argument slots explicitly (Win64 ABI puts float arg1 in XMM1)
        if constexpr (Slot == 12) { // IXAudio2Voice::SetVolume(self, float vol, UINT32 opSet)
            if (proxy->iface == XAudioIfaceId::MasteringOrSubmixVoice ||
                proxy->iface == XAudioIfaceId::SourceVoice) {
                using SetVolFn = int32_t (*)(void*, float, uint32_t);
                const float vol = cpu::emu_xmm_f32(emu, 1);
                rax = static_cast<uint64_t>(static_cast<uint32_t>(
                    reinterpret_cast<SetVolFn>(native_vtbl[Slot])(
                        proxy->native_obj, vol, static_cast<uint32_t>(r8))));
                return;
            }
        }
        if constexpr (Slot == 26) { // IXAudio2SourceVoice::SetFrequencyRatio(self, float ratio, UINT32 opSet)
            if (proxy->iface == XAudioIfaceId::SourceVoice) {
                using SetFreqFn = int32_t (*)(void*, float, uint32_t);
                const float ratio = cpu::emu_xmm_f32(emu, 1);
                rax = static_cast<uint64_t>(static_cast<uint32_t>(
                    reinterpret_cast<SetFreqFn>(native_vtbl[Slot])(
                        proxy->native_obj, ratio, static_cast<uint32_t>(r8))));
                return;
            }
        }

        // Forward generic integer/pointer args (up to 7 args after `this`)
        const uint64_t a4 = sp ? sp[5] : 0;
        const uint64_t a5 = sp ? sp[6] : 0;
        const uint64_t a6 = sp ? sp[7] : 0;
        const uint64_t a7 = sp ? sp[8] : 0;
        using NativeFn = uint64_t (*)(void*, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
        const uint64_t ret = reinterpret_cast<NativeFn>(native_vtbl[Slot])(
            proxy->native_obj, rdx, r8, r9, a4, a5, a6, a7);
        rax = ret;

        // Wrap newly created voice out-parameters into Win64 onebridge_t proxies
        const bool ok = (static_cast<int32_t>(ret) >= 0);
        if constexpr (Slot == 0) { // QueryInterface -> keep returning guest proxy
            if (ok && r8) {
                *reinterpret_cast<void**>(r8) = proxy;
            }
        } else if constexpr (Slot == 2) { // Release
            if ((proxy->iface == XAudioIfaceId::IXAudio2 || proxy->iface == XAudioIfaceId::IXAudio2_7) &&
                static_cast<uint32_t>(ret) == 0) {
                self.destroy_proxy(proxy);
            }
        } else if constexpr (Slot == 5 || Slot == 8) { // CreateSourceVoice (2.9 slot 5, 2.7 slot 8)
            const bool is_src = (Slot == 5 && proxy->iface == XAudioIfaceId::IXAudio2) ||
                                (Slot == 8 && proxy->iface == XAudioIfaceId::IXAudio2_7);
            if (is_src && ok && rdx) {
                auto** pp = reinterpret_cast<void**>(rdx);
                if (*pp) *pp = self.wrap(*pp, XAudioIfaceId::SourceVoice);
            }
        } else if constexpr (Slot == 6 || Slot == 7 || Slot == 9 || Slot == 10) {
            const bool is_voice =
                ((Slot == 6 || Slot == 7) && proxy->iface == XAudioIfaceId::IXAudio2) ||
                ((Slot == 9 || Slot == 10) && proxy->iface == XAudioIfaceId::IXAudio2_7);
            if (is_voice && ok && rdx) {
                auto** pp = reinterpret_cast<void**>(rdx);
                if (*pp) *pp = self.wrap(*pp, XAudioIfaceId::MasteringOrSubmixVoice);
            }
        } else if constexpr (Slot == 18) { // IXAudio2Voice::DestroyVoice
            if (proxy->iface == XAudioIfaceId::MasteringOrSubmixVoice ||
                proxy->iface == XAudioIfaceId::SourceVoice) {
                self.destroy_proxy(proxy);
            }
        }
    }

private:
    template <size_t... Is>
    void init_vtables(std::index_sequence<Is...>) {
        ((stubs_[Is] = cpu::NativeBridgeStub{},
          stubs_[Is].wrapper_ptr = reinterpret_cast<uint64_t>(&cpu::mobiro_native_thunk_wrapper),
          stubs_[Is].thunk_ptr = reinterpret_cast<uint64_t>(&dispatch_slot<Is>),
          vtable_ptrs_[Is] = reinterpret_cast<uintptr_t>(&stubs_[Is])), ...);
    }

    mutable std::mutex mu_;
    std::array<cpu::NativeBridgeStub, kMaxSlots> stubs_{};
    std::array<uintptr_t, kMaxSlots> vtable_ptrs_{};
    std::unique_ptr<XAudioProxyObject[]> pool_;
    uintptr_t pool_begin_ = 0;
    uintptr_t pool_end_ = 0;
    size_t bump_next_ = 0;
    uint32_t free_head_ = kInvalidSlot;
    std::atomic<size_t> active_count_{0};
};

} // namespace mobiro::audio
