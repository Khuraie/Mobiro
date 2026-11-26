#pragma once

#include "d3d11_com_thunks_gen.hpp"
#include "../cpu_mem/box64_bridge.hpp"

#include <array>
#include <cstdint>
#include <functional>
#include <mutex>
#include <unordered_map>
#include <utility>

namespace mobiro::gfx {

// Win64 COM proxy object returned to guest x86_64 code.
// Guest executes `mov rax, [rcx]; call [rax + slot*8]`, hitting a NativeBridgeStub
// (0xCC 'M' 'B' <dispatch_com_slot<Slot>> 0xC3) that bridges straight to native ARM64 DXVK.
struct ComProxyObject {
    const uintptr_t* lpVtbl = nullptr;
    void* native_obj = nullptr;
    d3d11_abi::ComIfaceId iface = d3d11_abi::ComIfaceId::Unknown;
};

using PresentHookFn = std::function<void(void* native_swap_chain, uint32_t sync_interval, uint32_t flags)>;

class D3D11ComBridge {
public:
    static constexpr size_t kMaxSlots = d3d11_abi::D3D11DeviceContextSlots::kSlotCount; // 115

    static D3D11ComBridge& global() {
        static D3D11ComBridge inst;
        return inst;
    }

    D3D11ComBridge() { init_vtables(std::make_index_sequence<kMaxSlots>{}); }

    void set_present_hook(PresentHookFn fn) {
        std::lock_guard<std::mutex> lk(mu_);
        present_hook_ = std::move(fn);
    }

    ComProxyObject* wrap(void* native_obj, d3d11_abi::ComIfaceId iface) {
        if (!native_obj) return nullptr;
        auto* proxy = new ComProxyObject();
        proxy->lpVtbl = vtable_ptrs_.data();
        proxy->native_obj = native_obj;
        proxy->iface = iface;

        std::lock_guard<std::mutex> lk(mu_);
        proxies_[reinterpret_cast<uintptr_t>(proxy)] = proxy;
        return proxy;
    }

    // Safely unwraps a guest pointer if and only if it is a registered ComProxyObject.
    // Never dereferences arbitrary integers or non-proxy guest memory.
    uint64_t unwrap_arg(uint64_t raw) const {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = proxies_.find(static_cast<uintptr_t>(raw));
        return (it != proxies_.end()) ? reinterpret_cast<uint64_t>(it->second->native_obj) : raw;
    }

    ComProxyObject* find_proxy(uintptr_t addr) const {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = proxies_.find(addr);
        return (it != proxies_.end()) ? it->second : nullptr;
    }

    void destroy_proxy(ComProxyObject* proxy) {
        if (!proxy) return;
        std::lock_guard<std::mutex> lk(mu_);
        proxies_.erase(reinterpret_cast<uintptr_t>(proxy));
        delete proxy;
    }

    void clear() {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto& [_, p] : proxies_) delete p;
        proxies_.clear();
        present_hook_ = nullptr;
    }

    size_t active_proxy_count() const {
        std::lock_guard<std::mutex> lk(mu_);
        return proxies_.size();
    }

    // Invokes a COM vtable slot directly from a Win64 x64emu_t register + XMM + stack frame
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
        ComProxyObject* proxy = self.find_proxy(static_cast<uintptr_t>(rcx));
        if (!proxy || !proxy->native_obj) {
            rax = 0x80070057ULL; // E_INVALIDARG
            return;
        }
        if (Slot >= d3d11_abi::slot_count_for(proxy->iface)) {
            rax = 0x80004001ULL; // E_NOTIMPL
            return;
        }

        // Native AArch64 DXVK object layout: first qword points to native vtable array
        const auto* native_vtbl = *reinterpret_cast<void* const* const*>(proxy->native_obj);
        if (!native_vtbl || !native_vtbl[Slot]) {
            rax = 0x80004001ULL;
            return;
        }

        // Intercept IDXGISwapChain::Present (slot 8) for overlay compositing & frame pacing
        if constexpr (Slot == d3d11_abi::DXGISwapChainSlots::kPresent) {
            if (proxy->iface == d3d11_abi::ComIfaceId::DXGISwapChain) {
                PresentHookFn hook;
                {
                    std::lock_guard<std::mutex> lk(self.mu_);
                    hook = self.present_hook_;
                }
                if (hook) {
                    hook(proxy->native_obj, static_cast<uint32_t>(rdx), static_cast<uint32_t>(r8));
                }
            }
        }

        // Handle ID3D11DeviceContext::ClearDepthStencilView (slot 53) scalar float Depth in XMM3
        if constexpr (Slot == d3d11_abi::D3D11DeviceContextSlots::kClearDepthStencilView) {
            if (proxy->iface == d3d11_abi::ComIfaceId::D3D11DeviceContext) {
                using ClearDsvFn = void (*)(void*, void*, uint32_t, float, uint8_t);
                auto fn = reinterpret_cast<ClearDsvFn>(native_vtbl[Slot]);
                void* dsv = reinterpret_cast<void*>(self.unwrap_arg(rdx));
                const uint32_t clear_flags = static_cast<uint32_t>(r8);
                const float depth = cpu::emu_xmm_f32(emu, 3);
                const uint8_t stencil = sp ? static_cast<uint8_t>(sp[5] & 0xFFu) : 0u;
                fn(proxy->native_obj, dsv, clear_flags, depth, stencil);
                rax = 0ULL;
                return;
            }
        }

        const uint64_t a1 = self.unwrap_arg(rdx);
        const uint64_t a2 = self.unwrap_arg(r8);
        const uint64_t a3 = self.unwrap_arg(r9);
        const uint64_t a4 = sp ? self.unwrap_arg(sp[5]) : 0;
        const uint64_t a5 = sp ? self.unwrap_arg(sp[6]) : 0;
        const uint64_t a6 = sp ? self.unwrap_arg(sp[7]) : 0;
        const uint64_t a7 = sp ? self.unwrap_arg(sp[8]) : 0;
        const uint64_t a8 = sp ? self.unwrap_arg(sp[9]) : 0;
        const uint64_t a9 = sp ? self.unwrap_arg(sp[10]) : 0;

        // Forward up to 10 pointer/integer arguments to native AAPCS64/host COM method.
        using NativeFn = uint64_t (*)(void*, uint64_t, uint64_t, uint64_t, uint64_t,
                                      uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
        auto fn = reinterpret_cast<NativeFn>(native_vtbl[Slot]);
        const uint64_t ret = fn(proxy->native_obj, a1, a2, a3, a4, a5, a6, a7, a8, a9);
        rax = ret;

        // Automatically reclaim ComProxyObject when native Release() drops refcount to 0
        if constexpr (Slot == 2) {
            if (static_cast<uint32_t>(ret) == 0) {
                self.destroy_proxy(proxy);
            }
        }
    }

private:
    template <size_t... Is>
    void init_vtables(std::index_sequence<Is...>) {
        ((stubs_[Is] = cpu::NativeBridgeStub{},
          stubs_[Is].thunk_ptr = reinterpret_cast<uint64_t>(&dispatch_slot<Is>),
          vtable_ptrs_[Is] = reinterpret_cast<uintptr_t>(&stubs_[Is])), ...);
    }

    mutable std::mutex mu_;
    std::array<cpu::NativeBridgeStub, kMaxSlots> stubs_{};
    std::array<uintptr_t, kMaxSlots> vtable_ptrs_{};
    std::unordered_map<uintptr_t, ComProxyObject*> proxies_;
    PresentHookFn present_hook_;
};

} // namespace mobiro::gfx
