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

    // Invokes a COM vtable slot directly from a Win64 x64emu_t register + stack frame
    template <size_t Slot>
    static void dispatch_slot(x64emu_t* emu) {
        if (!emu) return;
#ifdef MOBIRO_HAVE_BOX64
        uint64_t& rax = emu->regs[_AX].q[0];
        const uint64_t rcx = emu->regs[_CX].q[0];
        const uint64_t rdx = emu->regs[_DX].q[0];
        const uint64_t r8  = emu->regs[_R8].q[0];
        const uint64_t r9  = emu->regs[_R9].q[0];
        const auto* sp = reinterpret_cast<const uint64_t*>(emu->regs[_SP].q[0]);
#else
        uint64_t& rax = emu->rax;
        const uint64_t rcx = emu->rcx;
        const uint64_t rdx = emu->rdx;
        const uint64_t r8  = emu->r8;
        const uint64_t r9  = emu->r9;
        const auto* sp = reinterpret_cast<const uint64_t*>(emu->rsp);
#endif
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

        const uint64_t a1 = self.unwrap_arg(rdx);
        const uint64_t a2 = self.unwrap_arg(r8);
        const uint64_t a3 = self.unwrap_arg(r9);
        const uint64_t a4 = sp ? self.unwrap_arg(sp[5]) : 0;
        const uint64_t a5 = sp ? self.unwrap_arg(sp[6]) : 0;
        const uint64_t a6 = sp ? self.unwrap_arg(sp[7]) : 0;
        const uint64_t a7 = sp ? self.unwrap_arg(sp[8]) : 0;
        const uint64_t a8 = sp ? self.unwrap_arg(sp[9]) : 0;
        const uint64_t a9 = sp ? self.unwrap_arg(sp[10]) : 0;

        // Forward up to 10 pointer/integer arguments cleanly to native AAPCS64/host COM method.
        // shortcut: methods taking floating-point registers (e.g. RSSetViewports uses pointer, only
        // ClearDepthStencilView/OMSetBlendState take scalar floats) need XMM0..3 forwarding when Box64 links.
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
