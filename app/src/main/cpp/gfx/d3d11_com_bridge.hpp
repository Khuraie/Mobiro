#pragma once

#include "d3d11_com_thunks_gen.hpp"
#include "../cpu_mem/box64_bridge.hpp"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <utility>

namespace mobiro::gfx {

// Win64 COM proxy object returned to guest x86_64 code.
// Allocated from a contiguous lock-free slab so hot-path find/unwrap is O(1) with zero mutexes.
struct alignas(32) ComProxyObject {
    const uintptr_t* lpVtbl = nullptr;                            // +0x00: Win64 COM vtable pointer
    void* native_obj = nullptr;                                   // +0x08: native AArch64 DXVK object
    d3d11_abi::ComIfaceId iface = d3d11_abi::ComIfaceId::Unknown; // +0x10
    std::atomic<uint32_t> alive{0};                               // +0x14: lock-free validity flag
    uint32_t next_free = 0xFFFFFFFFu;                             // +0x18: intrusive freelist index
};
static_assert(sizeof(ComProxyObject) == 32);
static_assert(offsetof(ComProxyObject, lpVtbl) == 0);

using PresentHookFn = std::function<void(void* native_swap_chain, uint32_t sync_interval, uint32_t flags)>;

class D3D11ComBridge {
public:
    static constexpr size_t kMaxSlots = d3d11_abi::D3D11DeviceContextSlots::kSlotCount; // 115
    // shortcut: fixed 65536-slot proxy slab (~2 MB); grow to segmented slabs if a title exceeds 64k live D3D11 objects.
    static constexpr size_t kMaxProxies = 65536;
    static constexpr uint32_t kInvalidSlot = 0xFFFFFFFFu;

    static D3D11ComBridge& global() {
        static D3D11ComBridge inst;
        return inst;
    }

    D3D11ComBridge() : pool_(std::make_unique<ComProxyObject[]>(kMaxProxies)) {
        pool_begin_ = reinterpret_cast<uintptr_t>(pool_.get());
        pool_end_ = pool_begin_ + kMaxProxies * sizeof(ComProxyObject);
        init_vtables(std::make_index_sequence<kMaxSlots>{});
    }

    void set_present_hook(PresentHookFn fn) {
        std::lock_guard<std::mutex> lk(mu_);
        has_present_hook_.store(static_cast<bool>(fn), std::memory_order_release);
        present_hook_ = std::move(fn);
    }

    ComProxyObject* wrap(void* native_obj, d3d11_abi::ComIfaceId iface) {
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
        auto* proxy = &pool_[idx];
        proxy->lpVtbl = vtable_ptrs_.data();
        proxy->native_obj = native_obj;
        proxy->iface = iface;
        proxy->next_free = kInvalidSlot;
        proxy->alive.store(1u, std::memory_order_release);
        active_count_.fetch_add(1, std::memory_order_relaxed);
        return proxy;
    }

    // Lock-free O(1) unwrap: checks slab range + 32-byte alignment + atomic alive flag.
    // Never dereferences arbitrary integers or non-proxy guest memory.
    inline uint64_t unwrap_arg(uint64_t raw) const noexcept {
        const uintptr_t addr = static_cast<uintptr_t>(raw);
        if (addr < pool_begin_ || addr >= pool_end_) return raw;
        if (((addr - pool_begin_) & (sizeof(ComProxyObject) - 1)) != 0) return raw;
        const auto* p = reinterpret_cast<const ComProxyObject*>(addr);
        return p->alive.load(std::memory_order_acquire)
                   ? reinterpret_cast<uint64_t>(p->native_obj)
                   : raw;
    }

    inline ComProxyObject* find_proxy(uintptr_t addr) const noexcept {
        if (addr < pool_begin_ || addr >= pool_end_) return nullptr;
        if (((addr - pool_begin_) & (sizeof(ComProxyObject) - 1)) != 0) return nullptr;
        auto* p = reinterpret_cast<ComProxyObject*>(addr);
        return p->alive.load(std::memory_order_acquire) ? p : nullptr;
    }

    void destroy_proxy(ComProxyObject* proxy) {
        if (!proxy) return;
        const uintptr_t addr = reinterpret_cast<uintptr_t>(proxy);
        if (addr < pool_begin_ || addr >= pool_end_) return;
        if (((addr - pool_begin_) & (sizeof(ComProxyObject) - 1)) != 0) return;

        std::lock_guard<std::mutex> lk(mu_);
        if (proxy->alive.exchange(0u, std::memory_order_acq_rel) == 0u) return;
        proxy->native_obj = nullptr;
        const uint32_t idx = static_cast<uint32_t>(proxy - pool_.get());
        proxy->next_free = free_head_;
        free_head_ = idx;
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
        has_present_hook_.store(false, std::memory_order_release);
        present_hook_ = nullptr;
    }

    size_t active_proxy_count() const noexcept {
        return active_count_.load(std::memory_order_relaxed);
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
            if (proxy->iface == d3d11_abi::ComIfaceId::DXGISwapChain &&
                self.has_present_hook_.load(std::memory_order_acquire)) {
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

        uint64_t a1 = self.unwrap_arg(rdx);
        uint64_t a2 = self.unwrap_arg(r8);
        uint64_t a3 = self.unwrap_arg(r9);

        // Fast path for 1..4-arg hot slots: skips 6 stack loads + unwrap checks.
        // Slot 1/2 (IUnknown::AddRef/Release) apply to all COM interfaces; slots 12/13/15/24/44/45/50
        // (DrawIndexed, Draw, Unmap, IASetPrimitiveTopology, RSSetViewports/ScissorRects, ClearRTV)
        // are strictly gated to D3D11DeviceContext so D3D11Device::Create*Shader/CreateQuery & ResizeBuffers keep full dispatch.
        if constexpr (Slot == 1 || Slot == 2) {
            using FastFn = uint64_t (*)(void*);
            auto fn = reinterpret_cast<FastFn>(native_vtbl[Slot]);
            const uint64_t ret = fn(proxy->native_obj);
            rax = ret;
            if constexpr (Slot == 2) {
                if (static_cast<uint32_t>(ret) == 0) {
                    self.destroy_proxy(proxy);
                }
            }
            return;
        } else if constexpr (Slot == 12 || Slot == 13 || Slot == 15 || Slot == 24 ||
                             Slot == 44 || Slot == 45 || Slot == 50) {
            if (proxy->iface == d3d11_abi::ComIfaceId::D3D11DeviceContext) {
                using FastFn = uint64_t (*)(void*, uint64_t, uint64_t, uint64_t);
                auto fn = reinterpret_cast<FastFn>(native_vtbl[Slot]);
                rax = fn(proxy->native_obj, a1, a2, a3);
                return;
            }
        }

        uint64_t a4 = sp ? self.unwrap_arg(sp[5]) : 0;
        uint64_t a5 = sp ? self.unwrap_arg(sp[6]) : 0;
        uint64_t a6 = sp ? self.unwrap_arg(sp[7]) : 0;
        uint64_t a7 = sp ? self.unwrap_arg(sp[8]) : 0;
        uint64_t a8 = sp ? self.unwrap_arg(sp[9]) : 0;
        uint64_t a9 = sp ? self.unwrap_arg(sp[10]) : 0;

        // Zero-heap stack unwrapping for ID3D11DeviceContext methods taking arrays of COM pointers
        // (allocated only on array-bearing slots to avoid 384B memset overhead on every draw call).
        if constexpr (Slot == 7 || Slot == 8 || Slot == 10 || Slot == 16 || Slot == 18 ||
                      Slot == 22 || Slot == 25 || Slot == 26 || Slot == 33 || Slot == 34 ||
                      Slot == 37 || Slot == 59 || Slot == 61 || Slot == 62 || Slot == 63 ||
                      Slot == 65 || Slot == 66 || Slot == 67 || Slot == 68 || Slot == 70 ||
                      Slot == 71) {
            uint64_t tmp_arr0[32];
            uint64_t tmp_arr1[16];
            if (proxy->iface == d3d11_abi::ComIfaceId::D3D11DeviceContext) {
                if constexpr (Slot == 33 || Slot == 37) {
                    // OMSetRenderTargets(NumViews, ppRTVs, pDSV) / SOSetTargets(NumBuffers, ppSOTargets, pOffsets)
                    a2 = self.unwrap_proxy_array(a2, static_cast<uint32_t>(a1), tmp_arr0, 32);
                } else if constexpr (Slot == 34) {
                    // OMSetRenderTargetsAndUnorderedAccessViews
                    a2 = self.unwrap_proxy_array(a2, static_cast<uint32_t>(a1), tmp_arr0, 32);
                    a6 = self.unwrap_proxy_array(a6, static_cast<uint32_t>(a5), tmp_arr1, 16);
                } else {
                    // (this, StartSlot, NumItems, T* const* ppItems, ...)
                    a3 = self.unwrap_proxy_array(a3, static_cast<uint32_t>(a2), tmp_arr0, 32);
                }
            }
            using NativeFn = uint64_t (*)(void*, uint64_t, uint64_t, uint64_t, uint64_t,
                                          uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
            auto fn = reinterpret_cast<NativeFn>(native_vtbl[Slot]);
            const uint64_t ret = fn(proxy->native_obj, a1, a2, a3, a4, a5, a6, a7, a8, a9);
            rax = ret;
            if constexpr (Slot == 7 || Slot == 8 || Slot == 10) {
                const bool hr_ok = (static_cast<int32_t>(ret) >= 0);
                if (proxy->iface == d3d11_abi::ComIfaceId::D3D11Device && hr_ok) {
                    self.wrap_out_ptr(r9, d3d11_abi::ComIfaceId::D3D11ResourceChild);
                } else if constexpr (Slot == 7) {
                    if (proxy->iface == d3d11_abi::ComIfaceId::DXGIFactory1 && hr_ok) {
                        self.wrap_out_ptr(r8, d3d11_abi::ComIfaceId::DXGIAdapter1);
                    } else if (proxy->iface == d3d11_abi::ComIfaceId::DXGIAdapter1 && hr_ok) {
                        self.wrap_out_ptr(r8, d3d11_abi::ComIfaceId::DXGIOutput);
                    }
                } else if constexpr (Slot == 10) {
                    if (proxy->iface == d3d11_abi::ComIfaceId::DXGIFactory1 && hr_ok) {
                        self.wrap_out_ptr(r9, d3d11_abi::ComIfaceId::DXGISwapChain);
                    }
                }
            }
            return;
        }

        // Forward up to 10 pointer/integer arguments to native AAPCS64/host COM method.
        using NativeFn = uint64_t (*)(void*, uint64_t, uint64_t, uint64_t, uint64_t,
                                      uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
        auto fn = reinterpret_cast<NativeFn>(native_vtbl[Slot]);
        const uint64_t ret = fn(proxy->native_obj, a1, a2, a3, a4, a5, a6, a7, a8, a9);
        rax = ret;

        // Auto-wrap newly created/returned native AArch64 COM out-parameters into Win64 ComProxyObjects
        const bool hr_ok = (static_cast<int32_t>(ret) >= 0);
        if constexpr (Slot == 0) {
            // IUnknown::QueryInterface(REFIID riid, void** ppvObject)
            if (hr_ok && r8) {
                self.wrap_out_ptr(r8, classify_iid(reinterpret_cast<const uint8_t*>(rdx)));
            }
        } else if constexpr (Slot == 3) {
            if (proxy->iface == d3d11_abi::ComIfaceId::D3D11Device && hr_ok) {
                self.wrap_out_ptr(r9, d3d11_abi::ComIfaceId::D3D11ResourceChild); // CreateBuffer
            } else if (proxy->iface == d3d11_abi::ComIfaceId::D3D11DeviceContext ||
                       proxy->iface == d3d11_abi::ComIfaceId::D3D11ResourceChild) {
                self.wrap_out_ptr(rdx, d3d11_abi::ComIfaceId::D3D11Device); // GetDevice (void)
            }
        } else if constexpr (Slot >= 4 && Slot <= 10) {
            if (proxy->iface == d3d11_abi::ComIfaceId::D3D11Device && hr_ok) {
                self.wrap_out_ptr(r9, d3d11_abi::ComIfaceId::D3D11ResourceChild); // CreateTexture*/SRV/UAV/RTV/DSV
            } else if constexpr (Slot == 7) {
                if (proxy->iface == d3d11_abi::ComIfaceId::DXGIFactory1 && hr_ok) {
                    self.wrap_out_ptr(r8, d3d11_abi::ComIfaceId::DXGIAdapter1); // EnumAdapters
                } else if (proxy->iface == d3d11_abi::ComIfaceId::DXGIAdapter1 && hr_ok) {
                    self.wrap_out_ptr(r8, d3d11_abi::ComIfaceId::DXGIOutput); // EnumOutputs
                }
            } else if constexpr (Slot == 9) {
                if (proxy->iface == d3d11_abi::ComIfaceId::DXGISwapChain && hr_ok) {
                    self.wrap_out_ptr(r9, d3d11_abi::ComIfaceId::D3D11ResourceChild); // GetBuffer
                }
            } else if constexpr (Slot == 10) {
                if (proxy->iface == d3d11_abi::ComIfaceId::DXGIFactory1 && hr_ok) {
                    self.wrap_out_ptr(r9, d3d11_abi::ComIfaceId::DXGISwapChain); // CreateSwapChain
                }
            }
        } else if constexpr (Slot == 11) {
            if (proxy->iface == d3d11_abi::ComIfaceId::D3D11Device && hr_ok && sp) {
                self.wrap_out_ptr(sp[6], d3d11_abi::ComIfaceId::D3D11ResourceChild); // CreateInputLayout (arg5)
            }
        } else if constexpr (Slot == 12) {
            if (proxy->iface == d3d11_abi::ComIfaceId::DXGIFactory1 && hr_ok) {
                self.wrap_out_ptr(r8, d3d11_abi::ComIfaceId::DXGIAdapter1); // EnumAdapters1
            } else if (proxy->iface == d3d11_abi::ComIfaceId::D3D11Device && hr_ok && sp) {
                self.wrap_out_ptr(sp[5], d3d11_abi::ComIfaceId::D3D11ResourceChild); // CreateVertexShader (arg4)
            }
        } else if constexpr (Slot == 13 || Slot == 15 || Slot == 16 || Slot == 17 || Slot == 18) {
            if (proxy->iface == d3d11_abi::ComIfaceId::D3D11Device && hr_ok && sp) {
                self.wrap_out_ptr(sp[5], d3d11_abi::ComIfaceId::D3D11ResourceChild); // Create*Shader (arg4)
            }
        } else if constexpr (Slot >= 20 && Slot <= 24) {
            if (proxy->iface == d3d11_abi::ComIfaceId::D3D11Device && hr_ok) {
                self.wrap_out_ptr(r8, d3d11_abi::ComIfaceId::D3D11ResourceChild); // Create*State / CreateQuery
            }
        } else if constexpr (Slot == 27) {
            if (proxy->iface == d3d11_abi::ComIfaceId::D3D11Device && hr_ok) {
                self.wrap_out_ptr(r8, d3d11_abi::ComIfaceId::D3D11DeviceContext); // CreateDeferredContext
            }
        } else if constexpr (Slot == 40) {
            if (proxy->iface == d3d11_abi::ComIfaceId::D3D11Device) {
                self.wrap_out_ptr(rdx, d3d11_abi::ComIfaceId::D3D11DeviceContext); // GetImmediateContext (void)
            }
        }

        // Automatically reclaim ComProxyObject when native Release() drops refcount to 0
        if constexpr (Slot == 2) {
            if (static_cast<uint32_t>(ret) == 0) {
                self.destroy_proxy(proxy);
            }
        }
    }

private:
    uint64_t unwrap_proxy_array(uint64_t guest_arr_va, uint32_t count,
                                uint64_t* dst_buf, size_t max_items) const {
        if (!guest_arr_va || count == 0) return guest_arr_va;
        const size_t n = (count < max_items) ? static_cast<size_t>(count) : max_items;
        const auto* src = reinterpret_cast<const uint64_t*>(guest_arr_va);
        for (size_t i = 0; i < n; ++i) {
            dst_buf[i] = unwrap_arg(src[i]);
        }
        return reinterpret_cast<uint64_t>(dst_buf);
    }

    void wrap_out_ptr(uint64_t out_pp_va, d3d11_abi::ComIfaceId iface) {
        if (!out_pp_va) return;
        auto** pp = reinterpret_cast<void**>(out_pp_va);
        if (*pp && !find_proxy(reinterpret_cast<uintptr_t>(*pp))) {
            *pp = wrap(*pp, iface);
        }
    }

    static d3d11_abi::ComIfaceId classify_iid(const uint8_t* iid) {
        if (!iid) return d3d11_abi::ComIfaceId::D3D11ResourceChild;
        uint32_t d1 = 0;
        std::memcpy(&d1, iid, 4);
        // Fast Data1 match for core DXGI / D3D11 IIDs (falls back to D3D11ResourceChild)
        switch (d1) {
            case 0x770AAE78u: // IDXGIFactory1
            case 0x7B7166ECu: // IDXGIFactory
                return d3d11_abi::ComIfaceId::DXGIFactory1;
            case 0x29038F61u: // IDXGIAdapter1
            case 0x2411E7E1u: // IDXGIAdapter
                return d3d11_abi::ComIfaceId::DXGIAdapter1;
            case 0x310D36A0u: // IDXGISwapChain
                return d3d11_abi::ComIfaceId::DXGISwapChain;
            case 0xAE02EEDBu: // IDXGIOutput
                return d3d11_abi::ComIfaceId::DXGIOutput;
            case 0xDB6F6DDBu: // ID3D11Device
                return d3d11_abi::ComIfaceId::D3D11Device;
            case 0xC0BFA96Cu: // ID3D11DeviceContext
                return d3d11_abi::ComIfaceId::D3D11DeviceContext;
            default:
                return d3d11_abi::ComIfaceId::D3D11ResourceChild;
        }
    }
    template <size_t... Is>
    void init_vtables(std::index_sequence<Is...>) {
        ((stubs_[Is] = cpu::NativeBridgeStub{},
          stubs_[Is].wrapper_ptr = reinterpret_cast<uint64_t>(&cpu::mobiro_native_thunk_wrapper),
          stubs_[Is].thunk_ptr = reinterpret_cast<uint64_t>(&dispatch_slot<Is>),
          vtable_ptrs_[Is] = reinterpret_cast<uintptr_t>(&stubs_[Is])), ...);
        cpu::sync_box64_exec_region(stubs_.data(), sizeof(stubs_));
    }

    mutable std::mutex mu_;
    std::array<cpu::NativeBridgeStub, kMaxSlots> stubs_{};
    std::array<uintptr_t, kMaxSlots> vtable_ptrs_{};
    std::unique_ptr<ComProxyObject[]> pool_;
    uintptr_t pool_begin_ = 0;
    uintptr_t pool_end_ = 0;
    size_t bump_next_ = 0;
    uint32_t free_head_ = kInvalidSlot;
    std::atomic<size_t> active_count_{0};
    std::atomic<bool> has_present_hook_{false};
    PresentHookFn present_hook_;
};

} // namespace mobiro::gfx
