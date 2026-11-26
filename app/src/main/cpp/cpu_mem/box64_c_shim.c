// Pure C11 shim insulating Mobiro's C++20 runtime from upstream Box64 internal C headers.
#include "box64context.h"
#include "box64cpu.h"
#include "x64emu.h"
#include "emu/x64emu_private.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

uint64_t* mobiro_box64_reg_ptr(x64emu_t* emu, int reg_id) {
    if (!emu || reg_id < 0 || reg_id >= 16) return NULL;
    return &emu->regs[reg_id].q[0];
}

float mobiro_box64_xmm_f32(const x64emu_t* emu, int xmm_idx) {
    if (!emu || xmm_idx < 0 || xmm_idx >= 16) return 0.0f;
    return emu->xmm[xmm_idx].f[0];
}

uintptr_t mobiro_box64_teb(const x64emu_t* emu) {
    return emu ? emu->segs_offs[_GS] : 0;
}

// Native Box64 exit bridge (`0xCC 'S' 'C' 0ULL`): when a guest function returns here,
// Box64's ARM64 Dynarec and x64Int3 set `emu->quit = 1` and cleanly return control to C.
static const uint8_t g_box64_exit_stub[32] __attribute__((aligned(32))) = {
    0xCC, 'S', 'C',
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0xC3
};

int mobiro_box64_call_fn(uintptr_t fn_va,
                         uint64_t rcx,
                         uint64_t rdx,
                         uint64_t r8,
                         uintptr_t stack_base,
                         uint32_t stack_size,
                         uintptr_t teb_va,
                         uint64_t return_sentinel,
                         uint64_t* out_rax) {
    (void)return_sentinel;
    if (!fn_va || !stack_base || stack_size < 0x1000u) return 0;
    if (!my_context) {
        my_context = NewBox64Context(0);
        if (!my_context) return 0;
    }

    const uintptr_t stack_low = stack_base - (uintptr_t)stack_size;
    x64emu_t* emu = NewX64Emu(my_context, fn_va, stack_low, (int)stack_size, 0);
    if (!emu) return 0;

    uint64_t rsp = ((uint64_t)stack_base - 0x100ULL) & ~0xFULL;
    rsp -= 8;
    const uint64_t exit_addr = (uint64_t)(uintptr_t)g_box64_exit_stub;
    memcpy((void*)(uintptr_t)rsp, &exit_addr, 8);

    emu->regs[_SP].q[0] = rsp;
    emu->regs[_CX].q[0] = rcx;
    emu->regs[_DX].q[0] = rdx;
    emu->regs[_R8].q[0] = r8;
    emu->ip.q[0] = (uint64_t)fn_va;
    emu->segs_offs[_GS] = teb_va;

#ifdef DYNAREC
    DynaRun(emu);
#else
    Run(emu, 0);
#endif

    if (out_rax) *out_rax = emu->regs[_AX].q[0];
    FreeX64Emu(&emu);
    return 1;
}
