// Pure C11 shim insulating Mobiro's C++20 runtime from upstream Box64 internal C headers.
#include "box64context.h"
#include "box64cpu.h"
#include "custommem.h"
#include "debug.h"
#include "env.h"
#include "hostext.h"
#include "sysinfo.h"
#include "x64emu.h"
#include "emu/x64emu_private.h"

#include <android/log.h>
#include <inttypes.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

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

void mobiro_box64_request_quit(x64emu_t* emu) {
    if (emu) emu->quit = 1;
}

// Native Box64 exit bridge (`0xCC 'S' 'C' 0ULL`): when a guest function returns here,
// Box64's ARM64 Dynarec and x64Int3 set `emu->quit = 1` and cleanly return control to C.
static const uint8_t g_box64_exit_stub[32] __attribute__((aligned(32))) = {
    0xCC, 'S', 'C',
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0xC3
};

extern FILE* ftrace;

static pthread_once_t g_box64_ctx_once = PTHREAD_ONCE_INIT;

static void mobiro_init_box64_context_once(void) {
    if (!my_context) {
        // Mirror upstream Box64 core.c::initialize() prerequisites since main.c.o is excluded
        const char* trace_path = getenv("BOX64_TRACE_FILE");
        if (trace_path && trace_path[0]) {
            ftrace = fopen(trace_path, "w");
        }
        if (!ftrace) ftrace = stderr;
        setvbuf(ftrace, NULL, _IONBF, 0);
        box64_pagesize = (uintptr_t)sysconf(_SC_PAGESIZE);
        if (!box64_pagesize) box64_pagesize = 4096;
        LoadEnvVariables();
        InitializeSystemInfo();
#ifdef DYNAREC
        DetectHostCpuFeatures();
#endif
        my_context = NewBox64Context(0);
        if (my_context) {
            loadProtectionFromMap();
        }
        fprintf(ftrace, "[mobiro] Box64 context ready (pagesize=%zu, dynarec=%d, ctx=%p, exit_bridge=0x%" PRIxPTR ")\n",
                (size_t)box64_pagesize, BOX64ENV(dynarec), (void*)my_context,
                my_context ? my_context->exit_bridge : (uintptr_t)0);
        __android_log_print(ANDROID_LOG_WARN, "Mobiro",
                            "Box64 context ready (pagesize=%zu, dynarec=%d, ctx=%p)",
                            (size_t)box64_pagesize, BOX64ENV(dynarec), (void*)my_context);
    }
}

void mobiro_box64_ensure_init(void) {
    pthread_once(&g_box64_ctx_once, mobiro_init_box64_context_once);
}

void mobiro_box64_set_prot(uintptr_t addr, size_t size, int mobiro_prot) {
    if (!addr || !size) return;
    pthread_once(&g_box64_ctx_once, mobiro_init_box64_context_once);
    if (!my_context) return;
    const uintptr_t ps = box64_pagesize ? box64_pagesize : 4096;
    const uintptr_t start = addr & ~(ps - 1);
    const size_t len = ((addr - start) + size + ps - 1) & ~(ps - 1);
    uint32_t p = 0;
    if (mobiro_prot & 1) p |= PROT_READ;
    if (mobiro_prot & 2) p |= PROT_WRITE;
    if (mobiro_prot & 4) p |= PROT_EXEC;
    if (p) {
        setProtection(start, len, p);
    } else {
        freeProtection(start, len);
    }
}

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
    pthread_once(&g_box64_ctx_once, mobiro_init_box64_context_once);
    if (!my_context) return 0;

    const uintptr_t stack_low = stack_base - (uintptr_t)stack_size;
    x64emu_t* emu = NewX64Emu(my_context, fn_va, stack_low, (int)stack_size, 0);
    if (!emu) return 0;
    SetupX64Emu(emu, NULL);
    ResetFlags(emu);

    uint64_t rsp = ((uint64_t)stack_base - 0x100ULL) & ~0xFULL;
    rsp -= 8;
    const uint64_t exit_addr = my_context->exit_bridge
        ? (uint64_t)my_context->exit_bridge
        : (uint64_t)(uintptr_t)g_box64_exit_stub;
    memcpy((void*)(uintptr_t)rsp, &exit_addr, 8);

    emu->regs[_SP].q[0] = rsp;
    emu->regs[_CX].q[0] = rcx;
    emu->regs[_DX].q[0] = rdx;
    emu->regs[_R8].q[0] = r8;
    emu->ip.q[0] = (uint64_t)fn_va;
    emu->segs_offs[_GS] = teb_va;

    x64emu_t* prev_emu = thread_get_emu_no_create();
    thread_set_emu(emu);
    const uint32_t fn_prot = getProtection(fn_va);
    if (ftrace) {
        fprintf(ftrace, "[mobiro] call_fn enter fn=0x%" PRIxPTR " (prot=0x%x) rcx=0x%" PRIx64 " rdx=0x%" PRIx64 " rsp=0x%" PRIx64 " teb=0x%" PRIxPTR "\n",
                fn_va, fn_prot, rcx, rdx, rsp, teb_va);
    }
#ifdef DYNAREC
    DynaRun(emu);
#else
    Run(emu, 0);
#endif
    if (ftrace) {
        fprintf(ftrace, "[mobiro] call_fn exit fn=0x%" PRIxPTR " rax=0x%" PRIx64 " rip=0x%" PRIx64 " quit=%d\n",
                fn_va, emu->regs[_AX].q[0], emu->ip.q[0], emu->quit);
    }

    if (out_rax) *out_rax = emu->regs[_AX].q[0];
    if (prev_emu) {
        thread_set_emu(prev_emu);
    } else {
        thread_forget_emu();
    }
    FreeX64Emu(&emu);
    return 1;
}
