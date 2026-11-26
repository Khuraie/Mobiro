#pragma once

#include "box64_bridge.hpp"
#include "pe_loader.hpp"
#include "win64_teb.hpp"

#include <cstdint>
#include <cstring>
#include <string>

namespace mobiro::cpu {

struct ExecutionResult {
    bool ok = false;
    uint64_t exit_rax = 0;
    size_t steps_executed = 0;
    size_t thunks_dispatched = 0;
    std::string error;
};

// Dispatches loaded Win64 PE64 entry points with canonical TEB/GS and stack setup.
// Uses embedded Box64 Dynarec when MOBIRO_HAVE_BOX64 is enabled; otherwise provides
// a minimal x86_64 smoke-test dispatcher supporting real IAT calls & GS:[disp32] reads
// so the full PE64 -> relocation -> IAT stub -> Win64 ABI -> native thunk path is testable on CI.
class GuestExecutor {
public:
    static constexpr uint64_t kReturnSentinel = 0x0000DEAD0000C0DEULL;

    static ExecutionResult run_entry(const LoadedPeImage& img,
                                     const Win64ThreadEnv& tenv,
                                     Box64Bridge& /*bridge*/,
                                     size_t max_steps = 4096) {
        ExecutionResult res;
        if (!img.ok || !tenv.teb || !tenv.stack_base) {
            res.error = "Invalid PE image or Win64ThreadEnv.";
            return res;
        }

        x64emu_t emu{};
        // Win64 ABI requires RSP % 16 == 8 at function entry (return address pushed at [RSP])
        uint64_t rsp = (tenv.stack_base - 0x100) & ~uint64_t(0xF);
        rsp -= 8;
        uint64_t sentinel = kReturnSentinel;
        std::memcpy(reinterpret_cast<void*>(rsp), &sentinel, 8);

#ifdef MOBIRO_HAVE_BOX64
        emu.regs[_SP].q[0] = rsp;
        emu.ip.q[0] = img.entry_point;
        emu.segs_offs[_GS] = reinterpret_cast<uintptr_t>(tenv.teb);
        // shortcut: full Box64 Run() loop integration completes once arm64-v8a libbox64_core.a is linked.
        res.error = "Box64 Run() entrypoint wired; link arm64-v8a libbox64_core.a to execute full game.";
        return res;
#else
        emu.rsp = rsp;
        emu.rip = img.entry_point;
        emu.gs_base = reinterpret_cast<uint64_t>(tenv.teb);
        return run_smoke_interpreter(emu, max_steps);
#endif
    }

private:
#ifndef MOBIRO_HAVE_BOX64
    static uint64_t& reg_by_id(x64emu_t& e, uint8_t id) {
        switch (id & 0xF) {
            case 0: return e.rax;
            case 1: return e.rcx;
            case 2: return e.rdx;
            case 3: return e.rbx;
            case 4: return e.rsp;
            case 5: return e.rbp;
            case 6: return e.rsi;
            case 7: return e.rdi;
            case 8: return e.r8;
            case 9: return e.r9;
            case 10: return e.r10;
            default: return e.r11;
        }
    }

    // Decodes the exact x86_64 instructions emitted by Win64 prologues/thunks in unit tests:
    //   - 48 83 EC imm8 / 48 83 C4 imm8        (SUB/ADD RSP, imm8)
    //   - 48/49 B8..BF imm64                   (MOV r64, imm64)
    //   - 48 89 C1 / 48 89 C2 / 48 89 C3       (MOV RCX/RDX/RBX, RAX)
    //   - 48 01 D8                             (ADD RAX, RBX)
    //   - 65 48 8B 04 25 disp32                (MOV RAX, GS:[disp32])
    //   - FF 15 disp32                         (CALL QWORD PTR [RIP + disp32] -> IAT stub)
    //   - C3                                   (RET)
    static ExecutionResult run_smoke_interpreter(x64emu_t& emu, size_t max_steps) {
        ExecutionResult res;
        for (size_t step = 0; step < max_steps; ++step) {
            if (emu.rip == kReturnSentinel) {
                res.ok = true;
                res.exit_rax = emu.rax;
                res.steps_executed = step;
                return res;
            }
            const auto* pc = reinterpret_cast<const uint8_t*>(emu.rip);
            const uint8_t b0 = pc[0];

            // NativeBridgeStub trap (0xCC 'M' 'B' <8-byte thunk_ptr> 0xC3)
            if (b0 == 0xCC && pc[1] == 'M' && pc[2] == 'B') {
                const auto* stub = reinterpret_cast<const NativeBridgeStub*>(pc);
                auto fn = reinterpret_cast<NativeThunkFn>(stub->thunk_ptr);
                if (!fn) {
                    res.error = "Null native thunk pointer in bridge stub.";
                    return res;
                }
                fn(&emu);
                ++res.thunks_dispatched;
                // Execute implicit RET
                uint64_t ret_addr = 0;
                std::memcpy(&ret_addr, reinterpret_cast<const void*>(emu.rsp), 8);
                emu.rsp += 8;
                emu.rip = ret_addr;
                continue;
            }

            // RET (0xC3)
            if (b0 == 0xC3) {
                uint64_t ret_addr = 0;
                std::memcpy(&ret_addr, reinterpret_cast<const void*>(emu.rsp), 8);
                emu.rsp += 8;
                emu.rip = ret_addr;
                continue;
            }

            // CALL QWORD PTR [RIP + disp32] (FF 15 disp32) — standard Win64 IAT call
            if (b0 == 0xFF && pc[1] == 0x15) {
                int32_t disp = 0;
                std::memcpy(&disp, pc + 2, 4);
                const uint64_t next_rip = emu.rip + 6;
                const uint64_t iat_slot = static_cast<uint64_t>(static_cast<int64_t>(next_rip) + disp);
                uint64_t target = 0;
                std::memcpy(&target, reinterpret_cast<const void*>(iat_slot), 8);
                emu.rsp -= 8;
                std::memcpy(reinterpret_cast<void*>(emu.rsp), &next_rip, 8);
                emu.rip = target;
                continue;
            }

            // MOV RAX, GS:[disp32] (65 48 8B 04 25 disp32)
            if (b0 == 0x65 && pc[1] == 0x48 && pc[2] == 0x8B && pc[3] == 0x04 && pc[4] == 0x25) {
                uint32_t off = 0;
                std::memcpy(&off, pc + 5, 4);
                uint64_t val = 0;
                std::memcpy(&val, reinterpret_cast<const void*>(emu.gs_base + off), 8);
                emu.rax = val;
                emu.rip += 9;
                continue;
            }

            // SUB/ADD RSP, imm8 (48 83 EC/C4 imm8)
            if (b0 == 0x48 && pc[1] == 0x83 && (pc[2] == 0xEC || pc[2] == 0xC4)) {
                if (pc[2] == 0xEC) emu.rsp -= pc[3];
                else               emu.rsp += pc[3];
                emu.rip += 4;
                continue;
            }

            // MOV r64, imm64 (48/49 B8..BF imm64)
            if ((b0 == 0x48 || b0 == 0x49) && pc[1] >= 0xB8 && pc[1] <= 0xBF) {
                uint8_t reg_id = static_cast<uint8_t>((pc[1] - 0xB8) + ((b0 == 0x49) ? 8 : 0));
                uint64_t imm = 0;
                std::memcpy(&imm, pc + 2, 8);
                reg_by_id(emu, reg_id) = imm;
                emu.rip += 10;
                continue;
            }

            // MOV RCX/RDX/RBX, RAX (48 89 C1/C2/C3)
            if (b0 == 0x48 && pc[1] == 0x89 && (pc[2] == 0xC1 || pc[2] == 0xC2 || pc[2] == 0xC3)) {
                reg_by_id(emu, static_cast<uint8_t>(pc[2] - 0xC0)) = emu.rax;
                emu.rip += 3;
                continue;
            }

            // ADD RAX, RBX (48 01 D8)
            if (b0 == 0x48 && pc[1] == 0x01 && pc[2] == 0xD8) {
                emu.rax += emu.rbx;
                emu.rip += 3;
                continue;
            }

            res.error = "Unsupported opcode in smoke interpreter at RIP.";
            return res;
        }
        res.error = "Execution step limit exceeded.";
        return res;
    }
#endif
};

} // namespace mobiro::cpu
