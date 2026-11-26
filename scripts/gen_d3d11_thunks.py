#!/usr/bin/env python3
"""Generates binary-accurate Win64 -> ARM64 COM vtable slot metadata for DXGI & D3D11.

Zero external dependencies. Run from repo root:
    python scripts/gen_d3d11_thunks.py
Output:
    app/src/main/cpp/gfx/d3d11_com_thunks_gen.hpp
"""
from pathlib import Path

# Exact Win64 COM vtable slot counts & key named slot indices (verified against Windows SDK d3d11.h / dxgi.h)
INTERFACES = [
    ("Unknown", 3, {
        "QueryInterface": (0, 3, False),
        "AddRef": (1, 1, False),
        "Release": (2, 1, False),
    }),
    ("DXGIAdapter1", 11, {
        "QueryInterface": (0, 3, False),
        "AddRef": (1, 1, False),
        "Release": (2, 1, False),
        "EnumOutputs": (7, 3, False),
        "GetDesc": (8, 2, False),
        "CheckInterfaceSupport": (9, 3, False),
        "GetDesc1": (10, 2, False),
    }),
    ("DXGIFactory1", 14, {
        "QueryInterface": (0, 3, False),
        "AddRef": (1, 1, False),
        "Release": (2, 1, False),
        "EnumAdapters": (7, 3, False),
        "MakeWindowAssociation": (8, 3, False),
        "GetWindowAssociation": (9, 2, False),
        "CreateSwapChain": (10, 4, False),
        "CreateSoftwareAdapter": (11, 3, False),
        "EnumAdapters1": (12, 3, False),
        "IsCurrent": (13, 1, False),
    }),
    ("DXGISwapChain", 18, {
        "QueryInterface": (0, 3, False),
        "AddRef": (1, 1, False),
        "Release": (2, 1, False),
        "Present": (8, 3, False),
        "GetBuffer": (9, 4, False),
        "SetFullscreenState": (10, 3, False),
        "GetFullscreenState": (11, 3, False),
        "GetDesc": (12, 2, False),
        "ResizeBuffers": (13, 6, False),
        "ResizeTarget": (14, 2, False),
    }),
    ("D3D11Device", 43, {
        "QueryInterface": (0, 3, False),
        "AddRef": (1, 1, False),
        "Release": (2, 1, False),
        "CreateBuffer": (3, 4, False),
        "CreateTexture1D": (4, 4, False),
        "CreateTexture2D": (5, 4, False),
        "CreateTexture3D": (6, 4, False),
        "CreateShaderResourceView": (7, 4, False),
        "CreateUnorderedAccessView": (8, 4, False),
        "CreateRenderTargetView": (9, 4, False),
        "CreateDepthStencilView": (10, 4, False),
        "CreateInputLayout": (11, 6, False),
        "CreateVertexShader": (12, 5, False),
        "CreateGeometryShader": (13, 5, False),
        "CreatePixelShader": (15, 5, False),
        "CreateHullShader": (16, 5, False),
        "CreateDomainShader": (17, 5, False),
        "CreateComputeShader": (18, 5, False),
        "CreateBlendState": (20, 3, False),
        "CreateDepthStencilState": (21, 3, False),
        "CreateRasterizerState": (22, 3, False),
        "CreateSamplerState": (23, 3, False),
        "CreateQuery": (24, 3, False),
        "CreateDeferredContext": (27, 3, False),
        "CheckFormatSupport": (29, 3, False),
        "CheckMultisampleQualityLevels": (30, 4, False),
        "CheckFeatureSupport": (33, 4, False),
        "GetFeatureLevel": (37, 1, False),
        "GetCreationFlags": (38, 1, False),
        "GetDeviceRemovedReason": (39, 1, False),
        "GetImmediateContext": (40, 2, False),
    }),
    ("D3D11DeviceContext", 115, {
        "QueryInterface": (0, 3, False),
        "AddRef": (1, 1, False),
        "Release": (2, 1, False),
        "GetDevice": (3, 2, True),
        "VSSetConstantBuffers": (7, 4, True),
        "PSSetShaderResources": (8, 4, True),
        "PSSetShader": (9, 4, True),
        "PSSetSamplers": (10, 4, True),
        "VSSetShader": (11, 4, True),
        "DrawIndexed": (12, 4, True),
        "Draw": (13, 3, True),
        "Map": (14, 6, False),
        "Unmap": (15, 3, True),
        "PSSetConstantBuffers": (16, 4, True),
        "IASetInputLayout": (17, 2, True),
        "IASetVertexBuffers": (18, 6, True),
        "IASetIndexBuffer": (19, 4, True),
        "DrawIndexedInstanced": (20, 6, True),
        "DrawInstanced": (21, 5, True),
        "GSSetConstantBuffers": (22, 4, True),
        "GSSetShader": (23, 4, True),
        "IASetPrimitiveTopology": (24, 2, True),
        "VSSetShaderResources": (25, 4, True),
        "VSSetSamplers": (26, 4, True),
        "OMSetRenderTargets": (33, 4, True),
        "OMSetBlendState": (35, 4, True),
        "OMSetDepthStencilState": (36, 3, True),
        "Dispatch": (41, 4, True),
        "RSSetState": (43, 2, True),
        "RSSetViewports": (44, 3, True),
        "RSSetScissorRects": (45, 3, True),
        "CopySubresourceRegion": (46, 9, True),
        "CopyResource": (47, 3, True),
        "UpdateSubresource": (48, 7, True),
        "ClearRenderTargetView": (50, 3, True),
        "ClearDepthStencilView": (53, 5, True),
        "GenerateMips": (54, 2, True),
        "ResolveSubresource": (57, 6, True),
        "CSSetShaderResources": (67, 4, True),
        "CSSetUnorderedAccessViews": (68, 5, True),
        "CSSetShader": (69, 4, True),
        "CSSetSamplers": (70, 4, True),
        "CSSetConstantBuffers": (71, 4, True),
        "ClearState": (110, 1, True),
        "Flush": (111, 1, True),
    }),
]


def main() -> None:
    out_path = Path("app/src/main/cpp/gfx/d3d11_com_thunks_gen.hpp")
    lines = [
        "#pragma once",
        "// AUTO-GENERATED by scripts/gen_d3d11_thunks.py — do not hand-edit.",
        "// Binary-accurate Win64 DXGI & D3D11 COM vtable slot counts and key method indices.",
        "",
        "#include <cstddef>",
        "#include <cstdint>",
        "",
        "namespace mobiro::gfx::d3d11_abi {",
        "",
        "enum class ComIfaceId : uint32_t {",
    ]
    for idx, (name, _, _) in enumerate(INTERFACES):
        lines.append(f"    {name} = {idx},")
    lines.append(f"    Count = {len(INTERFACES)}")
    lines.append("};")
    lines.append("")
    lines.append("struct ComMethodMeta {")
    lines.append("    uint32_t slot;")
    lines.append("    uint8_t arg_count;")
    lines.append("    bool is_void;")
    lines.append("};")
    lines.append("")
    for name, slot_count, methods in INTERFACES:
        lines.append(f"namespace {name}Slots {{")
        lines.append(f"inline constexpr size_t kSlotCount = {slot_count};")
        for mname, (slot, argc, is_void) in methods.items():
            lines.append(f"inline constexpr uint32_t k{mname} = {slot};")
            lines.append(
                f"inline constexpr ComMethodMeta kMeta_{mname} = {{{slot}, {argc}, {'true' if is_void else 'false'}}};"
            )
        lines.append(f"}} // namespace {name}Slots")
        lines.append("")

    lines.append("inline constexpr size_t slot_count_for(ComIfaceId id) {")
    lines.append("    switch (id) {")
    for name, slot_count, _ in INTERFACES:
        lines.append(f"        case ComIfaceId::{name}: return {slot_count};")
    lines.append("        default: return 3;")
    lines.append("    }")
    lines.append("}")
    lines.append("")
    lines.append("} // namespace mobiro::gfx::d3d11_abi")
    lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    print(f"Generated {out_path} ({len(INTERFACES)} COM interfaces, {sum(s for _, s, _ in INTERFACES)} total slots).")


if __name__ == "__main__":
    main()
