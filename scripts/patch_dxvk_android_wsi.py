#!/usr/bin/env python3
"""Idempotently injects Mobiro's Android ANativeWindow (VK_KHR_android_surface) WSI driver into DXVK."""

import pathlib
import shutil
import sys


def insert_after(path: pathlib.Path, anchor: str, addition: str, sentinel: str) -> None:
    text = path.read_text(encoding="utf-8")
    if sentinel in text:
        return
    if anchor not in text:
        raise RuntimeError(f"Anchor not found in {path}: {anchor!r}")
    path.write_text(text.replace(anchor, anchor + addition, 1), encoding="utf-8")


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path-to-dxvk-src>", file=sys.stderr)
        return 1

    root = pathlib.Path(__file__).resolve().parent.parent
    dxvk = pathlib.Path(sys.argv[1]).resolve()
    android_wsi_dir = dxvk / "src" / "wsi" / "android"
    android_wsi_dir.mkdir(parents=True, exist_ok=True)

    for fname in ("wsi_platform_android.h", "wsi_platform_android.cpp"):
        shutil.copy2(root / "patches" / "dxvk" / fname, android_wsi_dir / fname)

    insert_after(
        dxvk / "src" / "wsi" / "wsi_platform.h",
        "#if defined(DXVK_WSI_WAYLAND)\n  extern WsiBootstrap WaylandWSI;\n#endif",
        "\n#if defined(DXVK_WSI_ANDROID)\n  extern WsiBootstrap AndroidWSI;\n#endif",
        "DXVK_WSI_ANDROID",
    )

    insert_after(
        dxvk / "src" / "wsi" / "wsi_platform.cpp",
        "#if defined(DXVK_WSI_WAYLAND)\n    &WaylandWSI,\n#endif",
        "\n#if defined(DXVK_WSI_ANDROID)\n    &AndroidWSI,\n#endif",
        "AndroidWSI",
    )

    insert_after(
        dxvk / "src" / "wsi" / "wsi_platform.cpp",
        "#if defined(DXVK_WSI_WIN32)\n        hint = \"Win32\";",
        "\n#elif defined(DXVK_WSI_ANDROID)\n        hint = \"Android\";",
        'hint = "Android"',
    )

    insert_after(
        dxvk / "src" / "wsi" / "meson.build",
        "  'wayland/wsi_platform_wayland.cpp',\n",
        "  'android/wsi_platform_android.cpp',\n",
        "wsi_platform_android.cpp",
    )

    insert_after(
        dxvk / "src" / "wsi" / "meson.build",
        "wsi_deps = [ dep_displayinfo ]\n",
        "if host_machine.system() == 'android'\n  wsi_deps += [ cpp.find_library('android') ]\nendif\n",
        "find_library('android')",
    )

    insert_after(
        dxvk / "meson.build",
        "  if get_option('native_wayland').allowed()\n    compiler_args += ['-DDXVK_WSI_WAYLAND']\n  endif\n",
        "  if host_machine.system() == 'android'\n    compiler_args += ['-DDXVK_WSI_ANDROID']\n  endif\n",
        "DXVK_WSI_ANDROID",
    )

    # Inject in-swapchain Mobiro TouchOverlayVk HUD renderer into DxvkSwapchainBlitter
    dxvk_core_dir = dxvk / "src" / "dxvk"
    for fname in ("mobiro_touch_hud.h", "mobiro_touch_hud.cpp"):
        shutil.copy2(root / "patches" / "dxvk" / fname, dxvk_core_dir / fname)

    insert_after(
        dxvk_core_dir / "meson.build",
        "    'dxvk_swapchain_blitter.cpp',\n",
        "    'mobiro_touch_hud.cpp',\n",
        "mobiro_touch_hud.cpp",
    )

    insert_after(
        dxvk_core_dir / "dxvk_swapchain_blitter.cpp",
        '#include "dxvk_swapchain_blitter.h"\n',
        '#include "mobiro_touch_hud.h"\n',
        "mobiro_touch_hud.h",
    )

    insert_after(
        dxvk_core_dir / "dxvk_swapchain_blitter.cpp",
        "      if (m_cursorView)\n        renderCursor(ctx, dstView);\n    }",
        "\n    {\n      static MobiroTouchHud s_mobiroTouchHud;\n      s_mobiroTouchHud.render(m_device, ctx, dstView);\n    }",
        "s_mobiroTouchHud",
    )

    print(f"[Mobiro] Patched DXVK Android ANativeWindow WSI + Touch HUD in {dxvk}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
