#!/usr/bin/env bash
set -euo pipefail

# Cross-compiles upstream open-source DXVK (dxvk-native D3D11/DXGI -> Vulkan) for Android arm64-v8a.
# Output: app/src/main/jniLibs/arm64-v8a/libdxvk_{d3d11,dxgi}.so (zero x86 emulation of DXVK).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DXVK_SRC="$ROOT_DIR/third_party/dxvk"
BUILD_DIR="$ROOT_DIR/third_party/build/dxvk-arm64"
JNI_OUT="$ROOT_DIR/app/src/main/jniLibs/arm64-v8a"

if [ ! -f "$DXVK_SRC/meson.build" ]; then
  echo "[Mobiro] DXVK source missing; run ./scripts/fetch_third_party.sh first." >&2
  exit 1
fi

NDK="${ANDROID_NDK_HOME:-${ANDROID_HOME:-}/ndk/27.2.12479018}"
HOST_TAG="linux-x86_64"
BIN="$NDK/toolchains/llvm/prebuilt/$HOST_TAG/bin"
if [ ! -x "$BIN/aarch64-linux-android31-clang++" ]; then
  echo "[Mobiro] Android NDK LLVM toolchain not found at $BIN" >&2
  exit 1
fi

CROSS_FILE="$BUILD_DIR/dxvk-android-aarch64.cross"
mkdir -p "$BUILD_DIR" "$JNI_OUT"
python3 "$ROOT_DIR/scripts/patch_dxvk_android_wsi.py" "$DXVK_SRC"
cat > "$CROSS_FILE" <<EOF
[binaries]
c = '$BIN/aarch64-linux-android31-clang'
cpp = '$BIN/aarch64-linux-android31-clang++'
ar = '$BIN/llvm-ar'
strip = '$BIN/llvm-strip'
pkg-config = 'false'

[host_machine]
system = 'android'
cpu_family = 'aarch64'
cpu = 'armv8'
endian = 'little'
EOF

SETUP_FLAGS=()
if [ -d "$BUILD_DIR/out/meson-private" ]; then
  SETUP_FLAGS+=(--wipe)
fi
meson setup "$BUILD_DIR/out" "$DXVK_SRC" "${SETUP_FLAGS[@]}" \
  --cross-file "$CROSS_FILE" \
  -Dbuildtype=release \
  -Denable_d3d8=false \
  -Denable_d3d9=false \
  -Denable_d3d10=false \
  -Denable_d3d11=true \
  -Denable_dxgi=true \
  -Dnative_glfw=disabled \
  -Dnative_sdl2=disabled \
  -Dnative_sdl3=disabled \
  -Dnative_xcb=disabled \
  -Dnative_wayland=disabled

ninja -C "$BUILD_DIR/out" src/dxgi/libdxvk_dxgi.so src/d3d11/libdxvk_d3d11.so
cp -f "$BUILD_DIR/out/src/dxgi/libdxvk_dxgi.so" "$JNI_OUT/"
cp -f "$BUILD_DIR/out/src/d3d11/libdxvk_d3d11.so" "$JNI_OUT/"
"$BIN/llvm-strip" --strip-unneeded "$JNI_OUT/libdxvk_dxgi.so" "$JNI_OUT/libdxvk_d3d11.so"

echo "[Mobiro] Native AArch64 DXVK staged at $JNI_OUT"
