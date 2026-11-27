#!/usr/bin/env bash
set -euo pipefail

# Cross-compiles open-source Mesa Turnip (Freedreno Adreno Vulkan ICD) for Android arm64-v8a.
# Output: app/src/main/jniLibs/arm64-v8a/libvulkan_freedreno.so (zero proprietary blobs).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MESA_SRC="$ROOT_DIR/third_party/mesa"
BUILD_DIR="$ROOT_DIR/third_party/build/mesa-turnip-arm64"
JNI_OUT="$ROOT_DIR/app/src/main/jniLibs/arm64-v8a"

if [ ! -f "$MESA_SRC/meson.build" ]; then
  echo "[Mobiro] Mesa source missing; run ./scripts/fetch_third_party.sh first." >&2
  exit 1
fi

NDK="${ANDROID_NDK_HOME:-${ANDROID_HOME:-}/ndk/27.2.12479018}"
HOST_TAG="linux-x86_64"
BIN="$NDK/toolchains/llvm/prebuilt/$HOST_TAG/bin"
if [ ! -x "$BIN/aarch64-linux-android31-clang" ]; then
  echo "[Mobiro] Android NDK LLVM toolchain not found at $BIN" >&2
  exit 1
fi

CROSS_FILE="$BUILD_DIR/android-aarch64.cross"
mkdir -p "$BUILD_DIR" "$JNI_OUT"
python3 "$ROOT_DIR/scripts/patch_turnip_android_stubs.py" "$MESA_SRC"
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
meson setup "$BUILD_DIR/out" "$MESA_SRC" "${SETUP_FLAGS[@]}" \
  --cross-file "$CROSS_FILE" \
  -Dbuildtype=release \
  -Dplatforms=android \
  -Dplatform-sdk-version=35 \
  -Dandroid-strict=false \
  -Dandroid-stub=true \
  -Dandroid-libbacktrace=disabled \
  -Dgallium-drivers= \
  -Dvulkan-drivers=freedreno \
  -Dfreedreno-kmds=kgsl \
  -Dglx=disabled \
  -Degl=disabled \
  -Dgles1=disabled \
  -Dgles2=disabled \
  -Dllvm=disabled \
  -Dzstd=disabled \
  -Dxmlconfig=disabled \
  -Dlibunwind=disabled

ninja -C "$BUILD_DIR/out" src/freedreno/vulkan/libvulkan_freedreno.so
cp -f "$BUILD_DIR/out/src/freedreno/vulkan/libvulkan_freedreno.so" "$JNI_OUT/"
"$BIN/llvm-strip" --strip-unneeded "$JNI_OUT/libvulkan_freedreno.so"

# Verify zero private Android HAL/VNDK DT_NEEDED entries (Android 15/16 clns-* safety gate)
NEEDED="$("$BIN/llvm-readelf" -d "$JNI_OUT/libvulkan_freedreno.so" | grep '(NEEDED)' || true)"
echo "[Mobiro] libvulkan_freedreno.so DT_NEEDED:"
echo "$NEEDED"
if echo "$NEEDED" | grep -Eq 'libhardware\.so|libsync\.so|libbacktrace\.so|libcutils\.so'; then
  echo "[Mobiro] ERROR: Private Android system library leaked into libvulkan_freedreno.so DT_NEEDED!" >&2
  exit 1
fi
if "$BIN/llvm-readelf" --dyn-syms "$JNI_OUT/libvulkan_freedreno.so" | grep -E 'UND[[:space:]]+AHardwareBuffer_getNativeHandle'; then
  echo "[Mobiro] ERROR: Private VNDK symbol AHardwareBuffer_getNativeHandle is still UND in libvulkan_freedreno.so!" >&2
  exit 1
fi

echo "[Mobiro] Turnip ICD staged at $JNI_OUT/libvulkan_freedreno.so"
