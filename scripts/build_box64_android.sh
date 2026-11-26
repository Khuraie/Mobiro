#!/usr/bin/env bash
set -euo pipefail

# Transparently cross-compiles upstream open-source Box64 for Android arm64-v8a
# using the official Android NDK toolchain (zero precompiled third-party blobs).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BOX64_SRC="$ROOT_DIR/third_party/box64"
BUILD_DIR="$ROOT_DIR/third_party/build/box64-arm64"
OUT_DIR="$ROOT_DIR/third_party/prebuilt/arm64-v8a/box64"

if [ ! -f "$BOX64_SRC/CMakeLists.txt" ]; then
  echo "[Mobiro] box64 source missing; run ./scripts/fetch_third_party.sh first." >&2
  exit 1
fi

NDK="${ANDROID_NDK_HOME:-${ANDROID_HOME:-}/ndk/27.2.12479018}"
TOOLCHAIN="$NDK/build/cmake/android.toolchain.cmake"
if [ ! -f "$TOOLCHAIN" ]; then
  echo "[Mobiro] Android NDK toolchain not found at $TOOLCHAIN" >&2
  exit 1
fi

cmake -S "$BOX64_SRC" -B "$BUILD_DIR" -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-31 \
  -DANDROID_STL=c++_shared \
  -DARM_DYNAREC=ON \
  -DANDROID=ON \
  -DBAD_SIGNAL=ON \
  -DCMAKE_BUILD_TYPE=Release

cmake --build "$BUILD_DIR" --parallel

mkdir -p "$OUT_DIR/include" "$OUT_DIR/lib"
cp -a "$BOX64_SRC/src/include/." "$OUT_DIR/include/"
find "$BUILD_DIR" -maxdepth 2 \( -name "libbox64*.a" -o -name "box64" \) -exec cp -a {} "$OUT_DIR/lib/" \;

echo "[Mobiro] Built Box64 arm64-v8a artifacts into $OUT_DIR"
