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
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DARM_DYNAREC=ON \
  -DANDROID=ON \
  -DBAD_SIGNAL=ON \
  -DCMAKE_BUILD_TYPE=Release

cmake --build "$BUILD_DIR" --parallel

mkdir -p "$OUT_DIR/include" "$OUT_DIR/lib"
(cd "$BOX64_SRC/src" && find . -type f -name "*.h" -exec cp --parents -f {} "$OUT_DIR/include/" \;)
cp -a "$BOX64_SRC/src/include/." "$OUT_DIR/include/"
if [ -f "$BUILD_DIR/box64" ]; then
  cp -f "$BUILD_DIR/box64" "$OUT_DIR/lib/box64_cli"
fi

# Package position-independent Box64 core + ARM64 Dynarec objects (excluding main.c.o) into libbox64_core.a
LLVM_AR="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar"
mapfile -t BOX64_OBJS < <(find "$BUILD_DIR/CMakeFiles" -type f -name "*.o" \
  ! -name "main.c.o" \
  ! -path "*CompilerId*" \
  ! -path "*/CMakeTmp/*" | sort)
if [ "${#BOX64_OBJS[@]}" -gt 0 ] && [ -x "$LLVM_AR" ]; then
  rm -f "$OUT_DIR/lib/libbox64_core.a"
  "$LLVM_AR" rcs "$OUT_DIR/lib/libbox64_core.a" "${BOX64_OBJS[@]}"
  echo "[Mobiro] Archived ${#BOX64_OBJS[@]} objects into $OUT_DIR/lib/libbox64_core.a"
fi

echo "[Mobiro] Built Box64 arm64-v8a artifacts into $OUT_DIR"
