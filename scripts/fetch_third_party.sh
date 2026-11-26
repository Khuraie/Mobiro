#!/usr/bin/env bash
set -euo pipefail

# Fetches upstream open-source translation components cleanly from source (zero precompiled blobs).
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TP_DIR="$ROOT_DIR/third_party"
mkdir -p "$TP_DIR"

clone_or_update() {
  local name="$1" url="$2" ref="$3"
  if [ -d "$TP_DIR/$name/.git" ]; then
    echo "[Mobiro] Updating $name ($ref)..."
    git -C "$TP_DIR/$name" fetch --depth 1 origin "$ref"
    git -C "$TP_DIR/$name" checkout FETCH_HEAD
  else
    echo "[Mobiro] Cloning $name ($ref)..."
    git clone --depth 1 --branch "$ref" "$url" "$TP_DIR/$name"
  fi
}

clone_or_update box64 "https://github.com/ptitSeb/box64.git" "main"
clone_or_update dxvk  "https://github.com/doitsujin/dxvk.git" "master"
clone_or_update mesa  "https://gitlab.freedesktop.org/mesa/mesa.git" "main"

echo "[Mobiro] Open-source third-party sources ready in $TP_DIR"
