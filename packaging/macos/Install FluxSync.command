#!/bin/bash
# FluxSync installer for macOS builds that are not Apple-notarized yet.
# Preferred: open Terminal, type `bash `, drag this file in, press Return.
set -e
cd "$(dirname "$0")"

if [ ! -d "FluxSync.app" ]; then
  echo "Keep this file next to FluxSync.app and run it again."
  exit 1
fi

echo "Installing FluxSync..."

# Stop a running copy so the bundle can be replaced cleanly.
pkill -x FluxSync 2>/dev/null || true
pkill -x fluxsyncd 2>/dev/null || true

rm -rf "/Applications/FluxSync.app"
ditto "FluxSync.app" "/Applications/FluxSync.app"

# Clear the quarantine flag that makes macOS report the app as "damaged",
# then re-sign ad-hoc: Apple Silicon refuses to exec unsigned Mach-O
# binaries, and --deep can miss loose helpers, so sign those explicitly.
xattr -dr com.apple.quarantine "/Applications/FluxSync.app" 2>/dev/null || true
find "/Applications/FluxSync.app/Contents/MacOS" -type f \
  -exec codesign --force --sign - {} \; 2>/dev/null || true
codesign --force --deep --sign - "/Applications/FluxSync.app"

echo "Done. Launching FluxSync..."
open "/Applications/FluxSync.app"
