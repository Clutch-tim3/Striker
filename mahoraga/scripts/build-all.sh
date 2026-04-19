#!/usr/bin/env bash
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "═══════════════════════════════════════"
echo "  MAHORAGA — Full Distribution Build"
echo "═══════════════════════════════════════"

echo ""
echo "Step 1/3 — Build Python backend..."
bash "$ROOT/scripts/build-python.sh"

echo ""
echo "Step 2/3 — Install Node dependencies..."
cd "$ROOT" && npm install

echo ""
echo "Step 3/3 — Build Electron app..."
npx electron-builder --publish never

echo ""
echo "═══════════════════════════════════════"
echo "  Build complete. Output in dist/"
echo "═══════════════════════════════════════"
ls -lh "$ROOT/dist/"
