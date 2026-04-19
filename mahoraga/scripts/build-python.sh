#!/usr/bin/env bash
set -e

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist/python"

echo "▶ Building Python backend with PyInstaller..."
cd "$ROOT"

pip3 install -q pyinstaller
pip3 install -q -r python/requirements.txt

pyinstaller \
  --onefile \
  --name mahoraga \
  --distpath "$DIST" \
  --workpath "$ROOT/build/pyinstaller" \
  --specpath "$ROOT/build" \
  --hidden-import sklearn.ensemble \
  --hidden-import sklearn.tree \
  --hidden-import psutil \
  --hidden-import watchdog \
  --hidden-import faiss \
  --add-data "models:models" \
  python/main.py

echo "✓ Python binary: $DIST/mahoraga"
