#!/bin/bash
set -e

cd "$(dirname "$0")/.."

VERSION=$(node -p "require('./package.json').version")
PLATFORM=$(uname -s)

echo ""
echo "  Mahoraga v${VERSION} — release"
echo "  ─────────────────────────────"
echo ""

# ── Preflight checks ────────────────────────────────────────────────────────

if [ -z "$GH_TOKEN" ]; then
  echo "  ✗  GH_TOKEN is not set."
  echo ""
  echo "     1. Open https://github.com/settings/tokens/new"
  echo "        Note: Mahoraga release — Scope: repo (check the top-level box)"
  echo "        Click Generate token and copy it."
  echo ""
  echo "     2. Add this line to your ~/.zshrc:"
  echo "        export GH_TOKEN=paste_your_token_here"
  echo ""
  echo "     3. Run:  source ~/.zshrc"
  echo "        Then: npm run release"
  echo ""
  exit 1
fi

if ! command -v firebase &>/dev/null; then
  echo "  ✗  Firebase CLI not found. Install it:"
  echo "     npm install -g firebase-tools"
  echo ""
  exit 1
fi

# Check firebase is logged in
if ! firebase projects:list &>/dev/null 2>&1; then
  echo "  ✗  Not logged in to Firebase. Run:"
  echo "     firebase login"
  echo ""
  exit 1
fi

echo "  ✓  GH_TOKEN set"
echo "  ✓  Firebase authenticated"
echo ""

# ── Build Python backend ─────────────────────────────────────────────────────
echo "  → Building Python backend..."
bash scripts/build-python.sh
echo "  ✓  Python backend built"
echo ""

# ── Build Electron + publish to GitHub Releases ──────────────────────────────
echo "  → Building Electron app and publishing to GitHub Releases..."
echo "     (This takes a few minutes)"
echo ""

# Build for the current platform only from local machine
case "$PLATFORM" in
  Darwin)  TARGET="--mac" ;;
  Linux)   TARGET="--linux" ;;
  MINGW*|MSYS*|CYGWIN*) TARGET="--win" ;;
  *)       TARGET="" ;;
esac

CSC_IDENTITY_AUTO_DISCOVERY=false npm run dist -- $TARGET --publish always
echo ""
echo "  ✓  Installer published to GitHub Releases"
echo ""

# ── Update version in Clive listing page ────────────────────────────────────
echo "  → Updating Clive listing (v${VERSION})..."

LISTING="deploy/public/apps/mahoraga/index.html"

# Update version badge
sed -i.bak "s|<span class=\"badge\">v[^<]*</span>|<span class=\"badge\">v${VERSION}</span>|" "$LISTING"

# Update sidebar version
sed -i.bak "s|<span class=\"val\">[0-9][0-9.]*</span>|<span class=\"val\">${VERSION}</span>|" "$LISTING"

# Update download URLs to point to GitHub Releases
GH_BASE="https://github.com/Clutch-tim3/Striker/releases/download/v${VERSION}"
sed -i.bak "s|const VER  = '[^']*'|const VER  = '${VERSION}'|" "$LISTING"

# Replace the static Firebase Storage base URL with GitHub Releases URLs
cat > /tmp/update_links.js << 'JSEOF'
const fs = require('fs');
const file = process.argv[1];
const ver  = process.argv[2];
const base = `https://github.com/Clutch-tim3/Striker/releases/download/v${ver}`;

let html = fs.readFileSync(file, 'utf8');

// Replace the BASE constant and links block with GitHub Releases URLs
html = html.replace(
  /const BASE = .*?;\s*const VER.*?;\s*const Q.*?;\s*const links = \{[\s\S]*?\};/,
  `const links = {\n    mac:   \`${base}/Mahoraga-${ver}.dmg\`,\n    win:   \`${base}/Mahoraga-Setup-${ver}.exe\`,\n    linux: \`${base}/Mahoraga-${ver}.AppImage\`,\n  };`
);

fs.writeFileSync(file, html);
JSEOF

node /tmp/update_links.js "$LISTING" "$VERSION"
rm -f "${LISTING}.bak"
echo "  ✓  Listing updated"
echo ""

# ── Deploy listing to Firebase Hosting ──────────────────────────────────────
echo "  → Deploying to Clive marketplace..."
cd deploy
firebase deploy --only hosting --project clive-6d22e
cd ..

echo ""
echo "  ────────────────────────────────────────────────"
echo "  ✓  Mahoraga v${VERSION} is live"
echo ""
echo "     Clive listing:  https://clive-6d22e.web.app/apps/mahoraga"
echo "     GitHub release: https://github.com/Clutch-tim3/Striker/releases/tag/v${VERSION}"
echo "  ────────────────────────────────────────────────"
echo ""
