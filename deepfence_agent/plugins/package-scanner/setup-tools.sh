#!/bin/bash

set -e

echo "🚀 Installing Syft & Grype..."

# ----------------------------
# Ensure directories exist (safe, no overwrite)
# ----------------------------
mkdir -p tools/syft-bin
mkdir -p tools/grype-bin

# ----------------------------
# Install Grype
# ----------------------------
echo "📦 Installing Grype..."
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
  | sh -s -- -b ./tools/grype-bin

# ----------------------------
# Install Syft
# ----------------------------
echo "📦 Installing Syft..."
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
  | sh -s -- -b ./tools/syft-bin

# ----------------------------
# Fix binary naming (IMPORTANT for your project)
# ----------------------------
echo "⚙️ Fixing syft binary name..."

# Handle both Linux + Windows cases
if [ -f "tools/syft-bin/syft" ]; then
  mv tools/syft-bin/syft tools/syft-bin/syft.bin
elif [ -f "tools/syft-bin/syft.exe" ]; then
  mv tools/syft-bin/syft.exe tools/syft-bin/syft.bin
fi

# Make executable (ignore error on Windows)
chmod +x tools/syft-bin/syft.bin 2>/dev/null || true
chmod +x tools/grype-bin/grype 2>/dev/null || true

# ----------------------------
# Export PATH (temporary)
# ----------------------------
export PATH=$PATH:$(pwd)/tools/syft-bin
export PATH=$PATH:$(pwd)/tools/grype-bin

# ----------------------------
# Verify installation
# ----------------------------
echo "🔍 Verifying installation..."

if [ -f "./tools/syft-bin/syft.bin" ]; then
  ./tools/syft-bin/syft.bin version || echo "❌ Syft issue"
else
  echo "❌ syft.bin not found"
fi

if [ -f "./tools/grype-bin/grype" ]; then
  ./tools/grype-bin/grype version || echo "❌ Grype issue"
elif [ -f "./tools/grype-bin/grype.exe" ]; then
  ./tools/grype-bin/grype.exe version || echo "❌ Grype issue"
else
  echo "❌ grype not found"
fi

echo "✅ Setup complete!"