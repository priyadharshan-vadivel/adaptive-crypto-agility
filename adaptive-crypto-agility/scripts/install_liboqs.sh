#!/usr/bin/env bash
# install_liboqs.sh
# Builds and installs LibOQS (Open Quantum Safe) + Python bindings

set -e
echo "=== Installing LibOQS and liboqs-python ==="

# System dependencies
sudo apt update -y
sudo apt install -y cmake gcc git ninja-build libssl-dev python3-dev

# Build liboqs
if [ ! -d "liboqs" ]; then
  git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
fi
cd liboqs && mkdir -p build && cd build
cmake -GNinja -DBUILD_SHARED_LIBS=ON ..
ninja
sudo ninja install
sudo ldconfig
cd ../..

# Install Python bindings
pip install liboqs-python cryptography

echo "=== LibOQS installation complete ==="
echo "Verify: python3 -c \"import oqs; print('OQS version:', oqs.oqs_version())\""
