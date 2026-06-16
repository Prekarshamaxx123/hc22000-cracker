#!/usr/bin/env bash
set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[-]${NC} $1"; }

cd "$(dirname "$0")"

# --- Go ---
if command -v go &>/dev/null; then
    info "Go found: $(go version)"
else
    warn "Go not found. Installing Go 1.22..."
    wget -q https://go.dev/dl/go1.22.5.linux-amd64.tar.gz -O /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin
    info "Go installed: $(go version)"
fi

# --- nvcc (CUDA) ---
CUDA_INSTALLED=false

if command -v nvcc &>/dev/null; then
    info "nvcc found: $(nvcc --version | grep release)"
    CUDA_INSTALLED=true
else
    for d in /usr/local/cuda /usr/local/cuda-* /opt/cuda; do
        if [[ -f "$d/bin/nvcc" ]]; then
            export PATH="$d/bin:$PATH"
            CUDA_INSTALLED=true
            break
        fi
    done
fi

if ! $CUDA_INSTALLED; then
    warn "nvcc not found. Installing CUDA Toolkit 12.5..."
    wget -q https://developer.download.nvidia.com/compute/cuda/repos/ubuntu2204/x86_64/cuda-keyring_1.1-1_all.deb -O /tmp/cuda-keyring.deb
    sudo dpkg -i /tmp/cuda-keyring.deb
    sudo apt-get update -qq
    sudo apt-get install -y -qq cuda-toolkit-12-5 || {
        warn "cuda-toolkit-12-5 not available, trying nvidia-cuda-toolkit..."
        sudo apt-get install -y -qq nvidia-cuda-toolkit
    }
    for d in /usr/local/cuda /usr/local/cuda-*; do
        if [[ -f "$d/bin/nvcc" ]]; then
            export PATH="$d/bin:$PATH"
            CUDA_INSTALLED=true
            break
        fi
    done
fi

if ! command -v nvcc &>/dev/null; then
    err "nvcc not found. Install manually: https://developer.nvidia.com/cuda-downloads"
    exit 1
fi
info "nvcc ready: $(nvcc --version | grep release)"

# --- CUDA libs ---
CUDA_LIB=""
for d in /usr/local/cuda/lib64 /usr/local/cuda/lib /usr/lib/x86_64-linux-gnu /usr/lib/cuda/lib64; do
    if [[ -f "$d/libcudart.so" ]]; then
        CUDA_LIB="$d"
        break
    fi
done

if [[ -z "$CUDA_LIB" ]]; then
    err "Cannot find libcudart.so. CUDA runtime not installed."
    exit 1
fi

# Create symlink so ld can find it
if ! ldconfig -p | grep -q libcudart; then
    if [[ "$CUDA_LIB" != /usr/lib/x86_64-linux-gnu ]]; then
        sudo sh -c "echo '$CUDA_LIB' > /etc/ld.so.conf.d/cuda.conf"
        sudo ldconfig
    fi
fi

# If libcuda.so missing, symlink from driver
if [[ ! -f "$CUDA_LIB/libcuda.so" ]]; then
    for d in /usr/lib/x86_64-linux-gnu /usr/lib64; do
        for f in "$d"/libcuda.so.*; do
            if [[ -f "$f" ]]; then
                sudo ln -sf "$f" "$CUDA_LIB/libcuda.so"
                info "Symlinked $f → $CUDA_LIB/libcuda.so"
                break 2
            fi
        done
    done
fi

export LD_LIBRARY_PATH="$CUDA_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

# --- Build ---
info "Building GPU version..."
make clean 2>/dev/null || true
make gpu

info "Build complete! Running hashcrack..."
echo ""
./hashcrack
