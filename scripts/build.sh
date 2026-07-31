#!/usr/bin/env bash
# =============================================================================
# 星枢加密体系 - Linux / macOS 构建脚本
# 用法: ./build.sh [linux|macos|android|all] [debug|release]
# 示例: ./build.sh linux release
#       ./build.sh all debug
# =============================================================================

set -e

PLATFORM="${1:-linux}"
PROFILE="${2:-release}"
BUILD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$BUILD_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${CYAN}[星枢]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

log "========================================"
log "  星枢加密体系 - 跨平台构建脚本"
log "========================================"
log "Platform : $PLATFORM"
log "Profile  : $PROFILE"
log "Root     : $BUILD_DIR"
echo ""

# =============================================================================
# 前置检查
# =============================================================================
check() {
    local name="$1"; shift
    local cmd="$*"
    echo -n "Checking $name... "
    if eval "$cmd" &>/dev/null; then
        echo -e "${GREEN}OK${NC}"
        return 0
    else
        echo -e "${RED}MISSING${NC}"
        return 1
    fi
}

log "=== 前置检查 ==="
check "Rust" "rustc --version" || error "Install Rust: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
check "Cargo" "cargo --version"
check "Node.js" "node --version"
check "Frontend" "test -f web/index.html" || error "web/index.html not found"

# Check tauri CLI
if ! cargo tauri --version &>/dev/null; then
    log "Installing Tauri CLI..."
    cargo install tauri-cli --locked || cargo install tauri-cli
fi

# =============================================================================
# 安装 Linux target
# =============================================================================
install_linux_targets() {
    log "=== 安装 Rust Linux targets ==="
    local targets=(
        "x86_64-unknown-linux-gnu"
        "aarch64-unknown-linux-gnu"
        "armv7-unknown-linux-gnueabihf"
    )
    for t in "${targets[@]}"; do
        if rustup target list --installed 2>/dev/null | grep -q "^$t$"; then
            echo -e "  $t: ${GREEN}already installed${NC}"
        else
            echo -e "  $t: installing..."
            rustup target add "$t"
        fi
    done
}

# =============================================================================
# 安装 Android SDK/NDK
# =============================================================================
install_android() {
    log "=== 检查 Android SDK/NDK ==="
    
    local ANDROID_HOME="${ANDROID_HOME:-}"
    [ -z "$ANDROID_HOME" ] && ANDROID_HOME="$HOME/Android/Sdk"
    
    # 如果没有 ANDROID_HOME，尝试常见路径
    if [ ! -d "$ANDROID_HOME/ndk" ]; then
        for p in "$HOME/Android/Sdk" "$HOME/Library/Android/sdk" "/opt/android-sdk"; do
            if [ -d "$p/ndk" ]; then
                ANDROID_HOME="$p"
                break
            fi
        done
    fi
    
    # 检查 NDK
    local NDK_VERSION=""
    if [ -d "$ANDROID_HOME/ndk" ]; then
        NDK_VERSION=$(ls "$ANDROID_HOME/ndk" | sort -V | tail -1)
        log "NDK found: $ANDROID_HOME/ndk/$NDK_VERSION"
        export ANDROID_NDK_ROOT="$ANDROID_HOME/ndk/$NDK_VERSION"
        export ANDROID_SDK_ROOT="$ANDROID_HOME"
        export NDK_PATH="$ANDROID_NDK_ROOT"
        export PATH="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"
        return 0
    fi
    
    warn "NDK not found at $ANDROID_HOME/ndk"
    
    # 尝试自动安装 NDK
    local SDKMANAGER=""
    for p in "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" \
             "$HOME/Android/Sdk/cmdline-tools/latest/bin/sdkmanager" \
             "/opt/android-sdk/cmdline-tools/latest/bin/sdkmanager"; do
        if [ -f "$p" ]; then SDKMANAGER="$p"; break; fi
    done
    
    if [ -z "$SDKMANAGER" ]; then
        log "Installing Android cmdline-tools..."
        local CMDLINE_ZIP="/tmp/cmdline-tools.zip"
        local CMDLINE_DIR="$ANDROID_HOME/cmdline-tools"
        curl -L -o "$CMDLINE_ZIP" \
            "https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"
        mkdir -p "$CMDLINE_DIR"
        unzip -q "$CMDLINE_ZIP" -d "$CMDLINE_DIR"
        mv "$CMDLINE_DIR/cmdline-tools" "$CMDLINE_DIR/latest" 2>/dev/null || true
        SDKMANAGER="$CMDLINE_DIR/latest/bin/sdkmanager"
        rm -f "$CMDLINE_ZIP"
    fi
    
    log "Installing NDK (r26b) via sdkmanager..."
    yes | "$SDKMANAGER" --install "ndk;26b" --sdk_root="$ANDROID_HOME" 2>&1 | tail -5
    
    NDK_VERSION=$(ls "$ANDROID_HOME/ndk" 2>/dev/null | sort -V | tail -1)
    if [ -n "$NDK_VERSION" ]; then
        export ANDROID_NDK_ROOT="$ANDROID_HOME/ndk/$NDK_VERSION"
        export ANDROID_SDK_ROOT="$ANDROID_HOME"
        export NDK_PATH="$ANDROID_NDK_ROOT"
        export PATH="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"
        log "NDK installed: $ANDROID_NDK_ROOT"
    else
        warn "NDK installation failed"
    fi
    
    # 安装 Android targets
    for t in aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android; do
        if ! rustup target list --installed 2>/dev/null | grep -q "^${t}$"; then
            rustup target add "$t" 2>/dev/null || true
        fi
    done
}

# =============================================================================
# 构建 Linux
# =============================================================================
build_linux() {
    log "=== 构建 Linux ==="
    install_linux_targets
    
    local targets=(
        "x86_64-unknown-linux-gnu"
        "aarch64-unknown-linux-gnu"
        "armv7-unknown-linux-gnueabihf"
    )
    
    local dist="$BUILD_DIR/dist/linux"
    mkdir -p "$dist"
    
    local profile_flag=""
    [ "$PROFILE" = "release" ] && profile_flag="--release"
    
    for target in "${targets[@]}"; do
        log "Building $target..."
        local arch="${target%%-*}"
        cd "$BUILD_DIR/src-tauri"
        
        if cargo build $profile_flag --target "$target" 2>&1 | tail -3; then
            local out_dir="$BUILD_DIR/src-tauri/target/$target/$PROFILE"
            if [ -f "$out_dir/star-compass-tauri" ]; then
                local size=$(du -h "$out_dir/star-compass-tauri" | cut -f1)
                cp "$out_dir/star-compass-tauri" "$dist/star-compass-$arch"
                echo -e "  ${GREEN}OK -> dist/linux/star-compass-$arch ($size)${NC}"
            fi
        else
            echo -e "  ${RED}FAILED${NC}"
        fi
        cd "$BUILD_DIR"
    done
    
    # AppImage 构建（如果安装了 appimage-builder）
    if command -v appimage-builder &>/dev/null; then
        log "Building AppImage..."
        cd "$BUILD_DIR/src-tauri"
        cargo tauri build --target x86_64-unknown-linux-gnu \
            --bundles appimage 2>&1 | tail -5
        local ap=$(find "$BUILD_DIR/src-tauri/target" -name "*.AppImage" 2>/dev/null | head -1)
        if [ -n "$ap" ]; then
            cp "$ap" "$dist/star-compass-x86_64.AppImage"
            echo -e "  ${GREEN}AppImage -> dist/linux/star-compass-x86_64.AppImage${NC}"
        fi
    else
        warn "appimage-builder not installed (skip AppImage)"
        warn "Install: cargo install appimage-builder"
    fi
}

# =============================================================================
# 构建 macOS
# =============================================================================
build_macos() {
    log "=== 构建 macOS ==="
    
    local targets=(
        "x86_64-apple-darwin"
        "aarch64-apple-darwin"
    )
    
    local dist="$BUILD_DIR/dist/macos"
    mkdir -p "$dist"
    
    local profile_flag=""
    [ "$PROFILE" = "release" ] && profile_flag="--release"
    
    for target in "${targets[@]}"; do
        log "Building $target..."
        cd "$BUILD_DIR/src-tauri"
        
        if cargo build $profile_flag --target "$target" 2>&1 | tail -3; then
            local out_dir="$BUILD_DIR/src-tauri/target/$target/$PROFILE"
            if [ -f "$out_dir/star-compass-tauri" ]; then
                local size=$(du -h "$out_dir/star-compass-tauri" | cut -f1)
                cp "$out_dir/star-compass-tauri" "$dist/star-compass-tauri-$target"
                echo -e "  ${GREEN}OK ($size)${NC}"
            fi
        fi
        cd "$BUILD_DIR"
    done
}

# =============================================================================
# 构建 Android
# =============================================================================
build_android() {
    log "=== 构建 Android ==="
    install_android
    
    local dist="$BUILD_DIR/dist/android"
    mkdir -p "$dist"
    
    local profile_flag=""
    [ "$PROFILE" = "release" ] && profile_flag="--release"
    
    cd "$BUILD_DIR/src-tauri"
    
    # 编译 .so 库
    local targets=(
        "aarch64-linux-android"
        "armv7-linux-androideabi"
        "i686-linux-android"
    )
    
    for target in "${targets[@]}"; do
        log "Compiling $target..."
        if cargo build $profile_flag --target "$target" 2>&1 | tail -2; then
            local arch="${target%%-*}"
            local out_dir="$BUILD_DIR/src-tauri/target/$target/$PROFILE"
            local so_files=$(find "$out_dir" -name "*.so" 2>/dev/null | head -5)
            if [ -n "$so_files" ]; then
                for so in $so_files; do
                    local name=$(basename "$so")
                    local size=$(du -h "$so" | cut -f1)
                    echo -e "  ${GREEN}$name ($size)${NC}"
                done
            fi
        fi
    done
    
    # 构建 APK via Tauri
    log "Building APK..."
    if cargo tauri build $profile_flag 2>&1 | tee /tmp/tauri-android.log; then
        local apk=$(find "$BUILD_DIR/src-tauri/target" -name "*.apk" 2>/dev/null | head -1)
        if [ -n "$apk" ]; then
            local size=$(du -h "$apk" | cut -f1)
            cp "$apk" "$dist/star-compass.apk"
            echo -e "  ${GREEN}APK -> dist/android/star-compass.apk ($size)${NC}"
        fi
    else
        error "APK build failed. Check /tmp/tauri-android.log"
    fi
    
    cd "$BUILD_DIR"
}

# =============================================================================
# 执行
# =============================================================================
log ""
case "$PLATFORM" in
    linux)
        build_linux
        ;;
    macos)
        build_macos
        ;;
    android)
        build_android
        ;;
    all)
        build_linux
        echo ""
        build_android
        ;;
    *)
        error "Unknown platform: $PLATFORM (use: linux, macos, android, all)"
        ;;
esac

log ""
log "========================================"
log "  构建完成！输出目录: dist/"
log "========================================"

if [ -d "$BUILD_DIR/dist" ]; then
    find "$BUILD_DIR/dist" -type f | while read -r f; do
        local size=$(du -h "$f" | cut -f1)
        echo "  $(basename "$f") ($size)"
    done
fi
