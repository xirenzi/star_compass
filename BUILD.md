# 星枢加密体系 - 跨平台构建指南

## 平台支持

| 平台 | 状态 | 构建方式 | 产物 |
|------|------|----------|------|
| Windows x86_64 | ✅ 本地构建 | `scripts/build.ps1 -Platform windows` | `.exe` |
| Linux x86_64 | ✅ 本地构建 | Linux 机器上运行 `scripts/build.sh linux` | ELF 二进制 |
| Linux ARM64 | ✅ 本地构建 | Linux ARM 机器上运行 `scripts/build.sh linux` | ELF 二进制 |
| Android APK | 🔧 需 NDK | 本地或 CI 构建 | `.apk` |
| macOS | ✅ 源码兼容 | macOS 机器上运行 `scripts/build.sh macos` | App 二进制 |

## Windows 桌面构建

```powershell
cd D:\bp\star_compass
.\scripts\build.ps1 -Platform windows -Profile release
```

产物：`dist\windows\star-compass-tauri.exe`

## Linux 桌面构建

> **注意**：Linux 构建需要在 Linux 机器上运行（Windows→Linux 交叉编译需要完整 Linux 系统库）。

### 在 Linux 机器上：

```bash
git clone <repo-url>
cd star_compass

# 安装依赖 (Ubuntu/Debian)
sudo apt install libgtk-3-dev libwebkit2gtk-4.1-dev \
  libappindicator3-dev librsvg2-dev pkg-config libssl-dev

# 安装 Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add x86_64-unknown-linux-gnu

# 构建
chmod +x scripts/build.sh
./scripts/build.sh linux release

# 产物
ls dist/linux/
```

### 可选：构建 ARM 架构（树莓派、ARM 服务器）

```bash
# 安装交叉编译工具链
sudo apt install gcc-aarch64-linux-gnu gcc-arm-linux-gnueabihf
rustup target add aarch64-unknown-linux-gnu armv7-unknown-linux-gnueabihf

# 构建
./scripts/build.sh linux release
```

## Android APK 构建

### 方式一：本地构建（需要 Android NDK）

```powershell
# Windows + Android NDK
.\scripts\build.ps1 -Platform android -Profile release

# Linux + Android NDK
./scripts/build.sh android release
```

### 方式二：GitHub Actions CI（推荐，无需本地 NDK）

```bash
# 推送代码，CI 自动构建所有平台
git push origin main
```

或手动触发：
1. 打开 GitHub 仓库 → Actions
2. 选择 "Cross-Platform Build"
3. 点击 "Run workflow"

CI 会自动构建：
- Linux x86_64 / ARM64 / ARMv7 二进制
- Linux AppImage
- Android APK

## 手动安装 NDK（Windows）

如果 BITS/curl 下载失败：

### 方法 1：SDK Manager
```powershell
# 下载 Android cmdline-tools
Invoke-WebRequest -Uri "https://dl.google.com/android/repository/commandlinetools-win-11076708_latest.zip" `
  -OutFile "$env:TEMP\cmdline-tools.zip"

# 安装到 SDK 目录
$SDK = "$env:LOCALAPPDATA\Android\Sdk"
Expand-Archive "$env:TEMP\cmdline-tools.zip" -DestinationPath "$SDK\cmdline-tools"
Move-Item "$SDK\cmdline-tools\cmdline-tools" "$SDK\cmdline-tools\latest"

# 安装 NDK
& "$SDK\cmdline-tools\latest\bin\sdkmanager.bat" --install "ndk;26b" --sdk_root="$SDK"
```

### 方法 2：直接下载 NDK（推荐国内镜像）

```powershell
# 华为云镜像
$URL = "https://repo.huaweicloud.com/android/repository/android-ndk-r26b-windows.zip"
# 或中科大镜像
$URL = "https://mirrors.ustc.edu.cn/android/repository/android-ndk-r26b-windows.zip"

# 使用 IDM / 浏览器下载
# 提取到 C:\Users\<用户名>\AppData\Local\Android\Sdk\ndk\26b
```

### 方法 3：Android Studio
1. 下载 Android Studio：https://developer.android.com/studio
2. 安装时勾选 "Android NDK"
3. NDK 自动安装到 `C:\Users\<用户名>\AppData\Local\Android\Sdk\ndk\<版本>`

## macOS 构建

```bash
# 安装 Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 安装依赖
brew install gtk+3 webkit2gtk@4.1

# 构建
./scripts/build.sh macos release
```

## GitHub Actions CI

每次 push 到 main 或打 tag 时自动构建所有平台。

Workflow 文件：`.github/workflows/build.yml`

### 构建矩阵

| Job | 触发条件 | 产物 |
|-----|----------|------|
| build-linux | push/PR/tag | `star-compass-{target}` |
| build-appimage | push/PR/tag | `*.AppImage` |
| build-android | push/PR/tag | `*.apk` |
| release | 打 tag (`v*`) | GitHub Release 附件 |

### 添加 secrets（如需要）

- `ANDROID_SIGNING_KEYSTORE`: Android 发布签名密钥
- `APPLE_CERTIFICATE`: macOS 开发证书（Base64）
- `APPLE_CERT_PASSWORD`: 证书密码
- `APPLE_TEAM_ID`: Apple Team ID

## 产物验证

```bash
# Linux ELF
file dist/linux/star-compass-x86_64
./dist/linux/star-compass-x86_64 --version  # 或 --help

# Android APK
adb install dist/android/star-compass.apk
```

## Troubleshooting

### Windows: `linker cc not found`

```powershell
# 安装 MinGW-w64（包含 gcc）
# 方法1: winget
winget install -e --id LLVM.LLVM --version 19.1.0

# 方法2: MSYS2
winget install -e --id MSYS2.MSYS2
# 在 MSYS2 终端:
pacman -S mingw-w64-x86_64-gcc
```

### Linux: `pkg-config: command not found`

```bash
sudo apt install pkg-config
```

### Android: `undefined reference to 'log'`

确保 NDK 版本 >= r21，且设置了 `ANDROID_NDK_ROOT` 环境变量。

### macOS: `webkit2gtk not found`

```bash
brew install webkit2gtk@4.1
# 或者使用 Tauri's built-in webview
```
