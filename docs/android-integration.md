# 星枢 Android 集成指南

## 概述

星枢加密体系通过 Android NDK (Rust + C) 提供 Android 原生库 (.so)，并通过 Tauri 框架打包为 APK。

## 架构

```
┌─────────────────────────────────────────────┐
│  Android App (Kotlin/Java)                  │
│  ┌───────────────────────────────────────┐  │
│  │  Tauri WebView (web/index.html)      │  │
│  │  ┌─────────────────────────────────┐  │  │
│  │  │  星枢 Web UI (HTML/CSS/JS)      │  │  │
│  │  └─────────────────────────────────┘  │  │
│  └──────────┬──────────────────────────┘  │
│             │ Tauri IPC (invoke)            │
│  ┌──────────▼──────────────────────────┐  │
│  │  Tauri JNI Bridge (Rust)            │  │
│  │  ┌─────────────────────────────┐    │  │
│  │  │  star_compass.lib (Rust NDK) │   │  │
│  │  │  · Hybrid KX (Kyber+X25519)  │   │  │
│  │  │  · Signal Ratchet             │   │  │
│  │  │  · Astro Encrypt              │   │  │
│  │  │  · Packet Format              │   │  │
│  │  └─────────────────────────────┘    │  │
│  └─────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

## Rust 库编译（Android NDK）

### 前置条件

1. **Rust**：安装 `stable` toolchain
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **Android NDK r26b**：必须安装

   **下载方式（选其一）：**

   | 方式 | 说明 |
   |------|------|
   | [Android Studio](https://developer.android.com/studio) | 勾选 NDK 安装 |
   | [华为云镜像](https://repo.huaweicloud.com/android/repository/android-ndk-r26b-windows.zip) | 国内推荐 |
   | [中科大镜像](https://mirrors.ustc.edu.cn/android/repository/android-ndk-r26b-windows.zip) | 国内推荐 |
   | [官方下载](https://developer.android.com/ndk/downloads) | 需要代理 |

   **提取到指定目录：**
   ```
   Windows: C:\Users\<用户名>\AppData\Local\Android\Sdk\ndk\26b
   Linux:   ~/Android/Sdk/ndk/26b
   ```

3. **Android SDK**：
   ```bash
   # sdkmanager 自动安装
   ~/Android/Sdk/cmdline-tools/latest/bin/sdkmanager \
     --install "platforms;android-34" "build-tools;34.0.0"
   ```

### 编译步骤

```bash
cd star_compass

# 添加 Android 编译目标
rustup target add aarch64-linux-android       # 手机 ARM64
rustup target add armv7-linux-androideabi     # 手机 ARM32
rustup target add i686-linux-android          # 模拟器 x86

# 设置 NDK 环境变量
export ANDROID_NDK_ROOT=~/Android/Sdk/ndk/26b   # Linux
# Windows PowerShell:
# $env:ANDROID_NDK_ROOT = "C:\Users\<用户名>\AppData\Local\Android\Sdk\ndk\26b"

# 编译 Rust 库
cargo build --release -p star_compass

# 验证 .so 文件
find target -name "*.so" -path "*/release/*" | sort
```

预期产物：
```
target/aarch64-linux-android/release/libstar_compass.so     (~2MB, 手机 ARM64)
target/armv7-linux-androideabi/release/libstar_compass.so   (~2MB, 手机 ARM32)
target/i686-linux-android/release/libstar_compass.so         (~2MB, 模拟器 x86)
target/x86_64-linux-android/release/libstar_compass.so       (~2MB, 模拟器 x86_64)
```

## Tauri Android 构建

### 配置 Android SDK 路径

在 `src-tauri/tauri.conf.json` 中配置：

```json
{
  "bundle": {
    "android": {
      "minSdkVersion": 24
    }
  }
}
```

### 设置环境变量

```bash
# Windows PowerShell
$env:ANDROID_NDK_ROOT = "C:\Users\<用户名>\AppData\Local\Android\Sdk\ndk\26b"
$env:ANDROID_SDK_ROOT = "C:\Users\<用户名>\AppData\Local\Android\Sdk"

# Linux/macOS
export ANDROID_NDK_ROOT=~/Android/Sdk/ndk/26b
export ANDROID_SDK_ROOT=~/Android/Sdk
```

### 构建 APK

```bash
cd src-tauri

# Debug APK
cargo tauri build

# Release APK（需要签名）
cargo tauri build -- --bundles apk
```

产物：`src-tauri/target/*/release/bundle/apk/星枢_x.x.x.apk`

### 安装和测试

```bash
# 通过 ADB 安装
adb install -r star_compass.apk

# 查看日志
adb logcat -s star_compass

# 通过 USB 调试
adb forward tcp:9222 localabstract:chrome_devtools_remote
```

## Android 原生调用（绕过 Tauri）

如果不需要 Tauri WebView，可以直接通过 JNI 调用 Rust 库：

### JNI 绑定示例（Kotlin）

```kotlin
package com.starcompass.android

class StarCompassLib {
    companion object {
        init {
            // 加载对应架构的 .so
            System.loadLibrary("star_compass")
        }
    }

    // 初始化加密系统
    external fun initEncryption(seed: ByteArray): Boolean

    // 生成密钥对
    external fun generateKeyPair(): ByteArray  // [公钥(32) | 私钥(32)]

    // 建立会话（混合密钥交换）
    external fun establishSession(
        myPrivateKey: ByteArray,
        myPublicKey: ByteArray,
        theirPublicKey: ByteArray
    ): ByteArray  // 共享密钥

    // 加密消息
    external fun encrypt(plaintext: ByteArray): ByteArray

    // 解密消息
    external fun decrypt(ciphertext: ByteArray): ByteArray

    // 获取公钥
    external fun getPublicKey(): ByteArray
}
```

### JNI 实现（Rust → Java）

在 `src-tauri/src/lib.rs` 添加：

```rust
use jni::JNIEnv;
use jni::objects::JByteArray;
use jni::sys::{jbyteArray, jboolean, jsize};

#[no_mangle]
pub extern "system" fn Java_com_starcompass_android_StarCompassLib_initEncryption(
    mut env: JNIEnv,
    _class: JClass,
    seed: JByteArray,
) -> jboolean {
    // 实现逻辑
    true as jboolean
}

#[no_mangle]
pub extern "system" fn Java_com_starcompass_android_StarCompassLib_generateKeyPair(
    mut env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    // 生成 X25519 密钥对
    // 返回 [公钥(32) | 私钥(32)]
    todo!()
}
```

Cargo.toml 添加：

```toml
[target.'cfg(mobile)'.dependencies]
jni = "0.21"
```

## Android NDK 下载镜像（国内）

如果官方地址无法访问，使用以下镜像：

```
# 华为云（推荐）
https://repo.huaweicloud.com/android/repository/android-ndk-r26b-windows.zip
https://repo.huaweicloud.com/android/repository/android-ndk-r26b-linux.zip

# 中科大
https://mirrors.ustc.edu.cn/android/repository/android-ndk-r26b-windows.zip
https://mirrors.ustc.edu.cn/android/repository/android-ndk-r26b-linux.zip

# 清华大学 TUNA
https://mirrors.tuna.tsinghua.edu.cn/android/repository/android-ndk-r26b-windows.zip
```

下载后解压到 SDK 目录：
```
Windows: %LOCALAPPDATA%\Android\Sdk\ndk\<版本>
Linux:   ~/Android/Sdk/ndk/<版本>
macOS:   ~/Library/Android/sdk/ndk/<版本>
```

## 常见问题

### Q: `linker cc not found`

A: NDK 未正确安装或 `ANDROID_NDK_ROOT` 未设置。验证：
```bash
echo $ANDROID_NDK_ROOT
ls $ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/*/bin/aarch64-linux-android-clang
```

### Q: `undefined reference to 'log'`

A: 确保 NDK 版本 >= r21，r26b 已包含 liblog。

### Q: Android 模拟器 vs 真机

| 架构 | 模拟器 | 真机 |
|------|--------|------|
| x86_64 | ✅ | ❌ |
| i686 | ✅ | ❌ |
| armv7 | 慢 | ✅ |
| aarch64 | ❌ | ✅ |

真机调试用 `aarch64`，模拟器用 `i686`。

### Q: APK 签名

Release APK 需要签名。Tauri 自动使用 debug 签名，开发测试无需额外配置。

发布签名配置（Tauri 2）：
```json
{
  "bundle": {
    "android": {
      "signingConfigs": [{
        "id": "release",
        " keystore": "/path/to/keystore.jks",
        "alias": "starcompass",
        "password": "...",
        "keyPassword": "..."
      }]
    }
  }
}
```
