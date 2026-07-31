# star_compass

星枢 - Star Compass: 基于八卦密码学原理的端到端加密通信系统。

## 功能
- 三才密钥协商（Kyber768 + X25519）
- 双棘轮消息加密（Signal Protocol）
- 八卦卦象身份标识
- 跨平台支持（Windows/Linux/Android）

## 构建
- Windows: scripts/build.ps1
- Linux: ash scripts/build.sh
- Android: Tauri Android bundler

## GitHub Actions CI
自动构建: Linux (x86_64/aarch64/armv7), AppImage, Android APK, Windows (本地构建后手动发布)







