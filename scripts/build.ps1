# =============================================================================
# 星枢加密体系 - 跨平台构建脚本
# 支持: Windows (桌面exe) / Linux (AppImage/deb/rpm) / Android (apk/aab)
# =============================================================================
param(
    [ValidateSet("windows", "linux", "android", "all")]
    [string]$Platform = "all",
    
    [ValidateSet("debug", "release")]
    [string]$Profile = "release"
)

$ErrorActionPreference = 'Stop'
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$PROJECT_ROOT = Split-Path -Parent $SCRIPT_DIR
$TAURI_DIR = Join-Path $PROJECT_ROOT "src-tauri"
$WEB_DIR = Join-Path $PROJECT_ROOT "web"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  星枢加密体系 - 跨平台构建脚本" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Platform : $Platform"
Write-Host "Profile  : $Profile"
Write-Host "Root     : $PROJECT_ROOT"
Write-Host ""

# =============================================================================
# 前置检查
# =============================================================================
function Test-Prereq {
    param([string]$Name, [string]$Check)
    Write-Host "Checking $Name... " -NoNewline
    $ok = Invoke-Expression $Check 2>$null
    if ($ok) { Write-Host "OK" -ForegroundColor Green }
    else { Write-Host "MISSING" -ForegroundColor Red; return $false }
    return $true
}

$all_ok = $true

# Check Rust
$rust_ok = Test-Prereq "Rust" "rustc --version 2>`$null"
if (-not $rust_ok) { Write-Host "Install: https://rustup.rs"; $all_ok = $false }

# Check Cargo
$cargo_ok = Test-Prereq "Cargo" "cargo --version 2>`$null"
if (-not $cargo_ok) { $all_ok = $false }

# Check Tauri CLI
$tauri_ok = Test-Prereq "Tauri CLI" "(cargo tauri --version 2>`$null) -ne `$null"
if (-not $tauri_ok) {
    Write-Host "Installing Tauri CLI..."
    cargo install tauri-cli --version "^2.0" 2>&1 | Out-Null
}

# Check node (for web)
$node_ok = Test-Prereq "Node.js" "node --version 2>`$null"
if (-not $node_ok) { Write-Host "Node.js needed for web builds"; }

# Check frontend files
$html_ok = Test-Path (Join-Path $WEB_DIR "index.html")
if ($html_ok) { Write-Host "Frontend     : OK (index.html found)" -ForegroundColor Green }
else { Write-Host "Frontend     : MISSING index.html" -ForegroundColor Red; $all_ok = $false }

Write-Host ""

# =============================================================================
# Helper: check NDK
# =============================================================================
function Get-AndroidNDK {
    $ANDROID_HOME = $env:ANDROID_HOME
    if (-not $ANDROID_HOME) {
        $ANDROID_HOME = "C:\Users\$env:USERNAME\AppData\Local\Android\Sdk"
    }
    $ndk_path = Join-Path $ANDROID_HOME "ndk"
    if (Test-Path $ndk_path) {
        $versions = Get-ChildItem $ndk_path -Directory | Sort-Object Name -Descending
        if ($versions) {
            return $versions[0].FullName
        }
    }
    return $null
}

function Get-AndroidSDK {
    $ANDROID_HOME = $env:ANDROID_HOME
    if (-not $ANDROID_HOME) {
        $ANDROID_HOME = "C:\Users\$env:USERNAME\AppData\Local\Android\Sdk"
    }
    if (Test-Path $ANDROID_HOME) { return $ANDROID_HOME }
    return $null
}

# =============================================================================
# Windows 桌面构建
# =============================================================================
function Build-Windows {
    Write-Host "=== Building for Windows ===" -ForegroundColor Yellow
    $target_flag = if ($Profile -eq "debug") { "" } else { "--release" }
    
    Push-Location $TAURI_DIR
    try {
        cargo build $target_flag 2>&1 | Tee-Object -Variable output
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Windows build FAILED" -ForegroundColor Red
            return $false
        }
        
        $exe_dir = if ($Profile -eq "debug") { "debug" } else { "release" }
        $exe = Join-Path $TAURI_DIR "target\$exe_dir\star-compass-tauri.exe"
        if (Test-Path $exe) {
            $size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
            Write-Host "Windows build SUCCESS: $exe ($size MB)" -ForegroundColor Green
            # Copy to dist
            $dist = Join-Path $PROJECT_ROOT "dist\windows"
            New-Item -ItemType Directory -Path $dist -Force | Out-Null
            Copy-Item $exe $dist -Force
            Write-Host "Copied to dist\windows\" -ForegroundColor Green
        }
        return $true
    } finally {
        Pop-Location
    }
}

# =============================================================================
# Linux 构建 (交叉编译)
# =============================================================================
function Build-Linux {
    Write-Host "=== Building for Linux (cross-compile from Windows) ===" -ForegroundColor Yellow
    
    # Check targets
    $targets = @("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu", "armv7-unknown-linux-gnueabihf")
    foreach ($t in $targets) {
        $installed = rustup target list --installed 2>$null | Where-Object { $_ -eq $t }
        if (-not $installed) {
            Write-Host "Installing Rust target: $t"
            rustup target add $t 2>&1 | Out-Null
        }
    }
    
    # Check cross-compile toolchain
    $cross_targets = @{
        "x86_64-unknown-linux-gnu" = "x86_64-linux-gnu-gcc"
        "aarch64-unknown-linux-gnu" = "aarch64-linux-gnu-gcc"
        "armv7-unknown-linux-gnueabihf" = "arm-linux-gnueabihf-gcc"
    }
    
    # Note: Windows->Linux cross-compile needs MinGW-w64 which is not typically installed.
    # Instead, we use cargo-zigbuild (preferred) or fallback to direct cross-compile
    # Try cargo-zigbuild first
    $zigbuild = cargo build-std --version 2>$null
    
    $dist = Join-Path $PROJECT_ROOT "dist\linux"
    New-Item -ItemType Directory -Path $dist -Force | Out-Null
    
    foreach ($target in $targets) {
        Write-Host "Building $target..."
        $target_flag = if ($Profile -eq "debug") { "" } else { "--release" }
        
        Push-Location $TAURI_DIR
        try {
            cargo build $target_flag --target $target 2>&1 | Tee-Object -Variable output
            if ($LASTEXITCODE -ne 0) {
                Write-Host "  $target FAILED (exit $LASTEXITCODE)" -ForegroundColor Red
                $output | Select-Object -Last 10
            } else {
                $out_dir = if ($Profile -eq "debug") { "debug" } else { "release" }
                $bin = Join-Path $TAURI_DIR "target\$target\$out_dir\star-compass-tauri"
                if (Test-Path $bin) {
                    $size = [math]::Round((Get-Item $bin).Length / 1MB, 1)
                    $arch = $target -replace "unknown-linux-gnu",""
                    Copy-Item $bin "$dist\star-compass-$arch" -Force
                    Write-Host "  $target OK -> dist\linux\star-compass-$arch ($size MB)" -ForegroundColor Green
                }
            }
        } finally {
            Pop-Location
        }
    }
    
    # Also build native Linux binary if we're on Linux (WSL/Linux)
    # This would be run on the target Linux machine
    Write-Host ""
    Write-Host "NOTE: For production Linux builds, run this script on a Linux machine:" -ForegroundColor Cyan
    Write-Host "  cd D:\bp\star_compass" -ForegroundColor Cyan
    Write-Host "  cargo tauri build --target x86_64-unknown-linux-gnu" -ForegroundColor Cyan
}

# =============================================================================
# Android 构建
# =============================================================================
function Build-Android {
    Write-Host "=== Building for Android ===" -ForegroundColor Yellow
    
    $ndk = Get-AndroidNDK
    $sdk = Get-AndroidSDK
    
    if (-not $ndk) {
        Write-Host "NDK not found. Installing..." -ForegroundColor Yellow
        
        # Try sdkmanager first
        $cmdline_tools = Join-Path $sdk "cmdline-tools\latest\bin\sdkmanager.bat"
        
        # Fallback: download NDK directly
        $ndk_urls = @(
            "https://dl.google.com/android/repository/android-ndk-r26b-windows.zip",
            "https://mirrors.ustc.edu.cn/android/repository/android-ndk-r26b-windows.zip",
            "https://mirrors.tuna.tsinghua.edu.cn/android/repository/android-ndk-r26b-windows.zip"
        )
        
        $ndk_zip = "$env:TEMP\ndk-r26b-windows.zip"
        $downloaded = $false
        
        foreach ($url in $ndk_urls) {
            Write-Host "Trying: $url" -ForegroundColor Cyan
            $proc = Start-Process -FilePath "curl.exe" -ArgumentList "-L -o `"$ndk_zip`" -C - `"$url`"" -WindowStyle Hidden -PassThru
            # Wait with progress check
            for ($i = 0; $i -lt 60; $i++) {
                Start-Sleep 5
                if (-not $proc.HasExited) {
                    $size = if (Test-Path $ndk_zip) { [math]::Round((Get-Item $ndk_zip).Length/1MB, 0) } else { 0 }
                    Write-Host "  Downloading... $size MB downloaded" -NoNewline
                    Write-Host ("`r" + (" " * 60) + "`r") -NoNewline
                } else { break }
            }
            if ((Test-Path $ndk_zip) -and (Get-Item $ndk_zip).Length -gt 100MB) {
                $downloaded = $true; break
            }
        }
        
        if (-not $downloaded) {
            Write-Host "NDK download failed. Please install manually:" -ForegroundColor Red
            Write-Host "1. Download from: https://developer.android.com/ndk/downloads" -ForegroundColor Red
            Write-Host "2. Extract to: $sdk\ndk\" -ForegroundColor Red
            Write-Host "3. Re-run this script" -ForegroundColor Red
            return
        }
        
        Write-Host "Extracting NDK..."
        $ndk_extract = Join-Path $sdk "ndk"
        Expand-Archive -Path $ndk_zip -DestinationPath $ndk_extract -Force
        # Rename if needed
        $extracted = Get-ChildItem $ndk_extract -Directory | Where-Object { $_.Name -like "android-ndk*" } | Select-Object -First 1
        if ($extracted) {
            $final = Join-Path $ndk_extract "26b"
            if (-not (Test-Path $final)) {
                Move-Item $extracted.FullName $final
            }
            $ndk = $final.FullName
        }
    }
    
    Write-Host "NDK: $ndk" -ForegroundColor Green
    Write-Host "SDK: $sdk" -ForegroundColor Green
    
    # Set environment
    $env:ANDROID_NDK_ROOT = $ndk
    $env:ANDROID_SDK_ROOT = $sdk
    $env:NDK_PATH = $ndk
    
    # Build targets
    $targets = @("aarch64-linux-android", "armv7-linux-androideabi", "i686-linux-android")
    
    $dist = Join-Path $PROJECT_ROOT "dist\android"
    New-Item -ItemType Directory -Path $dist -Force | Out-Null
    
    foreach ($target in $targets) {
        Write-Host "Building $target..."
        
        # Add target if not installed
        $installed = rustup target list --installed 2>$null | Where-Object { $_ -eq $target }
        if (-not $installed) {
            rustup target add $target 2>&1 | Out-Null
        }
        
        Push-Location $TAURI_DIR
        try {
            $target_flag = if ($Profile -eq "debug") { "" } else { "--release" }
            cargo build $target_flag --target $target 2>&1 | Tee-Object -Variable output
            if ($LASTEXITCODE -ne 0) {
                Write-Host "  $target FAILED" -ForegroundColor Red
                $output | Select-Object -Last 5
            } else {
                $out_dir = if ($Profile -eq "debug") { "debug" } else { "release" }
                $arch = $target -replace "-linux-android",""
                $so = Join-Path $TAURI_DIR "target\$target\$out_dir"
                Get-ChildItem $so -Filter "*.so" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                    $size = [math]::Round($_.Length/1KB, 0)
                    Write-Host "  $($_.Name): $size KB" -ForegroundColor Green
                }
            }
        } finally {
            Pop-Location
        }
    }
    
    # Use Tauri to build APK
    Write-Host ""
    Write-Host "Building APK with Tauri..."
    Push-Location $TAURI_DIR
    try {
        cargo tauri build 2>&1 | Tee-Object -Variable output
        if ($LASTEXITCODE -ne 0) {
            Write-Host "APK build FAILED" -ForegroundColor Red
            $output | Select-Object -Last 10
        } else {
            # Find APK
            $apk = Get-ChildItem (Join-Path $PROJECT_ROOT "src-tauri\target") -Filter "*.apk" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($apk) {
                $size = [math]::Round($apk.Length/1MB, 1)
                Copy-Item $apk.FullName "$dist\$($apk.Name)" -Force
                Write-Host "APK: $dist\$($apk.Name) ($size MB)" -ForegroundColor Green
            }
        }
    } finally {
        Pop-Location
    }
}

# =============================================================================
# 执行构建
# =============================================================================
Write-Host ""
switch ($Platform) {
    "windows" { Build-Windows }
    "linux"   { Build-Linux }
    "android" { Build-Android }
    "all"     {
        Build-Windows
        Write-Host ""
        Build-Linux
        Write-Host ""
        Build-Android
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Build complete! Outputs in dist\" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Show dist contents
$dist_dir = Join-Path $PROJECT_ROOT "dist"
if (Test-Path $dist_dir) {
    Get-ChildItem $dist_dir -Directory | ForEach-Object {
        Write-Host ""
        Write-Host "[$($_.Name)]" -ForegroundColor Yellow
        Get-ChildItem $_.FullName -File | ForEach-Object {
            $s = [math]::Round($_.Length/1MB, 1)
            Write-Host "  $($_.Name) ($s MB)"
        }
    }
}
