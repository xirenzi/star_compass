@echo off
chcp 65001 >nul
set "SCRIPT_DIR=%~dp0"
set "EXE_DIR=%SCRIPT_DIR%src-tauri\target\release"

:: 如果 web/ 不在 exe 同级，复制过去
if not exist "%EXE_DIR%\web" (
    echo 部署前端资源...
    xcopy /E /Y "%SCRIPT_DIR%web" "%EXE_DIR%\web" >nul
)

echo 启动星枢加密体系...
start "" "%EXE_DIR%\star-compass-tauri.exe"
