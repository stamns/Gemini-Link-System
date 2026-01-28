@echo off
chcp 65001 >nul
title Gemini Link System

:: ========================================
::   配置区域 - 可根据需要修改
:: ========================================

:: Python 解释器路径（留空则使用系统默认 python）
:: 示例: set "PYTHON_PATH=C:\Python310\python.exe"
:: 示例: set "PYTHON_PATH=D:\Anaconda3\envs\myenv\python.exe"
set "PYTHON_PATH=C:\Users\qxd\Downloads\geminibusiness\.venv\Scripts\python.exe"

:: 后端端口
set "BACKEND_PORT=4500"

:: 前端端口
set "FRONTEND_PORT=5000"

:: ========================================
::   以下内容无需修改
:: ========================================

echo ========================================
echo   Gemini Link System 一键启动脚本
echo ========================================
echo.
echo   后端端口: %BACKEND_PORT%
echo   前端端口: %FRONTEND_PORT%
echo.

:: 设置 Python 命令
if "%PYTHON_PATH%"=="" (
    set "PYTHON_CMD=python"
) else (
    set "PYTHON_CMD=%PYTHON_PATH%"
)

:: 检查 Python 是否可用
"%PYTHON_CMD%" --version >nul 2>nul
if %errorlevel% neq 0 (
    echo [错误] 未找到 Python，请检查 PYTHON_PATH 设置或安装 Python 3.10+
    echo        当前设置: %PYTHON_CMD%
    pause
    exit /b 1
)

:: 检查 Node.js 是否安装
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo [错误] 未找到 Node.js，请先安装 Node.js 18+
    pause
    exit /b 1
)

:: 获取脚本所在目录
set "ROOT_DIR=%~dp0"

echo [1/4] 检查后端依赖...
cd /d "%ROOT_DIR%backend"

:: 检查是否需要安装 Python 依赖
if not exist "__pycache__" (
    echo [提示] 首次运行，正在安装 Python 依赖...
    "%PYTHON_CMD%" -m pip install -r requirements.txt
)

echo [2/4] 启动后端服务...
:: 后台启动后端
start /b "" "%PYTHON_CMD%" -m uvicorn main:app --host 0.0.0.0 --port %BACKEND_PORT%

:: 等待后端启动
timeout /t 3 /nobreak >nul

echo [3/4] 检查前端依赖...
cd /d "%ROOT_DIR%frontend"

:: 检查是否需要安装 npm 依赖
if not exist "node_modules" (
    echo [提示] 首次运行，正在安装前端依赖...
    call npm install
)

echo [4/4] 启动前端服务...
echo.
echo ========================================
echo   启动完成！
echo ========================================
echo.
echo   后端地址: http://localhost:%BACKEND_PORT%
echo   前端地址: http://localhost:%FRONTEND_PORT%
echo   API 文档: http://localhost:%BACKEND_PORT%/docs
echo.
echo   按 Ctrl+C 停止所有服务
echo ========================================
echo.

:: 延迟打开浏览器
start /b cmd /c "timeout /t 3 /nobreak >nul && start http://localhost:%FRONTEND_PORT%"

:: 前台运行前端（这样 Ctrl+C 可以停止）
call npm run dev -- --port %FRONTEND_PORT%
