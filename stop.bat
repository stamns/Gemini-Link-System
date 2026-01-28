@echo off
chcp 65001 >nul
title Gemini Link System - 停止服务

:: 端口配置（需与 start.bat 保持一致）
set "BACKEND_PORT=4500"
set "FRONTEND_PORT=5000"

echo ========================================
echo   Gemini Link System 停止脚本
echo ========================================
echo.

echo 正在停止后端服务 (端口 %BACKEND_PORT%)...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":%BACKEND_PORT%" ^| findstr "LISTENING"') do (
    taskkill /F /PID %%a >nul 2>nul
)

echo 正在停止前端服务 (端口 %FRONTEND_PORT%)...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":%FRONTEND_PORT%" ^| findstr "LISTENING"') do (
    taskkill /F /PID %%a >nul 2>nul
)

echo.
echo ========================================
echo   所有服务已停止
echo ========================================
echo.

timeout /t 2 /nobreak >nul
