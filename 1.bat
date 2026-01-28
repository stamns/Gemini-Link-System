@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion

echo ==============================================
echo           Git 上传指定文件脚本（最终版）
echo ==============================================
echo 当前目录：%cd%
echo.

:: 配置信息
set "github_username=qxd-ljy"
set "remote_repo=https://github.com/qxd-ljy/Gemini-Link-System.git"
set "local_branch=master"
set "remote_branch=main"
set "commit_msg=更新指定项目文件"

:: 1. 检查Git仓库
echo [1/6] 检查Git仓库状态...
git rev-parse --is-inside-work-tree >nul 2>&1
if errorlevel 1 (
    echo 🔧 初始化Git仓库...
    git init
    echo ✅ Git仓库初始化成功！
) else (
    echo ✅ 已存在Git仓库，跳过初始化。
)

:: 2. 配置用户信息
echo.
echo [2/6] 配置Git用户信息...
git config user.name >nul 2>&1
if errorlevel 1 (
    echo 🔧 设置用户信息...
    git config user.name "%github_username%"
    git config user.email "%github_email%"
    echo ✅ 用户信息配置完成！
) else (
    echo ✅ 已配置用户信息，跳过设置。
)

:: 3. 检查远程仓库
echo.
echo [3/7] 检查远程仓库关联...
git remote | findstr /i "origin" >nul 2>&1
if errorlevel 1 (
    echo 🔧 添加远程仓库...
    git remote add origin %remote_repo%
    echo ✅ 远程仓库关联成功！
) else (
    echo ✅ 已关联远程仓库，跳过添加。
)

:: 4. 添加指定文件
echo.
echo [4/6] 添加指定文件到暂存区...
git add static\accounts.html
git add static\app.js
git add static\chat.html
git add static\dashboard.html
git add static\favicon.ico
git add static\index.html
git add static\style.css
git add static\keepalive.html
git add static\accountsettings.html
git add .dockerignore
git add .env.example
git add auth.py
git add database.py
git add docker-compose.yml
git add Dockerfile
git add main.py
git add README.md
git add requirements.txt
git add update_configs.py
git add keep_alive_env.py

if errorlevel 1 (
    echo ❌ 错误：部分文件添加失败！请检查文件路径。
    pause
    exit /b 1
) else (
    echo ✅ 指定文件添加完成！
)

:: 5. 提交变更
echo.
echo [5/6] 提交文件变更...
git commit -m "%commit_msg%"
if errorlevel 1 (
    echo ⚠️  提示：没有需要提交的变更（文件未修改）！
) else (
    echo ✅ 文件提交完成！
)


:: 6. 强制推送到远程（解决non-fast-forward问题）
echo.
echo [6/6] 推送到GitHub远程仓库...
git push -u origin %local_branch%:%remote_branch% 
if errorlevel 0 (
    echo.
    echo ==============================================
    echo ✅ 上传成功！代码已推送到GitHub！
    echo 📦 仓库地址：%remote_repo%
    echo ==============================================
) else (
    echo ❌ 错误：推送失败！请手动执行：
    echo git push -u origin %local_branch%:%remote_branch% ./
)

echo.
pause