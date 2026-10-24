@echo off
title Unified Threat Sandbox — Live Shutdown
echo =================================================================
echo   Stopping Unified Threat Sandbox & Cloudflare Public Tunnel
echo =================================================================

echo [1/3] Terminating Cloudflare Tunnel process...
taskkill /F /IM cloudflared.exe 2>nul
if %errorlevel% equ 0 (
    echo [+] Cloudflare Tunnel stopped. Public URL is now offline.
) else (
    echo [-] Cloudflare Tunnel was not running.
)

echo [2/3] Terminating Python Flask backend on port 5000...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :5000 ^| findstr LISTENING') do (
    taskkill /F /PID %%a 2>nul
    echo [+] Terminated backend process PID: %%a
)

echo [3/3] Checking remaining python processes for threat-sandbox...
powershell -NoProfile -Command "Get-Process python -ErrorAction SilentlyContinue | Where-Object { $_.Path -like '*threat-sandbox*' } | Stop-Process -Force" 2>nul

echo.
echo =================================================================
echo   Unified Threat Sandbox has been successfully taken down!
echo =================================================================
pause
