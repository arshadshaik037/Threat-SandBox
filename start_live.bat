@echo off
title Unified Threat Sandbox — Live Launcher
echo =================================================================
echo   Starting Unified Threat Sandbox Live Server with Cloudflare
echo =================================================================
cd /d "%~dp0"

echo [1/2] Launching Flask backend on http://127.0.0.1:5000 ...
start "Threat Sandbox Backend" cmd /k ".\.venv\Scripts\python.exe app.py"

echo Waiting 3 seconds for server initialization...
timeout /t 3 /nobreak >nul

echo [2/2] Launching Cloudflare Tunnel to expose public HTTPS URL...
echo Look for your public https://*.trycloudflare.com URL below:
echo =================================================================
"%LOCALAPPDATA%\cloudflared.exe" tunnel --protocol http2 --url http://127.0.0.1:5000
pause
