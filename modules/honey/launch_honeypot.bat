@echo off
chcp 65001 >nul
title Chimera Honeypot v3.2 - ByGhost

echo ==========================================
echo   Chimera Hardened Honeypot v3.2
echo   ByGhost - Advanced Deception Framework
echo ==========================================
echo.

REM Check if honeypot.py exists
if not exist "honeypot.py" (
    echo ❌ Error: honeypot.py not found!
    echo Make sure you're in the correct directory.
    pause
    exit /b 1
)

REM Check Python version
echo 🐍 Checking Python...
python --version 2>nul
if errorlevel 1 (
    echo ❌ Error: Python not found!
    echo Please install Python 3.7+ and add it to PATH.
    pause
    exit /b 1
)

REM Check required packages
echo 📦 Checking dependencies...
python -c "import rich, readchar" 2>nul
if errorlevel 1 (
    echo ⚠️  Warning: Some dependencies might be missing.
    echo    Run: pip install rich readchar
    echo.
)

echo.
echo 🚀 Starting honeypot services...
echo    • Web Server: http://localhost:8080
echo    • SSH Server: localhost:2222
echo    • FTP Server: localhost:2121
echo    • SMB Server: localhost:14445
echo    • SMTP Server: localhost:2525
echo    • Redis Server: localhost:16379
echo    • ElasticSearch: localhost:9209
echo.
echo 📊 Logs will be saved to:
echo    • chimera_v3_activity.jsonl
echo    • pcap_logs\ (network logs)
echo    • siem_events\ (SIEM events)
echo.
echo ⚠️  WARNING: This is a real honeypot!
echo    It will respond to network connections.
echo    Press Ctrl+C to stop all services.
echo.
echo ==========================================

REM Start the honeypot
python honeypot.py

echo.
echo ✅ Honeypot stopped.
pause
