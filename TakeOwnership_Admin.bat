@echo off
setlocal
title TakeOwnership - Admin Control

:: Check for Administrator privileges; prompt UAC if not elevated
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

:: Launch GUI in STA mode with UTF-8 BOM script
powershell -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%~dp0TakeOwnership_Admin.ps1"
exit /b
