@echo off
rem Double-click: build portable Foxray (see build-portable.ps1)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build-portable.ps1"
pause
