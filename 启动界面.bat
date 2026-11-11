@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ============================================================
echo   忍界 XSS 探针  ^|  NINJA REFLEX XSS SCANNER
echo ============================================================
python webui.py %*
pause
