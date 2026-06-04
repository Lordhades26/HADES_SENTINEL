@echo off
title DETENER ECOSYSTEM HADES
color 0C
chcp 65001 >nul 2>&1

echo =============================================================
echo   DETENER AGENTE HADES - CLEANUP SCOPADO Y VERIFICADO
echo   Cero procesos residuales, cero token en disco, puerto libre
echo =============================================================
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0DETENER_HADES.ps1"

echo.
pause
