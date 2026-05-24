@echo off
title DETENER ECOSYSTEM HADES
color 0C

echo =============================================================
echo   DETENER AGENTE HADES - DETENCION DE EMERGENCIA
echo   Terminando todos los procesos activos de ciberseguridad...
echo =============================================================
echo.

echo [INFO] Terminando subprocesos activos de escaneo y auditoria...
taskkill /f /im nmap.exe >nul 2>&1
taskkill /f /im tshark.exe >nul 2>&1
taskkill /f /im nuclei.exe >nul 2>&1
taskkill /f /im openssl.exe >nul 2>&1

echo [INFO] Terminando procesos del motor Python...
taskkill /f /im python.exe >nul 2>&1
taskkill /f /im pythonw.exe >nul 2>&1

echo.
echo =============================================================
echo  [OK] Todos los procesos relacionados han sido finalizados.
echo  Tu equipo y red estan libres de ejecuciones de HADES.
echo =============================================================
echo.
pause
