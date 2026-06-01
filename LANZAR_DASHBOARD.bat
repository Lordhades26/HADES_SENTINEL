@echo off
title LANZAR DASHBOARD WEB HADES v2.2.0
color 02

echo =============================================================
echo   HADES TACTICAL CYBER DASHBOARD v2.2.0
echo   Levantando servidor de control local y APIs seguras...
echo =============================================================
echo.

rem --- Buscar Python instalado ---
set PYTHON_EXE=
for %%P in (
    "python.exe"
    "C:\Python312\python.exe"
    "C:\Python311\python.exe"
    "C:\Python310\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
) do (
    if exist %%P (
        set PYTHON_EXE=%%P
        goto :python_found
    )
)

rem Intentar desde PATH
python --version >nul 2>&1
if %errorlevel%==0 (
    set PYTHON_EXE=python
    goto :python_found
)

echo [ERROR] Python no encontrado.
echo Instala Python desde https://python.org
echo.
pause
exit /b 1

:python_found
echo [OK] Python encontrado: %PYTHON_EXE%

rem --- Directorio del script ---
set SCRIPT_DIR=%~dp0
set SERVER_SCRIPT=%SCRIPT_DIR%hades_server.py

if not exist "%SERVER_SCRIPT%" (
    echo [ERROR] No se encontro hades_server.py en:
    echo %SCRIPT_DIR%
    pause
    exit /b 1
)

rem --- Evitar doble lanzamiento: si el puerto 8080 ya esta en escucha, el
rem     dashboard ya esta corriendo. Arrancar otro servidor fallaria al no poder
rem     enlazar el puerto. En su lugar, reabrimos el navegador en la sesion activa.
netstat -ano | findstr "LISTENING" | findstr ":8080" >nul 2>&1
if %errorlevel%==0 goto :ya_en_ejecucion

echo.
echo =============================================================
echo  Iniciando Servidor en el puerto 8080...
echo  Se abrira automaticamente el navegador en el Dashboard.
echo  Manten esta ventana abierta durante la auditoria.
echo =============================================================
echo.

%PYTHON_EXE% "%SERVER_SCRIPT%"
pause
exit /b 0

:ya_en_ejecucion
echo.
echo =============================================================
echo  [INFO] El Dashboard HADES YA esta en ejecucion en el puerto 8080.
echo  No se lanza un segundo servidor. Reabriendo el navegador en la
echo  sesion activa...
echo =============================================================
echo.
set HADES_TOKEN=
if exist "%SCRIPT_DIR%.hades_token" set /p HADES_TOKEN=<"%SCRIPT_DIR%.hades_token"
if defined HADES_TOKEN (
    start "" "http://127.0.0.1:8080/index.html?token=%HADES_TOKEN%"
) else (
    start "" "http://127.0.0.1:8080/index.html"
)
echo Si el navegador no abrio, visita manualmente:
echo   http://127.0.0.1:8080/index.html?token=%HADES_TOKEN%
echo.
echo Para DETENER el dashboard, cierra su ventana de servidor original.
pause
exit /b 0
