@echo off
title HADES SURVEILLANCE AGENT v2.2
color 0A

echo =============================================================
echo   HADES CYBERSECURITY AGENT v2.2 - VIGILANCIA AUTOMATICA
echo   Nmap + Tshark + Nuclei + Ollama IA (100%% Local)
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
set SURVEILLANCE=%SCRIPT_DIR%hades_surveillance_advanced.py

if not exist "%SURVEILLANCE%" (
    echo [ERROR] No se encontro hades_surveillance_advanced.py en:
    echo %SCRIPT_DIR%
    pause
    exit /b 1
)

rem --- Configuracion de red ---
set TARGET_RANGE=auto
set CAPTURE_SECS=30

echo [INFO] Red objetivo    : AUTODETECTAR (auto)
echo [INFO] Captura Tshark  : %CAPTURE_SECS% segundos
echo [INFO] Script          : %SURVEILLANCE%
echo.
echo =========================================
echo  Iniciando vigilancia en 3 segundos...
echo =========================================
echo.
timeout /t 3 /nobreak >nul

rem --- Lanzar el agente ---
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1

%PYTHON_EXE% "%SURVEILLANCE%" %TARGET_RANGE% %CAPTURE_SECS%

rem --- Resultado ---
set EXIT_CODE=%errorlevel%
echo.
echo =========================================
if %EXIT_CODE%==0 (
    echo  [HADES] Vigilancia completada con exito.
    echo.
    echo  Abriendo carpeta de informes...
    if exist "%SCRIPT_DIR%informes" (
        explorer "%SCRIPT_DIR%informes"
    )
) else (
    echo  [ERROR] El agente termino con codigo: %EXIT_CODE%
    echo  Revisa los mensajes de error anteriores.
)
echo =========================================
echo.
echo Presiona cualquier tecla para cerrar...
pause >nul
