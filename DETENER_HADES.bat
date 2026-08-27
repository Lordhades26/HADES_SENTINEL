@echo off
title DETENER AGENTE HADES
color 0C
chcp 65001 >nul 2>&1

echo =============================================================
echo   DETENER AGENTE HADES - CLEANUP SCOPADO Y VERIFICADO
echo   Cero procesos residuales, cero token en disco, puerto libre
echo =============================================================
echo.

rem El .ps1 externo se elimino en el commit 69f6ce8 y este .bat quedo invocando
rem un archivo inexistente: la parada de emergencia documentada no hacia NADA.
rem Ahora el cierre va embebido, sin depender de ficheros externos.
rem
rem Orden: parada elegante por la API -> terminacion del arbol de procesos del
rem servidor -> herramientas de escaneo huerfanas -> borrado del token ->
rem verificacion. Se mata SOLO el proceso que ocupa el puerto y sus hijos:
rem nunca "taskkill /im python.exe", que se llevaria por delante cualquier otro
rem Python del equipo.

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='SilentlyContinue';" ^
  "$base = Split-Path -Parent '%~f0';" ^
  "Write-Host '[1/5] Parada elegante por /api/stop...' -ForegroundColor Cyan;" ^
  "try { $r = Invoke-RestMethod -Uri 'http://127.0.0.1:8080/api/stop' -Method POST -Body '{}' -ContentType 'application/json' -TimeoutSec 8; Write-Host ('      ' + $r.message) -ForegroundColor Green } catch { Write-Host '      sin respuesta (el agente ya estaba detenido)' -ForegroundColor DarkGray };" ^
  "Start-Sleep -Seconds 2;" ^
  "Write-Host '[2/5] Terminando el proceso del dashboard (puerto 8080)...' -ForegroundColor Cyan;" ^
  "$pids = @(Get-NetTCPConnection -LocalPort 8080 -State Listen | Select-Object -ExpandProperty OwningProcess -Unique);" ^
  "if ($pids) { foreach ($p in $pids) { Write-Host ('      matando PID ' + $p + ' y su arbol'); cmd /c \"taskkill /f /t /pid $p >nul 2>&1\" } } else { Write-Host '      el puerto ya estaba libre' -ForegroundColor DarkGray };" ^
  "Write-Host '[3/5] Cerrando herramientas de escaneo huerfanas...' -ForegroundColor Cyan;" ^
  "$tools = @('nmap','tshark','dumpcap','nuclei','openssl');" ^
  "$n = 0; foreach ($t in $tools) { $ps = @(Get-Process -Name $t); if ($ps) { $n += $ps.Count; $ps | Stop-Process -Force } };" ^
  "if ($n -gt 0) { Write-Host ('      ' + $n + ' proceso(s) terminado(s)') } else { Write-Host '      ninguna herramienta activa' -ForegroundColor DarkGray };" ^
  "Write-Host '[4/5] Borrando el token de sesion...' -ForegroundColor Cyan;" ^
  "$tok = Join-Path $base '.hades_token';" ^
  "if (Test-Path $tok) { Remove-Item $tok -Force; Write-Host '      .hades_token eliminado' } else { Write-Host '      no habia token en disco' -ForegroundColor DarkGray };" ^
  "Start-Sleep -Seconds 1;" ^
  "Write-Host '[5/5] Verificacion final:' -ForegroundColor Cyan;" ^
  "$ok = $true;" ^
  "if (Get-NetTCPConnection -LocalPort 8080 -State Listen) { Write-Host '      [FALLA] el puerto 8080 sigue ocupado' -ForegroundColor Red; $ok = $false } else { Write-Host '      [OK] puerto 8080 libre' -ForegroundColor Green };" ^
  "$rest = @(Get-Process -Name nmap,tshark,dumpcap,nuclei,openssl);" ^
  "if ($rest.Count -gt 0) { Write-Host ('      [FALLA] quedan ' + $rest.Count + ' proceso(s) de escaneo') -ForegroundColor Red; $ok = $false } else { Write-Host '      [OK] sin procesos de escaneo' -ForegroundColor Green };" ^
  "if (Test-Path $tok) { Write-Host '      [FALLA] el token sigue en disco' -ForegroundColor Red; $ok = $false } else { Write-Host '      [OK] sin token en disco' -ForegroundColor Green };" ^
  "Write-Host '';" ^
  "if ($ok) { Write-Host ' HADES DETENIDO POR COMPLETO.' -ForegroundColor Green; exit 0 } else { Write-Host ' CIERRE INCOMPLETO - revisa las lineas marcadas [FALLA].' -ForegroundColor Red; exit 1 }"

set RC=%ERRORLEVEL%
echo.
if %RC%==0 (echo Codigo de salida: 0 ^(cierre verificado^)) else (echo Codigo de salida: %RC% ^(cierre incompleto^))
echo.
pause
exit /b %RC%
