# DETENER_HADES.ps1 — Cleanup scopado y verificado de HADES SENTINEL.
# Regla del proyecto: tras detener el agente NO debe quedar nada corriendo:
#   - cero procesos HADES (hades_*.py) ni sus arboles de hijos
#   - cero herramientas externas huerfanas (nmap, tshark, nuclei, ...)
#   - puerto :8080 libre
#   - .hades_token revocado del disco
# Diseno scopado: NUNCA `taskkill /im python.exe` (rompe Codex, Jupyter, IDEs).

$ErrorActionPreference = 'SilentlyContinue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# Patron que identifica un proceso Python ejecutando un script HADES.
# IMPORTANTE: filtramos ademas por nombre de imagen Python para evitar falsos
# positivos. Sin esto, cualquier shell que mencione 'hades_*.py' en su linea
# de comando (editores, scripts wrapper, esta misma terminal) seria asesinada.
$pattern = 'hades_(server|local|surveillance_advanced|win_master_advanced|mcp|report_docx)\.py'
$pythonImages = @('python.exe','pythonw.exe','py.exe','python3.exe','python3.11.exe','python3.12.exe','python3.13.exe')

Write-Host '[1/5] Procesos HADES por commandline...' -ForegroundColor Cyan
$hadesProcs = Get-CimInstance Win32_Process | Where-Object {
    $_.CommandLine -match $pattern -and $pythonImages -contains $_.Name
}
if ($hadesProcs) {
    foreach ($p in $hadesProcs) {
        Write-Host ('   -> PID {0} ({1})' -f $p.ProcessId, $p.Name) -ForegroundColor Yellow
        & taskkill /F /T /PID $p.ProcessId 2>$null | Out-Null
    }
} else {
    Write-Host '   (sin procesos HADES activos)' -ForegroundColor Gray
}

Write-Host ''
Write-Host '[2/5] Liberando puerto :8080...' -ForegroundColor Cyan
$conn = Get-NetTCPConnection -LocalPort 8080 -State Listen -ErrorAction SilentlyContinue
if ($conn) {
    foreach ($c in $conn) {
        Write-Host ('   -> liberando PID {0}' -f $c.OwningProcess) -ForegroundColor Yellow
        & taskkill /F /T /PID $c.OwningProcess 2>$null | Out-Null
    }
} else {
    Write-Host '   (:8080 ya libre)' -ForegroundColor Gray
}

Write-Host ''
Write-Host '[3/5] Terminando herramientas hijas conocidas...' -ForegroundColor Cyan
$tools = @('nmap','tshark','nuclei','masscan','gobuster','nikto','wpscan','httpx','feroxbuster','openssl','sslscan','testssl')
foreach ($t in $tools) {
    $running = Get-Process -Name $t -ErrorAction SilentlyContinue
    if ($running) {
        Write-Host ('   -> matando {0} ({1} instancias)' -f $t, $running.Count) -ForegroundColor Yellow
        $running | Stop-Process -Force -ErrorAction SilentlyContinue
    }
}

Write-Host ''
Write-Host '[4/5] Revocando token de sesion...' -ForegroundColor Cyan
$tokenFile = Join-Path $here '.hades_token'
if (Test-Path $tokenFile) {
    Remove-Item -Force $tokenFile -ErrorAction SilentlyContinue
    if (Test-Path $tokenFile) {
        Write-Host '   -> [WARN] .hades_token NO se pudo eliminar' -ForegroundColor Red
    } else {
        Write-Host '   -> .hades_token eliminado' -ForegroundColor Yellow
    }
} else {
    Write-Host '   (.hades_token no existia)' -ForegroundColor Gray
}

Write-Host ''
Write-Host '[5/5] VERIFICACION FINAL...' -ForegroundColor Cyan
# WMI/CimInstance cachea procesos zombie un par de segundos tras taskkill, por
# eso verificamos cada PID que matamos con Get-Process (refleja estado real).
Start-Sleep -Milliseconds 1500
$residualPids = @()
if ($hadesProcs) {
    foreach ($p in $hadesProcs) {
        if (Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue) {
            $residualPids += $p.ProcessId
        }
    }
}
# Re-escanear por si quedo un python HADES no detectado en la primera pasada
$newScan = Get-CimInstance Win32_Process | Where-Object {
    $_.CommandLine -match $pattern -and $pythonImages -contains $_.Name
}
foreach ($p in $newScan) {
    if ((Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue) -and ($residualPids -notcontains $p.ProcessId)) {
        $residualPids += $p.ProcessId
    }
}
$port = Get-NetTCPConnection -LocalPort 8080 -State Listen -ErrorAction SilentlyContinue
$tokenLeft = Test-Path $tokenFile
$residualCount = @($residualPids).Count
$portStatus = if ($port) { 'OCUPADO PID ' + $port.OwningProcess } else { 'libre' }
$tokenStatus = if ($tokenLeft) { 'PRESENTE' } else { 'revocado' }
Write-Host ('   Procesos HADES residuales: {0}' -f $residualCount) -ForegroundColor $(if ($residualCount -gt 0) { 'Red' } else { 'Green' })
Write-Host ('   Puerto :8080:             {0}' -f $portStatus) -ForegroundColor $(if ($port) { 'Red' } else { 'Green' })
Write-Host ('   Token .hades_token:       {0}' -f $tokenStatus) -ForegroundColor $(if ($tokenLeft) { 'Red' } else { 'Green' })
Write-Host ''

$allClean = ($residualCount -eq 0) -and (-not $port) -and (-not $tokenLeft)
if ($allClean) {
    Write-Host '=============================================================' -ForegroundColor Green
    Write-Host '  [OK] HADES detenido completamente. Nada quedo corriendo.' -ForegroundColor Green
    Write-Host '=============================================================' -ForegroundColor Green
    exit 0
} else {
    Write-Host '=============================================================' -ForegroundColor Red
    Write-Host '  [WARN] Quedan recursos sin liberar - revisar manualmente.' -ForegroundColor Red
    Write-Host '=============================================================' -ForegroundColor Red
    exit 1
}
