# Avvia Sentinel AI in locale (solo sviluppo).
# Uso: tasto destro > "Esegui con PowerShell", oppure da PowerShell:  .\avvia-sentinel.ps1
# Requisiti: Docker Desktop avviato, Node.js 20 o superiore.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$backend = Join-Path $root "backend"
$frontend = Join-Path $root "frontend"
$tenantId = "00000000-0000-4000-8000-000000000001"

function Passo($testo) { Write-Host ""; Write-Host "==> $testo" -ForegroundColor Cyan }

Passo "Controllo Docker"
docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker non risponde. Apri Docker Desktop, aspetta che sia pronto e rilancia lo script." -ForegroundColor Red
    exit 1
}

Passo "Controllo Node.js"
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Host "npm non trovato. Installa Node.js 20 o superiore da https://nodejs.org e rilancia lo script." -ForegroundColor Red
    exit 1
}

Set-Location $backend
if (-not (Test-Path ".env")) {
    Passo "Creo backend\.env da .env.example"
    Copy-Item ".env.example" ".env"
}

Passo "Avvio dei servizi Docker (la prima volta ci vogliono alcuni minuti)"
docker compose up -d --build
if ($LASTEXITCODE -ne 0) { Write-Host "docker compose up non è riuscito: guarda i messaggi sopra." -ForegroundColor Red; exit 1 }

Passo "Attendo che Keycloak sia pronto"
$pronto = $false
for ($i = 0; $i -lt 60; $i++) {
    try {
        Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 "http://localhost:8080/realms/sentinel/.well-known/openid-configuration" | Out-Null
        $pronto = $true; break
    } catch { Start-Sleep -Seconds 3 }
}
if (-not $pronto) { Write-Host "Keycloak non risponde dopo 3 minuti. Controlla con: docker compose logs keycloak" -ForegroundColor Red; exit 1 }

Passo "Attendo che l'API sia pronta"
$pronto = $false
for ($i = 0; $i -lt 40; $i++) {
    try {
        Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 "http://localhost:8000/api/v1/health" | Out-Null
        $pronto = $true; break
    } catch { Start-Sleep -Seconds 3 }
}
if (-not $pronto) { Write-Host "L'API non risponde. Controlla con: docker compose logs api" -ForegroundColor Red; exit 1 }

Passo "Creo il tenant di prova (se non esiste già)"
docker compose exec -T postgres psql -U postgres -d sentinel -c "INSERT INTO tenants (id, name, slug) VALUES ('$tenantId', 'Tenant demo', 'demo') ON CONFLICT DO NOTHING;"

Set-Location $frontend
if (-not (Test-Path ".env")) {
    Passo "Creo frontend\.env da .env.example"
    Copy-Item ".env.example" ".env"
}
if (-not (Test-Path "node_modules")) {
    Passo "Installo le dipendenze del frontend (solo la prima volta)"
    npm install
    if ($LASTEXITCODE -ne 0) { Write-Host "npm install non è riuscito: guarda i messaggi sopra." -ForegroundColor Red; exit 1 }
}

Passo "Avvio il frontend in una nuova finestra"
Start-Process powershell -WorkingDirectory $frontend -ArgumentList "-NoExit", "-Command", "npm run dev"
Start-Sleep -Seconds 5
Start-Process "http://localhost:5173"

Write-Host ""
Write-Host "Sentinel AI è avviata." -ForegroundColor Green
Write-Host "  Dashboard:  http://localhost:5173   (utente tenant.admin, password sentinel-dev)"
Write-Host "  API docs:   http://localhost:8000/docs"
Write-Host "  Keycloak:   http://localhost:8080   (admin / admin)"
Write-Host "Per fermare tutto: .\ferma-sentinel.ps1"
