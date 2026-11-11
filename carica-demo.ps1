# Carica i dati dimostrativi (finti) nel tenant di prova di Meitaka CTI. Solo sviluppo.
# Uso:  .\carica-demo.ps1             carica i dati (non fa nulla se ci sono già)
#       .\carica-demo.ps1 -Reset      toglie i dati demo e li ricarica
#       .\carica-demo.ps1 -Rimuovi    toglie solo i dati demo
# Requisiti: la piattaforma deve essere accesa (avvia-sentinel.ps1) e l'immagine aggiornata
# (da backend: docker compose up -d --build).

param([switch]$Reset, [switch]$Rimuovi)

$ErrorActionPreference = "Stop"
$backend = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "backend"
Set-Location $backend

docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker non risponde. Apri Docker Desktop e rilancia lo script." -ForegroundColor Red
    exit 1
}

$argomenti = @()
if ($Reset) { $argomenti += "--reset" }
if ($Rimuovi) { $argomenti += "--remove" }

docker compose exec -T api python -m app.demo.seed @argomenti
if ($LASTEXITCODE -ne 0) {
    Write-Host "Non è riuscito. Se l'errore dice 'No module named app.demo' ricostruisci l'immagine: docker compose up -d --build" -ForegroundColor Red
    exit 1
}
Write-Host ""
Write-Host "Fatto. Ricarica la pagina http://localhost:5173 (Ctrl+F5)." -ForegroundColor Green
