# Ferma Sentinel AI in locale.
# Uso:  .\ferma-sentinel.ps1            ferma i servizi e conserva i dati
#       .\ferma-sentinel.ps1 -Cancella  ferma i servizi e cancella anche il database

param([switch]$Cancella)

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $root "backend")

if ($Cancella) {
    docker compose down -v
    Write-Host "Servizi fermati e dati cancellati. Al prossimo avvio si riparte da zero." -ForegroundColor Yellow
} else {
    docker compose down
    Write-Host "Servizi fermati. I dati restano per il prossimo avvio." -ForegroundColor Green
}
Write-Host "Il frontend gira nella sua finestra di PowerShell: chiudila o premi Ctrl+C."
