# Avvio locale

Aggiornato il 9 novembre 2026, dopo l'aggiunta di `backend/Dockerfile` e del realm Keycloak di sviluppo. Sostituisce `Sentinel AI — Avvio.md` della vecchia cartella.

## Stack completo con Docker

Serve Docker Desktop. Dalla cartella `backend`:

```powershell
cd "C:\percorso-progetto\piattaforma cti\backend"
copy .env.example .env
docker compose up -d --build
```

Al primo avvio:

1. `postgres` crea il database e il ruolo applicativo `sentinel_app` (senza superuser e senza BYPASSRLS).
2. `migrate` applica le migrazioni Alembic (6 al 09/11/2026) e si ferma: `Exited (0)` è normale.
3. `keycloak` importa il realm `sentinel` da `backend/keycloak/realm-dev.json` (30-60 secondi).
4. `api`, `worker` e `beat` partono.

Controllo: `docker compose ps`. Tutto deve essere `Up`, tranne `migrate`.

### Creare il tenant di prova

Non c'è ancora un'API per i tenant né un seed. Gli utenti di prova appartengono al tenant `00000000-0000-4000-8000-000000000001`, che va creato una volta:

```powershell
docker compose exec postgres psql -U postgres -d sentinel -c "INSERT INTO tenants (id, name, slug) VALUES ('00000000-0000-4000-8000-000000000001', 'Tenant demo', 'demo');"
```

### Utenti di prova (solo sviluppo)

Password per tutti: `sentinel-dev`. Il file del realm è solo per docker-compose locale e non va mai usato in un ambiente raggiungibile da altri.

| Utente | Ruolo | Tenant |
|---|---|---|
| `super.admin` | super_admin | nessuno (accede a tutti) |
| `tenant.admin` | tenant_admin | tenant demo |
| `analyst` | analyst | tenant demo |
| `viewer` | viewer | tenant demo |
| `api.user` | api_user | tenant demo |

Console admin di Keycloak: http://localhost:8080, utente `admin`, password `admin`.

### Provare l'API con un token vero

```powershell
$tok = (Invoke-RestMethod -Method Post -Uri http://localhost:8080/realms/sentinel/protocol/openid-connect/token -Body @{grant_type="password"; client_id="sentinel-ai"; username="tenant.admin"; password="sentinel-dev"}).access_token
Invoke-RestMethod -Uri http://localhost:8000/api/v1/tenants/00000000-0000-4000-8000-000000000001/assets -Headers @{Authorization="Bearer $tok"}
```

Il login con password diretta (`grant_type=password`) è attivo sul client `sentinel-ai` solo nel realm di sviluppo, per questo tipo di prova. Documentazione interattiva dell'API: http://localhost:8000/docs.

### Fermare

```powershell
docker compose down      # conserva i dati
docker compose down -v   # cancella anche il database
```

## Frontend

```powershell
cd "C:\percorso-progetto\piattaforma cti\frontend"
copy .env.example .env
npm install
npm run dev
```

Apri http://localhost:5173. Il login con Keycloak è configurato (client `sentinel-ai`, PKCE), ma la maggior parte delle pagine resta vuota o in errore finché il backend non espone gli endpoint che il frontend chiama (vedi `docs/STATO-PROGETTO.md`). Non verificato nel browser il 09/11/2026.

## Solo test, senza servizi

```powershell
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
pytest
```

I test usano SQLite in memoria e Redis finto; non serve nessuna variabile d'ambiente. Risultato atteso: 120 passati, 2 saltati (i test RLS che richiedono Postgres).

Frontend: `npm test` e `npm run build` dalla cartella `frontend`.

## Porte

| Servizio | Porta |
|---|---|
| API FastAPI | 8000 |
| Frontend Vite | 5173 (proxy `/api` → 8000) |
| Keycloak | 8080 |
| Postgres | 5432 |
| Redis | 6379 |

## Problemi noti

- Il worker stampa un avviso di Celery su `broker_connection_retry_on_startup`: innocuo.
- I collector partono solo agli orari del beat (NVD ogni ora, KEV alle 05:00 UTC, ATT&CK alle 04:30 UTC). Per lanciarne uno subito: `docker compose exec worker celery -A app.worker.celery_app call sentinel.tasks.collect_kev`.
