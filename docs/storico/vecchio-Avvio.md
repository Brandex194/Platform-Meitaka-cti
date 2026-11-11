> **Documento storico.** Si riferisce al vecchio codice di Sentinel AI (cartella `Desktop\File piattaforma (vecchio prototipo)`), sostituito dal rebuild iniziato il 23/10/2026. Sostituito da `docs/AVVIO.md`. Gli utenti e la password demo qui elencati non esistono nel rebuild. Conservato così com'era per riferimento; lo stato attuale è in `docs/STATO-PROGETTO.md`.

---

Sentinel AI Guida all'avvio locale

Questa guida fa partire l'intera piattaforma sul tuo laptop in un solo comando.\
**Tempo stimato: 3–5 minuti** al primo avvio (scarica le immagini Docker). I successivi avvii impiegano meno di 30 secondi.

## Prerequisiti

🐳

**Docker Desktop**versione 24+ consigliata

📦

**Docker Compose**incluso in Docker Desktop

💻

**4 GB RAM liberi**Keycloak + Postgres + Redis + API

Verifica che Docker sia in esecuzione prima di proseguire: l'icona della balena deve essere visibile nel tray di sistema.

## Avvio passo per passo

1

Apri il terminale nella cartella del progetto

Naviga nella directory principale (quella che contiene `docker-compose.yml`).

PowerShell / bash

```
$ cd "C:\percorso-progetto\File piattaforma (vecchio prototipo)"
```

2

Crea il file .env (solo al primo avvio)

Copia il file di esempio. Per lo sviluppo locale le password di default vanno benissimo.

PowerShell

```
$ cp .env.example .env
```

**Attenzione:** non usare le password di default su un server raggiungibile da Internet. Modificale nel file `.env` prima di qualsiasi deploy.

3

Avvia tutti i servizi

Costruisce le immagini, applica le migrazioni del database e parte tutto in background.

PowerShell / bash

```
$ docker compose up -d --build
```

Il container `migrate` si avvia per primo, applica le migrazioni Alembic e il seed dati, poi si ferma. È normale — ha fatto il suo lavoro.

4

Verifica che tutto sia partito

Aspetta 30–60 secondi, poi controlla lo stato.

PowerShell / bash

```
$ docker compose ps
```

Tutti i container devono mostrare **Up** o **healthy**. Il container `migrate` può mostrare **Exited (0)**: è corretto.

5

Apri la dashboard nel browser

Vai all'indirizzo della dashboard, fai login con uno degli utenti demo qui sotto.

URL dashboard

```
http://localhost:5173
```

## Indirizzi dei servizi

| Servizio | URL | Cosa trovi |
| --- | --- | --- |
| Frontend | http://localhost:5173 | Dashboard principale — entra qui |
| API Backend | http://localhost:8000 | REST API FastAPI |
| API Docs | http://localhost:8000/docs | Swagger UI interattivo |
| Keycloak | http://localhost:8081 | Console OIDC — admin / admin |

## Utenti demo

Tutti gli utenti condividono la stessa password:

PASSWORD SentinelDemo!2026

| Username | Ruolo | Per testare |
| --- | --- | --- |
| super.admin | super_admin | Accesso cross-tenant, gestione tenants |
| tenant.admin | tenant_admin | Gestione asset e config del tenant demo |
| analyst | analyst | Scoring, analisi IoC, correlazioni |
| viewer | viewer | Sola lettura — i tasti di scrittura sono bloccati |
| api.user | api_user | Accesso programmatico, rate limit più alto |

## Fermare la piattaforma

Ferma (dati conservati)

I dati Postgres rimangono. Al prossimo avvio riparti da dove hai lasciato.

```
$ docker compose down
```

Ferma e cancella tutto

Rimuove anche il volume Postgres. Il prossimo avvio riparte dal seed iniziale.

```
$ docker compose down -v
```

## Problemi comuni

**Errore di login / pagina bianca sul frontend**\
Keycloak impiega 30–60 secondi a inizializzarsi. Controlla che il container `keycloak` sia **healthy** con `docker compose ps`, poi ricarica la pagina.

**La porta 8081 è già occupata**\
Cambia il mapping in `docker-compose.yml` da `"8081:8080"` a `"8082:8080"`, aggiorna anche `VITE_OIDC_AUTHORITY` nel servizio `frontend` con il nuovo numero di porta, poi riavvia.

**Il container `migrate` fallisce**\
Postgres potrebbe non essere ancora pronto. Riprova con: `docker compose up migrate --force-recreate`. Per i dettagli: `docker compose logs migrate`.

**Vedere i log in tempo reale**\
`docker compose logs -f api` per il backend, `docker compose logs -f frontend` per il frontend, `docker compose logs -f` per tutto.