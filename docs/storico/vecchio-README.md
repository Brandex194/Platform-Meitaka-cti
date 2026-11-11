> **Documento storico.** Si riferisce al vecchio codice di Sentinel AI (cartella `Desktop\File piattaforma (vecchio prototipo)`), sostituito dal rebuild iniziato il 23/10/2026. Conservato così com'era per riferimento; lo stato attuale è in `docs/STATO-PROGETTO.md`.

---

# Sentinel AI

Piattaforma di Cyber Threat Intelligence multi-tenant: ingest di feed
pubblici (CVE, IoC, leak), normalizzazione/deduplicazione, correlazione
automatica ed enrichment, scoring di rischio gerarchico (asset → gruppo →
tenant) e dashboard cliente — progettata secondo il modello di un vero
prodotto B2B/MSSP multi-tenant.

**Nota**: questo è un progetto personale di portfolio di Luca Brandalese,
non collegato a un'azienda o un cliente reale. Il design segue comunque
gli standard di un prodotto enterprise reale (multi-tenant isolation,
RBAC, audit log, IaC su due cloud, CI) — vedi `IMPLEMENTATION_PLAN.md`
§11 per lo stato reale, voce per voce, di cosa è costruito e cosa no.

Questo file è il punto di ingresso per chi deve capire, far girare o
mandare in produzione il progetto. Per il disegno funzionale/dati
completo vedi `Architettura.md`; per il percorso di implementazione a
blocchi vedi `IMPLEMENTATION_PLAN.md`.

## Stack e struttura del repository

| Percorso | Contenuto |
|---|---|
| `backend/` | API FastAPI (`app/api`), worker Celery (`app/worker`), pipeline di ingest/normalizzazione/correlazione/enrichment/scoring (`app/ingest`, `app/normalize`, `app/correlation`, `app/enrichment`, `app/risk`), auth/RBAC (`app/auth`), audit log (`app/audit`), modelli ML (`app/ml`), migrazioni Alembic (`backend/alembic`) |
| `frontend/` | SPA React + TypeScript (Vite), dashboard cliente e console di amministrazione |
| `docker/` | Configurazioni di supporto per lo stack `docker-compose` locale (es. realm Keycloak) |
| `infra/terraform/` | IaC per Azure (AKS) e AWS (EKS): bootstrap dello state, moduli riusabili, environment per cloud |
| `infra/helm/sentinel/` | Chart Helm unico, parametrizzato per Azure/AWS, che deploya l'applicazione sul cluster creato da Terraform |
| `docs/` | `AUTH.md` (autenticazione/RBAC), `DEPLOY.md` (deploy Azure/AWS + hardening applicativo), `RUNBOOK.md` (operazioni quotidiane) |
| `.github/workflows/` | CI (lint, test, scan immagini e IaC) e pipeline di deploy |

Componenti a runtime: PostgreSQL, Redis (broker Celery + cache), Keycloak
(OIDC/RBAC), API FastAPI, worker + beat Celery, frontend React servito da
nginx. In locale girano tutti come container Docker Compose; in
produzione Postgres e Redis diventano servizi gestiti (vedi
`docs/DEPLOY.md`).

## Avvio rapido (locale, con docker-compose)

Richiede Docker e Docker Compose.

```bash
docker compose up -d --build
```

Servizi esposti sul laptop dopo l'avvio:

| Servizio | URL locale |
|---|---|
| Frontend (dashboard) | http://localhost:5173 |
| API backend | http://localhost:8000 (docs interattive su `/docs`) |
| Keycloak (admin/login OIDC) | http://localhost:8081 |
| Postgres | localhost:5432 |
| Redis | localhost:6379 |

Il container `migrate` applica automaticamente le migrazioni Alembic e il
seed dati al primo avvio, prima che partano `api`/`worker`/`beat`.
Credenziali demo per il login (solo sviluppo — vedi `docs/AUTH.md` per
l'elenco completo e gli avvertimenti) sono precaricate nel realm
Keycloak importato da `docker/keycloak/realm-export.json`.

Per fermare e ripulire (incluso il volume dati Postgres):

```bash
docker compose down -v
```

**Demo rapida guidata**: la cartella `provaDemo/` contiene una variante
di questo stesso `docker-compose.yml` con script di avvio/stop
(`run-demo.sh`/`.ps1`, `stop-demo.sh`/`.ps1`) e un documento con la
sequenza esatta dei comandi e un tour guidato per i 5 ruoli demo —
`provaDemo/COMANDI_DEMO.md`. Utile per una prima prova o per far vedere
la piattaforma a qualcuno senza dover spiegare tutto il repository.

## Sviluppo senza Docker per un singolo componente

- **Backend**: `cd backend && python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt -r requirements-dev.txt`, poi `uvicorn app.main:app --reload` (richiede comunque Postgres/Redis raggiungibili, es. dallo stack compose). Test: `pytest`; lint: `ruff check .`; security: `bandit -r app`.
- **Frontend**: `cd frontend && npm install && npm run dev`. Test: `npm test`; lint: `npm run lint`; typecheck: `npm run typecheck`; build: `npm run build`.

## Documentazione

- **`docs/AUTH.md`** — come funziona l'autenticazione OIDC/JWT e il
  modello RBAC, utenti demo, cosa è stato verificato con un vero
  Keycloak/provider-mock e cosa no.
- **`docs/DEPLOY.md`** — come portare la piattaforma su Azure (AKS) o AWS
  (EKS) con Terraform + Helm, prerequisiti del cluster, sequenza del
  primo deploy, backlog di hardening infrastrutturale (con motivazione
  per ogni check di sicurezza rimandato) e hardening applicativo
  (security header, limite dimensione richiesta, CORS, fix del leak di
  credenziali su `/ready`).
- **`docs/RUNBOOK.md`** — operazioni quotidiane su un ambiente già
  deployato: log, migrazioni, scaling, rotazione segreti, incident
  response di base.
- **`Architettura.md`** — disegno funzionale e dati completo (aree
  amministrazione/analisi/clienti, modello dati, formule di scoring,
  stack tecnologico, costi indicativi).
- **`IMPLEMENTATION_PLAN.md`** — i workstream e le fasi con cui il
  progetto è stato costruito.

## Stato del progetto

La piattaforma copre l'intero percorso funzionale descritto in
`Architettura.md` (ingest → normalizzazione → correlazione → enrichment →
scoring → API/dashboard) più autenticazione multi-tenant, audit log,
IaC per due cloud e hardening applicativo/infrastrutturale — vedi
`IMPLEMENTATION_PLAN.md` per il dettaglio dei workstream completati.
Ogni documento in `docs/` dichiara esplicitamente, senza ambiguità, cosa
è stato verificato con strumenti reali durante lo sviluppo e cosa
richiede invece una verifica con accesso di rete pieno (es. un vero
`terraform apply`/`helm install` contro un cluster reale) prima di un
primo deploy in produzione: leggerli prima di deployare.

Gap noti, non ancora colmati (dettaglio in `IMPLEMENTATION_PLAN.md`
§11): nessun alerting proattivo (email/Slack/Teams), nessun vault
dedicato per i segreti (le chiavi restano lette da variabili
d'ambiente, oggi però mascherate in memoria — vedi hardening sotto),
nessun modello ML addestrato per il risk scoring predittivo (solo un
forecasting lineare interpretabile), nessuna integrazione MISP/OpenCTI,
nessun sandbox/detonation per hash IOC. Nota: `GREYNOISE_API_KEY` esiste
come variabile di configurazione ma non è collegata a nessun
collector/enrichment reale — resta l'unica impostazione "morta" nel
codice (un audit sistematico del 23/09/2026 ne ha trovate e sistemate
altre 3 — `nvd_api_key`, `attack_taxii_base_url`,
`risk_forecast_min_points` — dettaglio in `IMPLEMENTATION_PLAN.md`
§11; lo stesso audit ha trovato che anche `secret_key` non ha nessun
consumatore reale nel codice — auth è interamente OIDC/JWT via JWKS —
segnalato ma non ancora deciso se rimuoverlo o darle un uso reale).
Lo stesso audit ha anche scoperto un'integrazione **SIEM/SOAR
bidirezionale reale e testata** (`app/ti`: Sentinel, Splunk, QRadar) mai
documentata prima qui — disattivata di default via feature flag.

**24/09/2026 — Hardening dei segreti**: le 14 credenziali/token in
`Settings` (API key dei collector/enrichment, token TI, `secret_key`)
sono ora `pydantic.SecretStr` invece di stringhe semplici: mai visibili
in log, errori o repr, sbloccate con `.get_secret_value()` solo nel
punto esatto in cui servono (l'header HTTP verso il servizio esterno).
`app/core/secrets.py` aggiunge anche il seam per sostituire in futuro le
variabili d'ambiente con un vero secret store (Vault/AWS Secrets
Manager) senza toccare il resto del codice. Dettaglio in
`IMPLEMENTATION_PLAN.md` §11.
