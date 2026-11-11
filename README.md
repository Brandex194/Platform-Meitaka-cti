# Meitaka CTI

> Nome scelto il 09/11/2026; prima il progetto si chiamava **Sentinel AI**. Nel codice, nel database, in Keycloak (realm `sentinel`, client `sentinel-ai`) e negli script `avvia-sentinel.ps1` / `ferma-sentinel.ps1` resta il nome tecnico `sentinel`, per non rompere dati e configurazioni esistenti.

Piattaforma di Cyber Threat Intelligence multi-tenant: ingest di feed pubblici (CVE, KEV, ATT&CK, in futuro IoC, leak e phishing), normalizzazione e deduplicazione, enrichment (EPSS, KEV, match CPE con range di versione), correlazione con gli asset di ogni cliente e risk score che sale e scende con le evidenze. Non è un SIEM/SOAR/EDR: è un layer di intelligence pensato per integrarsi con quei sistemi.

Progetto personale di portfolio di Luca Brandalese, costruito con gli standard di un prodotto B2B/MSSP (isolamento tenant con RLS, RBAC, audit log).

Questa cartella contiene il **rebuild** iniziato il 23/10/2026, riscritto da zero dopo il reverse engineering del vecchio codice (che resta in `Desktop\File piattaforma per mediaminer`). Lo stato aggiornato, con cosa funziona e cosa no, è in [`docs/STATO-PROGETTO.md`](docs/STATO-PROGETTO.md).

## Struttura

| Percorso | Contenuto |
|---|---|
| `backend/app/` | API FastAPI (`api/v1`), auth JWT/RBAC (`auth`), collector (`collectors`: NVD, KEV, ATT&CK reali; IoC, phishing, HIBP stub), `normalize`, `enrichment`, `correlation`, `risk`, Redis Streams (`streams`), Celery worker e beat (`worker`), modelli e sessioni DB (`db`) |
| `backend/alembic/` | 4 migrazioni: schema (21 tabelle), policy RLS, colonne CPE, correzione cast RLS |
| `backend/tests/` | Test pytest (unitari + smoke di integrazione) |
| `frontend/src/` | SPA React 19 + TypeScript + Vite + Tailwind; TanStack Query/Table, Recharts, Zustand, oidc-client-ts |
| `frontend/tests/` | Test Vitest con mock MSW |
| `docs/superpowers/` | Spec di design e piani di fase 1, 2, 3 |
| `docs/` | Stato del progetto, auth, avvio locale, storico dei documenti del vecchio codice |
| `.superpowers/sdd/` | Registro di esecuzione della fase 1 (decisioni, review, report finale) |
| `graphify-out/` | Grafo del codice generato da graphify (03/11/2026) |

## Documentazione

| File | A cosa serve |
|---|---|
| [`docs/STATO-PROGETTO.md`](docs/STATO-PROGETTO.md) | Verifica del 09/11/2026: test eseguiti, difetti vecchi risolti, problemi aperti, prossimi passi |
| [`Architettura.md`](Architettura.md) | Visione funzionale, modello dati, formule di scoring ufficiali, stack e costi |
| [`IMPLEMENTATION_PLAN.md`](IMPLEMENTATION_PLAN.md) | Le tre fasi del rebuild e a che punto sono |
| [`.copilot-instructions.md`](.copilot-instructions.md) | Regole vincolanti per chi scrive codice (scope, stack, scoring, naming, qualità) |
| [`docs/AUTH.md`](docs/AUTH.md) | Come funzionano autenticazione OIDC, ruoli e isolamento tenant nel codice attuale |
| [`docs/AVVIO.md`](docs/AVVIO.md) | Come far girare test e servizi oggi, e cosa manca per lo stack completo |
| [`docs/superpowers/specs/2026-10-23-sentinel-ai-design.md`](docs/superpowers/specs/2026-10-23-sentinel-ai-design.md) | Spec di design del rebuild |
| [`docs/storico/`](docs/storico/) | Revisioni, audit e guide del vecchio codice, conservate per riferimento |

## Comandi di qualità

Backend (da `backend/`, Python 3.12 o 3.13):

```bash
pip install -e ".[dev]"
pytest
ruff check .
bandit -r app
```

Frontend (da `frontend/`):

```bash
npm install
npm test
npm run build
```

Il frontend non ha ancora gli script `lint` e `typecheck` (il typecheck gira dentro `npm run build` con `tsc -b`).

## Stato in breve (09/11/2026)

- Fase 1 backend: completata, 120 test passati.
- Stack Docker: parte con `docker compose up` dal 09/11/2026 (Dockerfile e realm Keycloak aggiunti), vedi `docs/AVVIO.md`.
- Fase 2 frontend: pagine costruite, ma chiamano endpoint che il backend non ha ancora. Da allineare.
- Fase 3 (ML, SIEM, notifiche, infrastruttura K3s, CI): non iniziata.
- Tutto il lavoro è sul branch `feature/phase1-backend`; `master` ha solo il primo commit.
