# Piano di implementazione — Sentinel AI (rebuild)

Aggiornato al 9 novembre 2026. Sostituisce il vecchio `IMPLEMENTATION_PLAN.md` (workstream WS1–WS7 e fasi A–E del codice precedente, ora in `docs/storico/`).

Il rebuild segue l'approccio "B — rebuild corretto in fasi" della spec `docs/superpowers/specs/2026-10-23-sentinel-ai-design.md`. I piani dettagliati, task per task con i test, sono in `docs/superpowers/plans/`. Questo file dice solo a che punto è ogni fase; il dettaglio di cosa funziona è in `docs/STATO-PROGETTO.md`.

## Principi

- Prima che funzioni davvero, poi che sia coerente con l'architettura, poi che sia elegante.
- Ogni regola di business (scoring, correlazione) ha almeno un test unitario.
- Ogni query sui dati filtra per tenant; la RLS è la seconda rete, non la prima.
- Niente dati inventati: CVE, KEV, EPSS e threat actor solo da fonti citabili.
- Componenti di fase successiva (Neo4j, Kafka, GraphQL, SOAR) solo su richiesta esplicita.

## Fase 1 — Backend (completata il 23/10/2026)

Piano: `docs/superpowers/plans/2026-10-23-sentinel-phase1-backend.md`. Registro: `.superpowers/sdd/2026-10-23-sentinel-phase1-backend/`.

| Task | Contenuto | Stato |
|---|---|---|
| 1 | Scaffold, docker-compose, pyproject | Fatto; `Dockerfile` e realm Keycloak aggiunti il 09/11/2026 |
| 2 | Config e risoluzione segreti | Fatto |
| 3–4 | 21 modelli, migrazioni, RLS su 13 tabelle | Fatto |
| 5 | Auth JWT RS256, ruoli, sessione per tenant | Fatto |
| 6 | Redis Streams (publish, read, cursori) | Fatto |
| 7 | Collector NVD, KEV, ATT&CK; HIBP, IoC, phishing come stub | Fatto (stub dichiarati) |
| 8 | Normalizzazione | Fatto |
| 9 | Enrichment: CPE con range di versione, KEV, EPSS | Fatto; enrichment IP rimandato |
| 10 | Correlazione (5 regole, 2 stub) | Fatto |
| 11 | Risk engine con decay, EPSS, pesi da `ScoreRule` | Fatto; alert solo su log, score tenant rimandato |
| 12 | Celery beat | Fatto |
| 13 | API v1, RBAC, error model, audit | Fatto |
| 14 | Smoke test di integrazione | Fatto |
| Review finale | isolamento tenant, commit/cursori, ultimo score per asset, validazione pesi | Fatto, 118 test passati |

## Fase 2 — Frontend e API CTI (in corso)

Piano: `docs/superpowers/plans/2026-10-24-sentinel-phase2-frontend.md`.

| Task | Contenuto | Stato |
|---|---|---|
| 1 | Scaffold Vite + React 19 + Tailwind + Vitest | Fatto |
| 2 | Login OIDC con PKCE | Fatto |
| 3 | Client API tipizzato | Fatto, ma i tipi non corrispondono alle risposte reali del backend |
| 4 | Layout e componenti condivisi | Fatto |
| 5 | Dashboard, Assets, Scores, Exposure, Analysis | Fatto, collegato al backend il 09/11 |
| 6 | Cases e Identities | Cases fatta e collegata; Identities solo API, pagina assente |
| 7 | Actors, Campaigns, Observables, Dark Web, Reports | Fatto, collegato al backend il 09/11 |
| Verifica di integrazione | stack reale con backend e Keycloak | Fatta il 09/11 (API + login dal browser) |

**Lavoro mancante per chiudere la fase 2** (non era nel piano, ma la spec §3 e §7 lo assegnano a questa fase):

1. ~~`backend/Dockerfile` e `backend/keycloak/realm-dev.json`.~~ Fatto il 09/11/2026.
2. ~~Contratto API unico e API mancanti.~~ Fatto il 09/11/2026 (passo 2), dettagli in `docs/STATO-PROGETTO.md`.
3. Pagina Identities nel frontend.
4. ~~Correggere la normalizzazione NVD (`cpe_nodes`).~~ Fatto il 09/11/2026 (passo 3).

## Fase 3 — ML, SIEM, notifiche, infrastruttura (non iniziata)

Piano: `docs/superpowers/plans/2026-10-24-sentinel-phase3-ml-infra.md`.

| Task | Contenuto |
|---|---|
| 1 | Classificatore dark web |
| 2 | Similarità IoC con FAISS |
| 3 | Forecast OLS dello score |
| 4 | Task Celery per l'indice FAISS e rotte ML |
| 5 | SIEM in entrata e in uscita |
| 6 | Pagine frontend di fase 3 (Scanner, Red Team, Connectors) |
| 7 | Infrastruttura K3s su Hetzner (`iac/`) |
| 8 | CI/CD (lint, pytest, vitest, build e push immagini) |

Da aggiungere a questa fase: notifiche Slack/email/webhook sulla transizione di livello, rate limit per tenant attivo, trigger append-only su `audit_logs`.

## Decisioni aperte

| Decisione | Opzioni |
|---|---|
| Taratura dello scoring | Deciso il 09/11/2026: il codice segue `Architettura.md` §5 (passo 4) con la formula moltiplicativa tarata su 12 scenari (passo 5, ScoreRule globale v2, migrazione `0006`). Restano aperti: lo scenario 5 (tante esposizioni medie sommate arrivano a Critical, va rivisto §5.3), lo scenario 6 (CVE in KEV su server interno esce Low, serve un minimo per KEV), `R_group` e `R_tenant`. |
| Funzioni della v10 (`SENTINEL_AI_v10.html`) | Deciso il 09/11/2026: portare nella piattaforma ciò che la v10 mostrava, un gruppo alla volta. Fatto: aspetto (tema scuro, barra laterale a gruppi) e inserimento di attori, campagne e observables (passo 6); casi completi con SLA, timeline e note (passo 7); pagina Management con chiavi API, audit e tenant (passo 8); import/export STIX 2.1 (passo 9); arricchimento con VirusTotal e archivio chiavi cifrato senza lettura (passo 10). Fatto anche: formula di scoring v3 (scenari 5 e 6) e Knowledge Graph con collegamenti indicatore-campagna (passo 11). Fatti anche (passo 12): spiegazione dello score per asset, Dark Web con findings e leak inseriti dall'analista (email solo come hash), Quick Report con più sezioni, CSV e stampa. Prossimi: AbuseIPDB e OTX (servono altre chiavi); `R_group` e `R_tenant`; collector Dark Web vero. Security Scanner e Red Team restano fuori dall'MVP di `Architettura.md`. |
| Exposure Intelligence | Priorità 2 del progetto: "Analyze Exposure" per cliente con spiegazione dello score (KEV, EPSS, esposizione, exploit). Non pianificata in nessuna fase. |
| Branch | Fare merge di `feature/phase1-backend` su `master` prima di iniziare la fase 3. |
