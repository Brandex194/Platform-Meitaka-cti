# Sentinel AI — Stato del progetto al 9 novembre 2026

Verifica fatta leggendo e testando il codice in `C:\Users\lucab\OneDrive\Desktop\claude progetti\piattaforma cti` (il rebuild iniziato il 23/10/2026). Il codice non è stato modificato.

## In sintesi

Il rebuild ha un backend di fase 1 solido e testato: la pipeline collector → normalizzazione → enrichment → correlazione → risk engine esiste, l'isolamento tenant (RLS + controllo token/path) è fatto bene e quasi tutti i difetti trovati nel reverse engineering del 23/10 sono stati evitati. Il frontend di fase 2 all'inizio **non funzionava contro questo backend** (8 endpoint inesistenti, risposte non paginate). **Sistemato il 09/11/2026 nel passo 2**, vedi in fondo.

Tre cose da decidere o sistemare prima di andare avanti (la terza è stata sistemata il 09/11, vedi in fondo):

1. ~~**Frontend e backend non si parlano** (dettaglio sotto).~~ **Sistemato il 09/11/2026**, vedi "Passo 2" in fondo. La fase 2 del piano ha costruito le pagine ma non le API di backend che la spec prevedeva (cases, identities, threat-actors, campaigns, reports).
2. ~~**Lo scoring del codice non segue le formule del progetto.**~~ **Deciso e fatto il 09/11/2026: il codice segue §5**, vedi "Passo 4" in fondo. Testo originale: Livelli spostati di un gradino (Critical da 0.9 invece che da 0.7), nessun `min(1, …)` sul rischio asset, nessun `E_exposure × I_impact`, nessuno score tenant. È una scelta tua: o si adegua il codice alle formule di `Architettura.md` §5, o si aggiornano le formule tramite una nuova `ScoreRule` versionata.
3. ~~**`docker compose up` non può partire**: mancano `backend/Dockerfile` e `backend/keycloak/realm-dev.json`.~~ **Sistemato il 09/11/2026**, vedi "Passo 1" in fondo.

## Dove sta il lavoro

| Cosa | Stato |
|---|---|
| Git | Tutti i 48 commit sono sul branch `feature/phase1-backend`, compresi quelli del frontend. `master` contiene solo il primo commit (spec e piani). Nessun remote configurato. |
| Ultimo commit | 04/11/2026, "feat: CTI catalog and reports pages (actors, campaigns, observables, dark web, reports)" |
| Spec | `docs/superpowers/specs/2026-10-23-sentinel-ai-design.md` |
| Piani | `docs/superpowers/plans/` — fase 1 backend (completata), fase 2 frontend (pagine fatte, verifica di integrazione non fatta), fase 3 ML/infra (non iniziata) |
| Registro esecuzione fase 1 | `.superpowers/sdd/2026-10-23-sentinel-phase1-backend/` (progress, decisioni R1–R6, review, final-fix-report) |
| Vecchio codice | Resta in `File piattaforma per mediaminer`, non toccato. Non serve al rebuild. |

## Comandi eseguiti il 09/11/2026

| Comando | Esito |
|---|---|
| `pytest` (backend, SQLite, senza Postgres/Redis) | **118 passati, 2 saltati** (i 2 test RLS che richiedono Postgres vero) |
| `ruff check` con le regole di default | 15 segnalazioni: 13 import non usati, 1 `== None`, 1 `== True`. Il repo non ha una configurazione ruff. |
| `bandit -r app` | 6 segnalazioni Low (`try/except/pass`), nessuna Medium/High |
| Frontend (`npm test`, typecheck, build) | **Non eseguito** in questa verifica. Anche se passasse, non direbbe nulla sul contratto con il backend perché i test usano mock MSW. |

Python 3.13 ora installa tutto senza problemi (`faiss-cpu>=1.8` ha wheel per la 3.13); il vincolo "solo 3.11/3.12" della revisione del 09/10 non vale più.

## I 10 difetti del reverse engineering (23/10), nel rebuild

| # | Difetto nel codice vecchio | Nel rebuild |
|---|---|---|
| 1 | NVD rileggeva sempre le CVE più vecchie | **Risolto.** `collectors/nvd.py` usa `lastModStartDate`/`lastModEndDate` dall'ultima run salvata in Redis (prima run: ultimi 90 giorni) e pagina fino a `totalResults`. |
| 2 | Lo score non scendeva mai | **Risolto.** `PATCH .../exposure-matches/{id}` mette `is_active=False` sul `CorrelationEvent`; il risk engine somma solo eventi attivi e scrive 0 per gli asset senza eventi. `f_recency` è ricalcolata a ogni run. |
| 3 | `ScoreRule.weights` ignorato | **Risolto.** Il risk engine legge pesi e soglie dalla regola attiva (prima quella del tenant, poi quella globale). API `POST`/`PATCH` con version bump e riga di audit; i pesi devono sommare a 1. |
| 4 | EPSS fuori dallo score | **Risolto.** `epss_boost = min(epss×2, 0.3)` con peso proprio. |
| 5 | Match CPE senza range di versione | **Risolto.** `enrichment/cpe.py` gestisce `versionStart/End Including/Excluding` e, dal 09/11 (passo 3), anche la versione fissata nel CPE della CVE. Se un estremo non è una versione valida il match resta positivo (scelta documentata nel codice). Fino al passo 3 il match non scattava mai perché la normalizzazione non salvava i CPE. |
| 6 | Pagine frontend su collection manuali `frontend_v9` | **Risolto lato frontend** (niente più `frontend_v9`), ma le API che dovrebbero sostituirle non esistono ancora: vedi sotto. |
| 7 | Leak di un cliente copiati in tutti i tenant | **Risolto per costruzione.** `leaks` ha `tenant_id` con RLS. Il collector HIBP però oggi restituisce sempre 0: è uno stub. |
| 8 | Alert mai inviati | **Parziale.** `check_and_notify` viene chiamato, ma scrive solo nel log, e le soglie (0.7 in salita, 0.3 in discesa) sono fisse nel codice invece di seguire la transizione di livello. Slack/email/webhook sono in fase 3. |
| 9 | Buchi RBAC | **Risolto per le API che esistono.** Ogni rotta tenant passa da `get_scoped_db`, che rifiuta un token di un altro tenant (403) salvo `super_admin`. Non esiste un endpoint per cancellare tenant. |
| 10 | KEV riscaricato per ogni CVE | **Risolto.** Tabella `kev_catalog` aggiornata una volta al giorno. |

## Frontend e backend non coincidevano (situazione prima del passo 2)

Il backend espone solo: `GET /health`, `GET|POST /tenants/{id}/assets`, `GET /tenants/{id}/scores`, `POST /tenants/{id}/scores/compute`, `GET /tenants/{id}/exposure-matches`, `PATCH /tenants/{id}/exposure-matches/{match_id}`, `POST /tenants/{id}/score-rules`, `PATCH /tenants/{id}/score-rules/{rule_id}`, `GET /dashboard`.

| Pagina | Cosa chiama il frontend | Problema |
|---|---|---|
| Dashboard | `GET /tenants/{id}/dashboard`, si aspetta `critical_scores`, `active_exposures`, `recent_events`, `scores_by_level` | Il backend ha `GET /dashboard` (senza tenant nel path) e restituisce solo `open_cases` e `top_assets` |
| Assets, Scores, Exposure | si aspettano `{items, total, page, size}` | Il backend restituisce una lista semplice: le tabelle restano vuote |
| Exposure → Resolve | `PATCH /exposure-matches/{id}` | Il backend vuole `/tenants/{id}/exposure-matches/{match_id}`: 404 |
| Analysis | `GET /tenants/{id}/correlation-events` | Non esiste |
| Cases | `GET|POST|PATCH|DELETE /tenants/{id}/cases` | Non esiste (la tabella `cases` c'è) |
| Actors, Campaigns | `GET /threat-actors`, `GET /campaigns` | Non esistono |
| Observables, Dark Web | `GET /indicators`, `GET /observations` | Non esistono |
| Reports | `GET /reports/quick` | Non esiste |

Altre incongruenze: il frontend usa il client OIDC `sentinel-ai`, il backend verifica l'audience `sentinel-api`; dal 09/11 il realm di sviluppo ha un audience mapper che lo risolve. La pagina Identities prevista dalla spec non esiste. Il piano di fase 2 non contiene nessun task di backend: la spec (§3, §7) invece metteva queste API in fase 2.

## Scoring: codice contro regole del progetto (situazione prima del passo 4)

| Regola (`Architettura.md` §5) | Codice (`app/risk/`) |
|---|---|
| `S_base = sev×0.5 + conf×0.3 + rec×0.2` | `sev×0.45 + conf×0.27 + rec×0.18 + epss_boost×0.10` (decisione R5 del registro di fase 1, per aggiungere EPSS) |
| `f_recency` a gradini (1.0 / 0.5 / 0.2) | lineare da 1.0 a 0 in 90 giorni |
| `f_confidence` dalla fonte | usa `s_context` dell'evento di correlazione |
| `S_context = S_base × E_exposure × I_impact` | non applicato: gli asset non hanno esposizione né impatto |
| `R_asset = min(1, Σ S_context × α_i)` | somma semplice senza tetto e senza pesi di dominio: può superare 1 |
| Livelli: Medium da 0.2, High da 0.4, Critical da 0.7 | Medium da 0.4, High da 0.7, Critical da 0.9 (0.9 fisso nel codice) |
| `R_group`, `R_tenant` con pesi β | non implementati (rimandati, decisione T11-R3) |

Il punto 2 del progetto ("Exposure Intelligence" con "why this score") non è ancora coperto: le exposure match restituite dall'API non includono CVE, score né spiegazione.

## Altri buchi noti

- Collector IoC, phishing e HIBP sono stub che restituiscono 0. NVD, KEV e ATT&CK sono reali.
- Regole di correlazione phishing→brand e campagna→asset sono stub (mancano colonne).
- Il rate limit per tenant (`app/auth/rate_limit.py`) esiste ma nessuna rotta lo usa.
- Le chiavi API in `Settings` sono `str` normali: l'hardening `SecretStr` del vecchio codice (24/09) non è stato riportato.
- `audit_logs` non è append-only: nessun trigger, e il ruolo applicativo `sentinel_app` ha DELETE su tutte le tabelle (migrazione 0002). La spec lo richiede.
- Doppia riga di audit (rotta + middleware) sulle modifiche a `ScoreRule` (rimandato, T13-R3).
- Nessun seed: senza dati inseriti a mano la piattaforma è vuota. Va bene, purché i dati di esempio futuri siano reali e verificabili.
- Nessuna CI (`.github/workflows/` non esiste), nessuna infrastruttura (`iac/` è in fase 3).

## Prossimi passi consigliati, in ordine

1. ~~Aggiungere `backend/Dockerfile` e il realm Keycloak di sviluppo.~~ Fatto il 09/11/2026.
2. ~~Allineare il contratto API: o il backend adotta la paginazione e il path `/tenants/{id}/dashboard`, o il frontend si adegua; poi le API mancanti (cases, correlation-events, threat-actors, campaigns, indicators, observations, reports).~~ Fatto il 09/11/2026.
3. ~~Correggere la normalizzazione NVD (`cpe_nodes`, CVSS).~~ Fatto il 09/11/2026.
4. ~~Decidere sullo scoring e coprirlo con test.~~ Fatto il 09/11/2026 (strada B). Resta la taratura dei pesi e `R_group`/`R_tenant`.
5. Exposure Intelligence con spiegazione dello score.
6. Merge di `feature/phase1-backend` su `master` e CI.

## Passo 1 fatto il 09/11/2026: lo stack parte

File aggiunti o modificati nel codice:

| File | Cosa |
|---|---|
| `backend/Dockerfile`, `backend/.dockerignore` | Immagine unica Python 3.12 per migrate, api, worker, beat; utente non root UID 1000 |
| `backend/keycloak/realm-dev.json` | Realm `sentinel` di sviluppo: 5 ruoli, client `sentinel-ai` (pubblico, PKCE S256), client `sentinel-api` (solo audience), mapper `tenant_id`, `roles` e audience, attributo `tenant_id` nel profilo utente, 5 utenti di prova |
| `backend/app/core/config.py`, `backend/app/auth/jwks.py` | Nuova impostazione facoltativa `KEYCLOAK_INTERNAL_URL` per scaricare le chiavi JWKS: dentro Docker `localhost:8080` non è Keycloak, ma l'issuer del token resta `http://localhost:8080/...` |
| `backend/tests/test_auth/test_jwks_url.py` | 2 test per la scelta dell'URL JWKS |
| `backend/docker-compose.yml` | `KEYCLOAK_INTERNAL_URL` per api e worker, commento "solo sviluppo" su Keycloak |
| `backend/pyproject.toml` | `kombu>=5.4,<5.5`: con kombu 5.7 worker e beat crashavano all'avvio (richiede redis-py 6.1, Celery 5.4 installa la 5.3) |
| `backend/alembic.ini` | `prepend_sys_path = .` così `alembic upgrade head` trova il pacchetto `app` nel container |
| `backend/.env.example` | Variabile `KEYCLOAK_INTERNAL_URL` |

Verifica eseguita (in un ambiente Linux con Docker, non sul tuo PC):

- `pytest`: 120 passati, 2 saltati. `ruff` e `bandit` puliti sui file toccati.
- `docker compose up`: tutti i servizi `Up`, `migrate` uscito con 0 dopo le 4 migrazioni su Postgres 16, realm importato da Keycloak 25.0.6.
- Token reale da Keycloak per `tenant.admin`: `iss` = `http://localhost:8080/realms/sentinel`, `aud` = `sentinel-api`, `tenant_id` e `roles` presenti.
- API con quel token: `GET /health` 200; senza token 401; `POST` e `GET` asset 201/200; `viewer` in scrittura 403; tenant diverso 403 "Tenant mismatch"; `super.admin` su un altro tenant 200; `/dashboard` 200; `scores/compute` 200; 2 righe in `audit_logs`.
- Worker: task `normalize` e `risk_and_alert` eseguiti senza errori.

Non verificato: login dal browser tramite il frontend, build dell'immagine sul tuo PC.

## Passo 2 fatto il 09/11/2026: frontend e backend si parlano

**Contratto.** Tutte le liste rispondono `{items, total, page, size}` con `?page=` (da 1) e `?size=` (1-200, default 50). I modelli di risposta sono in `backend/app/api/v1/schemas.py` e ricalcano `frontend/src/api/types.ts` campo per campo (controllato con uno script).

**API del backend dopo il passo 2** (tutte sotto `/api/v1`):

| Rotta | Chi scrive | Note |
|---|---|---|
| `GET/POST /tenants/{id}/assets` | super_admin, tenant_admin, api_user | |
| `GET/POST /tenants/{id}/assets/{asset_id}/software`, `DELETE .../software/{id}` | super_admin, tenant_admin, api_user | nuovo; il CPE deve essere `cpe:2.3:...`, serve alla correlazione |
| `GET /tenants/{id}/scores`, `POST .../scores/compute` | compute: super_admin, tenant_admin, analyst | la lista ora dà l'ultimo score per asset |
| `GET /tenants/{id}/exposure-matches?status=`, `PATCH .../{id}` | super_admin, tenant_admin, analyst | |
| `GET /tenants/{id}/dashboard` | lettura | sostituisce `GET /dashboard` |
| `GET /tenants/{id}/correlation-events?active=` | lettura | nuovo |
| `GET/POST/PATCH/DELETE /tenants/{id}/cases` | super_admin, tenant_admin, analyst | nuovo |
| `GET/POST /tenants/{id}/identities` | super_admin, tenant_admin, analyst | nuovo, nessuna pagina frontend |
| `GET /tenants/{id}/indicators?ioc_type=` | lettura | nuovo; IOC globali + del tenant |
| `GET /tenants/{id}/observations?event_type=` | lettura | nuovo |
| `GET /tenants/{id}/reports/quick` | lettura | nuovo; top 10 CVE delle esposizioni attive (prima KEV, poi EPSS, poi CVSS) e media giornaliera dello score a 30 giorni |
| `GET /threat-actors`, `GET /campaigns` | lettura | nuovi, catalogo comune; le campagne di altri tenant sono nascoste (la tabella non ha RLS, il filtro è nel codice) |

Il frontend ora chiama i path con il tenant (`exposure-matches/{id}`, `indicators`, `observations`, `reports/quick`), `Software` ha il campo `cpe` e la dashboard non si rompe se mancano gli eventi recenti.

**Corretto anche:** un errore di validazione con messaggio personalizzato (es. CPE sbagliato) rispondeva 500 invece di 422, perché il gestore errori non riusciva a convertire l'eccezione in JSON. Ora usa `jsonable_encoder`.

**Verifica:**
- backend `pytest`: 145 passati, 2 saltati (27 test nuovi: paginazione, software, cases, catalogo, IOC, osservazioni, eventi, report, dashboard);
- frontend `vitest`: 40 passati (12 nuovi in `tests/api/endpoints.test.tsx`, che controllano il path chiamato da ogni hook); `npm run build` ok;
- `ruff` sui file toccati: restano solo B008 (`Depends` negli argomenti, idioma di FastAPI, presente anche nel codice esistente); `bandit`: nessun problema nei file nuovi (i 5 `try/except/pass` segnalati sono in file preesistenti);
- stack Docker reale con Keycloak e Postgres con RLS: tutte le rotte sopra con token veri (201/200, viewer in scrittura 403, CPE sbagliato 422, altro tenant 403);
- login dal browser (Playwright) con `tenant.admin` e visita di tutte le 11 pagine: tutte le chiamate API 200, dashboard con i numeri reali.

**Non verificato:** `PATCH` di un'esposizione sullo stack reale (non ce ne sono, per il bug NVD sopra; è coperto dai test); `eslint` del frontend non parte perché manca la configurazione (problema preesistente).

## Passo 3 fatto il 09/11/2026: le esposizioni nascono

**Il problema.** `normalize/engine.py` salvava di una CVE solo id, descrizione e CVSS v3.1. Le configurazioni CPE di NVD (quali prodotti e versioni sono colpiti) andavano perse, quindi `cpe_nodes` restava vuoto e la regola `vuln_software` non trovava mai niente.

**Cosa è cambiato:**
- `normalize/engine.py` ora legge `configurations` (formato NVD 2.0) e salva in `cpe_nodes` le voci `cpeMatch` con `vulnerable: true`, con i range di versione. Salta i nodi negati, i doppioni e le voci di piattaforma (`vulnerable: false`, cioè "gira su").
- CVSS: prima v3.1, poi v4.0, v3.0, v2; dentro la stessa versione vince la valutazione "Primary" di NVD. Salva anche il vettore (`cvss_vector`). La descrizione è quella in inglese. Le formule di scoring non sono toccate: cambia solo che le CVE senza v3.1 adesso hanno un CVSS invece di niente.
- `enrichment/cpe.py`: se NVD indica una versione precisa nel CPE (es. `http_server:2.4.49`) senza range, ora conta solo quella versione. Prima ogni versione del prodotto dava match a 0.5, quindi una volta salvati i CPE sarebbero nate esposizioni false (es. 2.4.51 segnalato come vulnerabile).

**Limite noto (scritto nel codice):** le configurazioni "AND" (es. "prodotto X solo se gira su sistema Y") vengono appiattite: basta X per il match.

**Dati già scaricati:** le CVE salvate prima di questo passo hanno `cpe_nodes` vuoto. Si riempiono quando NVD le rimanda (cioè quando vengono modificate). Per ricaricarle subito: `docker compose exec redis redis-cli DEL nvd:last_run` e poi `collect_nvd` (rilegge gli ultimi 90 giorni). È scritto anche in GUIDA.md.

**Verifica:**
- `pytest`: 158 passati, 2 saltati (13 nuovi: estrazione CPE, nodi negati e doppioni, CVSS con ripieghi, versione fissata, e un test che va dal record NVD all'esposizione);
- stack Docker reale: due asset con Apache 2.4.49 e 2.4.51, un record nel formato NVD per CVE-2021-41773 messo nello stream, poi `normalize` e `correlate`. Risultato: 1 esposizione, solo sul 2.4.49 (confidenza 0.9), visibile in Exposure, Analysis, dashboard e report rapido. `PATCH` "resolved" con `analyst` 200 e l'evento esce dagli attivi;
- `ruff` sui file toccati: nessun problema nuovo.

**Non verificato:** il download vero da NVD. Da questo ambiente `services.nvd.nist.gov` non è raggiungibile, quindi il record di prova l'ho scritto io nel formato NVD 2.0. Va provato sul tuo PC lanciando `collect_nvd`.

## Passo 4 fatto il 09/11/2026: lo scoring segue Architettura §5

**Decisione dell'utente:** strada B, cioè il codice si adegua alle formule ufficiali. Il confronto che l'ha preceduta è nel documento "Scoring Sentinel: codice attuale o formule di Architettura §5" (script: `docs/note/confronto-scoring-2026-11-09.py` nei file del progetto).

**Cosa calcola ora il risk engine:**
- `S_base` = gravità × 0.5 + confidenza × 0.3 + recency × 0.2. La gravità è CVSS/10 (0.6, "Media", se manca). La confidenza è 1.0 per le CVE in CISA KEV, altrimenti quella del match CPE. La recency va a gradini: 1.0 sotto 7 giorni, 0.5 fino a 30, 0.2 oltre.
- `S_context` = `S_base` × esposizione × impatto dell'asset (internet 1.0, DMZ 0.5, interno 0.2; critico 1.0, business 0.6, non critico 0.3).
- `R_asset` = min(1, somma di `S_context` × α), con α 1.0 vulnerabilità, 0.8 leak, 0.5 IoC, 0.4 phishing, 0.2 altro.
- Livelli: low sotto 0.2, medium sotto 0.4, high sotto 0.7, critical da 0.7.

**Scelte prese da me, da confermare:** un asset non classificato conta come internet e critico, così nessun rischio viene sottostimato. KEV entra come confidenza 1.0, perché §5 la definisce "confermata in incidenti reali". L'EPSS resta disponibile come quarto peso della ScoreRule, a 0 di default. Tutto si cambia con una nuova versione di ScoreRule, senza toccare il codice.

**Cosa è cambiato nel codice:**
- Migrazione `0005`: colonne `exposure` e `impact` sugli asset (con vincolo sui valori), `parameters` sulle ScoreRule, `score_rule_id` e `score_rule_version` sugli score, nuova ScoreRule globale con i valori di §5. La policy RLS di `score_rules` ora lascia leggere le regole globali da una sessione di tenant, ma non scriverle: senza questo, il ricalcolo dall'API ignorava la regola globale.
- `app/risk/formulas.py` riscritto, `app/risk/engine.py` aggiornato. Le regole create prima (senza `parameters.formula`) vengono ignorate, perché i loro pesi erano pensati per l'altra formula.
- API: `POST` e `PATCH /tenants/{id}/assets/{asset_id}` accettano `exposure` e `impact`. `POST/PATCH .../score-rules` accettano `parameters` (validati) e controllano che le soglie siano in ordine. Ogni score dice con quale versione di regola è stato calcolato.
- Frontend: nella pagina Assets due menu per esposizione e impatto (modificabili da tenant admin, super admin e API user).

**Verifica:**
- `pytest`: 200 passati, 2 saltati. Ogni termine di §5 ha il suo test, e i 7 scenari del confronto sono test di regressione con i valori attesi.
- `vitest`: 43 passati; `npm run build` ok.
- Stack Docker reale: migrazione 0005 applicata, tolta e riapplicata. Tre asset con Apache 2.4.49 e la CVE-2021-41773 messa in KEV: web esposto e critico 0.875 critical, DMZ e business 0.263 medium, interno e non critico 0.052 low. Con una regola di tenant v2 che porta la DMZ a 0.8, lo stesso asset passa a 0.42 high e lo score riporta "versione 2". Da una sessione di tenant la regola globale si legge, mentre scriverla o crearne una è rifiutato da Postgres.
- Browser: nella pagina Assets il cambio di impatto salva (PATCH 200).

**Non fatto:** la taratura dei pesi (con quelli di §5 una CVE media trovata oggi su un asset esposto e critico è già critical), `R_group` e `R_tenant`, e la spiegazione dello score nell'Exposure Intelligence. Gli score calcolati prima restano nel database con la vecchia scala, fino al prossimo ricalcolo.

## Passo 5 fatto il 09/11/2026: formula moltiplicativa tarata

**Decisione dell'utente:** accettati i livelli attesi dei 12 scenari e adottata la formula moltiplicativa proposta nel documento "Taratura dello scoring Sentinel" (script di ricerca in `docs/note/taratura-2026-11-09/` nei file del progetto).

**Cosa calcola ora il risk engine:**
- `S_base` = gravità × (confidenza × 0.3 + recency × 0.3 + EPSS × 0.4), dove l'EPSS vale min(EPSS × 2, 0.3) / 0.3. La gravità moltiplica tutto: una CVE debole resta debole anche se è di oggi.
- Esposizione: internet 1.0, DMZ 0.7, interno 0.3. Impatto: critico 1.0, business 0.7, non critico 0.4.
- `α`, `min(1, …)`, livelli e asset non classificato (1.0 × 1.0) invariati.

**Cosa è cambiato nel codice:**
- `app/risk/formulas.py`: due formule, `"architettura-5"` (additiva, passo 4) e `"architettura-5-moltiplicativa"` (default), ciascuna con i suoi pesi e fattori. La ScoreRule sceglie con `parameters.formula`.
- `app/risk/engine.py`: legge la formula dalla regola; ignora le regole con formula sconosciuta.
- API `score-rules`: valida `formula`; una regola nuova senza pesi prende quelli della sua formula.
- Migrazione `0006`: nuova ScoreRule globale versione 2 con la formula moltiplicativa. La versione 1 (additiva) resta nel database; il downgrade toglie solo la v2.

**Verifica:**
- `pytest`: 220 passati, 2 saltati. `ruff` pulito sui file toccati.
- I 12 scenari della taratura sono test: 10 al livello atteso, 5 e 6 documentati come mancati.
- Stack Docker reale: migrazione 0006 applicata, tolta e riapplicata. Stessa CVE in KEV (CVSS 7.5, EPSS di prova 0.94): web esposto e critico 0.75 critical, DMZ e business 0.367 medium, interno e non critico 0.09 low. Gli score riportano la regola versione 2.

**Non fatto:** scenario 5 (tante esposizioni medie sommate arrivano a critical, va rivisto §5.3), scenario 6 (CVE in KEV su server interno esce low, serve un minimo per KEV), `R_group` e `R_tenant`, spiegazione dello score nell'Exposure Intelligence, download vero da NVD. Per applicare la `0006` sul tuo PC va riavviato lo stack (il servizio `migrate` applica la migrazione all'avvio).

## Passo 6 fatto il 09/11/2026: aspetto della v10 e inserimento di attori, campagne, observables

**Decisione dell'utente:** "stesso aspetto su Meitaka CTI" e, partendo dal "lavoro quotidiano", le funzioni che la v10 (`SENTINEL_AI_v10.html`, vecchio prototipo in un solo HTML) mostrava. Ho letto solo l'interfaccia della v10, non ho verificato quali sue funzioni lavorassero davvero.

**Aspetto:** tema scuro blu/slate ripreso dalla v10, senza glow né animazioni (le istruzioni di progetto chiedono un tono enterprise sobrio). Variabili di colore in `frontend/src/index.css`, barra laterale a gruppi (Intelligence, Operations, Knowledge Base) con icone, titolo di pagina, tabelle e badge nuovi, font Inter e JetBrains Mono da Google Fonts. Nei menu di Assets ho tolto i numeri tra parentesi ("DMZ (0.5)"): erano della vecchia formula e con la v2 erano sbagliati.

**Inserimento da frontend e API:**
- `POST/PATCH/DELETE /tenants/{id}/threat-actors`, `/campaigns` e `POST/DELETE /tenants/{id}/indicators`, per `analyst`, `tenant_admin` e `super_admin`.
- Migrazione `0007`: `threat_actors.tenant_id` (NULL = catalogo comune). `GET /threat-actors` ora mostra gli attori comuni e quelli del proprio tenant; prima li mostrava tutti.
- Si modificano e cancellano solo le voci del proprio tenant. Una campagna può puntare a un attore comune o del proprio tenant, mai di un altro. Cancellando un attore, le sue campagne restano senza collegamento. Un indicatore uguale (stesso tipo e valore, domini ed email senza maiuscole) nello stesso tenant dà 409.
- Pagine Threat Actors, Campaigns e Observables con moduli di creazione e modifica, colonna "Source" (yours, shared, feed) e conferma prima di cancellare.

**Bug trovato e sistemato:** il client API provava a leggere il corpo anche delle risposte 204, quindi ogni cancellazione dal frontend (anche dei casi) mostrava "Unexpected end of JSON input" e la tabella non si aggiornava. Ora la 204 è gestita e c'è un test.

**Verifica:**
- `pytest`: 237 passati, 2 saltati. `bandit`: nessun problema di livello medio o alto. `ruff`: restano solo i B008 che c'erano già.
- `vitest`: 57 passati; `npm run build` ok.
- Stack Docker reale: migrazione 0007 applicata su database nuovo. Con l'analista creati attore, campagna e observable; viewer rifiutato (403); duplicato (409); confidenza 1.5 (422); attore di un altro tenant non visibile e non modificabile (404); una campagna non può puntare a un attore altrui; cancellato l'attore, la campagna resta senza attore.
- Browser con login vero su Keycloak: creati attore, campagna collegata e observable, errore "already exists" mostrato nel modulo, modifica e cancellazione dell'attore con la riga che sparisce.

**Non fatto:** modifica degli observables; modifica o cancellazione delle voci comuni da parte di `super_admin`; i casi completi (passo 7). Non provato: la migrazione 0007 su un database già pieno (solo su uno nuovo).



## Passo 7 fatto il 09/11/2026: casi completi (SLA, timeline, note)

- **Stati**: `open`, `in_progress` ("In analysis"), `closed`, `false_positive`. Aperti = open + in_progress (la dashboard e il report contano così). Chiusi = closed + false_positive.
- **SLA**: alla creazione `due_at = created_at + ore per severità` (critical 4 h, high 24 h, medium 72 h, low 168 h; scelta mia, da confermare con i clienti, in `app/cases/sla.py`). Cambiando severità la scadenza si ricalcola da `created_at`. `sla_status` è calcolato: `on_track`, `at_risk` (resta meno del 25% del tempo), `breached`, `met` (chiuso entro la scadenza; chiuso in ritardo = `breached`), `none`.
- **Timeline**: ogni scrittura registra un evento (`created`, `status_changed {from,to}`, `severity_changed`, `edited`, `note_added`, `note_deleted`) in `case_events`, con chi l'ha fatto. `GET .../cases/{id}/timeline`, dal più recente.
- **Note**: `GET/POST .../cases/{id}/notes`, `DELETE .../notes/{note_id}` (1–20000 caratteri, mostrate come testo semplice, mai come HTML). Le scrive chi può scrivere (analyst, tenant.admin, super.admin); le cancella l'autore o un admin del tenant.
- **Migrazione 0008**: colonne `cases.due_at`/`closed_at` (con backfill dei casi esistenti), tabelle `case_notes` e `case_events` con RLS forzata e GRANT a `sentinel_app`. Verificata su Postgres reale: upgrade, downgrade, upgrade.
- **Frontend**: filtro per stato, colonna SLA, clic sul titolo apre il pannello con descrizione, scadenza, azioni rapide (Analyze, Close, False positive, Reopen), tab Notes e Timeline. Corretto un bug: modificando un caso la descrizione non veniva inviata.
- **Verifiche**: pytest 267 passati/2 saltati, vitest 63, tsc e build ok, ruff senza nuovi errori (solo il B008 tipico di FastAPI), flusso completo con token Keycloak reali e nel browser (crea, analizza, nota, timeline, falso positivo, filtro).
- **Non verificato**: migrazione 0008 su un database con molti casi già presenti; ruolo viewer nel browser (verificato via API: 403 sulla scrittura, lettura ok).


## Passo 8 e 9 fatti il 09/11/2026: pagina Management e STIX 2.1

**Management** (menu "Administration", solo `tenant_admin` e `super_admin`):
- **Chiavi API**: si creano dalla pagina (nome, scadenza in giorni o mai). La chiave intera si vede una volta sola, nel DB resta solo l'hash SHA-256. Una chiave si usa con l'header `X-API-Key`, vale per un solo tenant e ha il ruolo `api_user` (letture e scrittura asset; non può gestire chiavi). Si revoca, non si cancella: la riga resta. Il Bearer di Keycloak, se presente, ha la precedenza.
- **Audit log**: elenco paginato e filtrabile delle scritture del tenant (quando, azione, esito, utente, IP, se via chiave API). Prima l'audit non registrava utente, IP ed esito.
- **Tenants** (solo `super_admin`): elenco, creazione (slug fisso) e modifica di nome e settore. Creare un tenant crea solo l'anagrafica: gli utenti si creano a mano in Keycloak con l'attributo `tenant_id`.
- **Roles**: tabella di riferimento. Utenti e ruoli restano in Keycloak, non c'è una gestione utenti nella piattaforma.
- Migrazione **0009**: tabella `api_keys` (RLS forzata, GRANT), `audit_logs.ip` e `status_code`, `audit_logs.action` da 100 a 255 caratteri. **Bug trovato e corretto**: con 100 caratteri le righe d'audit dei DELETE con percorso lungo (per esempio cancellare una nota di un caso, 130 caratteri) non venivano scritte e il middleware lo nascondeva.

**STIX 2.1** (menu Knowledge Base, `analyst`, admin, `api_user`; il viewer no):
- **Export**: bundle con indicatori, attori e campagne visibili al tenant (catalogo comune incluso, oppure solo i propri con `own_only=true`), più la relazione `attributed-to` campagna → attore. Gli id sono i nostri UUID, quindi due export danno gli stessi id. Gli observable che non si possono scrivere come pattern (per esempio un hash di lunghezza strana) restano fuori, contati in `X-Stix-Skipped`.
- **Import**: indicatori con un solo confronto (`ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `email-addr`, `file:hashes` MD5/SHA-1/SHA-256/SHA-512), attori, campagne e `attributed-to`. Tutto ciò che si crea è del tenant che importa. I duplicati (stesso tipo e valore, stesso nome senza distinzione di maiuscole, anche rispetto al catalogo comune) si contano e non si toccano: importare due volte lo stesso file non cambia nulla. Il resto è elencato con il motivo (pattern complessi con AND/OR, tipi non supportati come malware, revocati, id non validi, IP non valido). Limiti: 10 MB, 5000 oggetti; risposta con al massimo 100 motivi (il totale è esatto).
- **Non c'è ancora il Knowledge Graph**: gli indicatori non sono collegati alle campagne nel database, quindi il grafico avrebbe solo attori e campagne. Le relazioni diverse da `attributed-to` (`indicates`, `uses`) oggi vengono saltate, dichiarate nel risultato.
- **Verifiche**: pytest 330 passati/2 saltati, vitest 77, tsc e build ok, ruff senza nuovi errori oltre al B008 di FastAPI, bandit senza problemi sul codice nuovo. Su stack reale con token Keycloak veri: chiave API creata, usata, bloccata sul tenant sbagliato, revocata (401 dopo); tenant creato e slug duplicato rifiutato; import di un bundle scritto a mano, secondo import senza effetti, export con tipo `application/stix+json;version=2.1`; browser: Management (chiavi, audit, tenant) e STIX (download e upload).
- **Non verificato**: import di un bundle reale prodotto da un altro strumento (MISP, OpenCTI); con un'altra fonte potrebbero comparire pattern che oggi saltiamo; migrazione 0009 su un database con molte righe d'audit.


## Passo 10 fatto il 09/11/2026: arricchimento con VirusTotal e chiavi che non si possono leggere

- **Chiavi di servizi esterni** (Management → Integrations, solo `tenant_admin` e `super_admin`): una chiave per tenant e per servizio, oggi solo VirusTotal. Si aggiunge, si sostituisce, si rimuove. **Non si può mai rileggere**: la pagina non la riceve, l'API non la restituisce nemmeno a un admin (la lista dice solo "configurata" e quando è cambiata), il campo è di tipo password e si svuota dopo il salvataggio. Una chiave dal formato sbagliato viene rifiutata senza ripeterla nella risposta.
- **Cifratura**: nel database c'è solo il testo cifrato (Fernet). La chiave principale è `SECRETS_ENCRYPTION_KEY`; senza, salvare una chiave dà 503 (nessun ripiego in chiaro). Nel `docker-compose.yml` c'è un valore **solo per sviluppo**, noto a chi legge il repo: per un uso vero metti il tuo in `backend/.env` (comando per generarlo in `.env.example`). Se la chiave principale cambia, le chiavi salvate non si decifrano più e vanno reinserite (il sistema lo dice).
- **Enrich**: negli Observables, per ip, domain, url e hash, il pulsante Enrich (Refresh se c'è già un verdetto) chiede a VirusTotal e mostra rilevazioni su motori totali (`4/70`) con link alla scheda su VirusTotal. Si salvano solo i numeri (malevoli, sospetti, innocui, non rilevati, reputazione, data analisi). Lo fanno `analyst` e admin; il viewer vede i verdetti ma non può chiedere. Un indicatore sconosciuto a VirusTotal è segnato "unknown to VT". Errori chiari: chiave rifiutata (409), limite di richieste raggiunto (429: le chiavi gratuite fanno 4 richieste al minuto e 500 al giorno), servizio non raggiungibile (502).
- Migrazione **0010**: `integration_keys` e `indicator_enrichments` con RLS forzata e GRANT. Nuova dipendenza `cryptography`.
- **Verifiche**: pytest 368 passati/2 saltati, vitest 82, tsc e build ok, ruff senza nuovi errori (solo B008), bandit senza problemi. Su stack reale con una chiave finta: salvata, cifrata nel DB (nessuna traccia in chiaro), assente da risposte, audit log e log dell'API; formato errato rifiutato; analyst riceve 403 sulla gestione; senza chiave l'enrich dà 409. Nel browser: campo password, vuoto alla riapertura.
- **Non verificato**: la chiamata vera a VirusTotal, perché dalla sandbox non è raggiungibile; è testata solo con risposte simulate. La prima prova reale è sul PC, con la tua chiave.
- **Da fare dopo**: AbuseIPDB e OTX (stessa struttura: serve solo un nuovo provider), arricchimento automatico dei nuovi indicatori, uso del verdetto nello scoring.


## Passo 11 fatto il 09/11/2026: scoring v3 (scenari 5 e 6) e Knowledge Graph

**Scoring, formula `architettura-5-moltiplicativa-v3` (ora il default, ScoreRule globale versione 3, migrazione 0011).** Stessi pesi, esposizione e impatto della moltiplicativa; due cambi:
- **Scenario 5 (tante esposizioni medie → critical)**: §5.3 rivisto. La somma semplice diventa una somma a pesi decrescenti: i contributi si ordinano dal più alto, il primo conta intero, il secondo ×0.5, il terzo ×0.25 e così via (`aggregation_decay` 0.5), con tetto 1. Cinque CVE da 5.0 su un asset esposto e critico passano da 1.0 critical a 0.433 high; il totale di qualsiasi numero di risultati non supera il doppio del maggiore.
- **Scenario 6 (CVE in KEV su server interno → low)**: `kev_floor` 0.25. Una CVE nel catalogo KEV contribuisce almeno 0.25 (medium) qualunque sia l'asset. Passa da 0.12 low a 0.25 medium. Non abbassa mai uno score più alto.
- Tutti i 12 scenari della taratura sono ora al livello approvato (test per ciascuno). Le regole che usano le formule precedenti non cambiano comportamento (niente decadimento, niente minimo). Gli score già calcolati restano nel DB finché non si ricalcola; i nuovi riportano "versione 3". I valori 0.5 e 0.25 sono una mia scelta, da confermare.
- **Ancora aperti**: `R_group` e `R_tenant`, spiegazione dello score nell'Exposure Intelligence.

**Knowledge Graph** (menu Knowledge Base → Graph, migrazione 0012):
- **Collegamenti indicatore ↔ campagna** (`campaign_indicators`, RLS forzata): "questo indicatore è stato visto in questa campagna". Il collegamento è del tenant che lo crea; campagna e indicatore possono essere propri o del catalogo comune. Si fanno dal pannello del grafo (analyst e admin): si seleziona una campagna, si sceglie un indicatore e si preme Connect; Unlink li toglie. Cancellare una campagna o un indicatore toglie anche i suoi collegamenti.
- **Grafo**: tre colonne, attori → campagne → indicatori, con la relazione "attribuita a" (già esistente) e "indicates" (nuova). Selezionando un nodo si evidenziano le sue connessioni e un pannello le elenca. Contorno tratteggiato = catalogo comune o feed. Si disegnano al massimo 500 indicatori collegati, con avviso se ce ne sono di più. Solo gli indicatori collegati compaiono. Letto da tutti i ruoli del tenant, mai nodi o collegamenti di altri tenant.
- **STIX**: l'export include `indicates` (indicatore → campagna) quando entrambi sono nel bundle; l'import crea i collegamenti (anche verso una campagna del catalogo comune, senza duplicarla) e segnala quelli che puntano a oggetti non importati. La pagina STIX ha la colonna "Links".
- **Verifiche**: pytest 402 passati/2 saltati, vitest 89, tsc e build ok, ruff senza nuovi errori oltre al B008. Su stack reale: migrazioni 0011 e 0012 applicate e riapplicate (RLS forzata sulla nuova tabella); su Postgres con il motore vero, cinque CVE da 5.0 → 0.433 high, KEV su asset interno e non critico → 0.25 medium, entrambi con regola versione 3; nel browser si creano attore e campagna, si collegano due indicatori dal pannello e il grafo si disegna con le connessioni.
- **Non verificato**: grafo con centinaia di nodi (il layout è fisso a colonne e scorre in verticale; il browser è stato provato con una decina); le prestazioni sopra i 500 indicatori collegati.


## Passo 12 fatto il 10/11/2026: spiegazione dello score, Dark Web, Quick Report

**Spiegazione dello score** (pagina Scores, bottone "Explain" su ogni riga; nessuna migrazione):
- `GET /tenants/{t}/assets/{id}/score-explanation` (tutti i ruoli del tenant, 404 se l'asset non è del tenant). Il calcolo per asset è ora una sola funzione (`asset_breakdown` in `risk/engine.py`) usata sia per salvare lo score sia per spiegarlo: la spiegazione non può divergere dal valore salvato (c'è un test).
- Il pannello mostra: totale e livello con le soglie, regola e formula usate, esposizione e impatto dell'asset con i loro fattori (e l'avviso "non classificato = caso peggiore"), poi una riga per ogni finding con CVE, CVSS, EPSS, KEV (e se il minimo KEV è scattato), base, base × contesto, α, contributo, peso di decadimento e valore contato; infine la somma, con il tetto a 1 se supera.
- Viene ricalcolata al momento della richiesta: se i dati sono cambiati dopo l'ultimo calcolo, può differire un poco dallo score salvato (lo dice il pannello). Anche l'Exposure Intelligence resta com'era: la spiegazione sta in Scores.

**Dark Web** (nessun crawler: l'app non va sul dark web, registra ciò che trova l'analista o un servizio esterno):
- **Findings**: fonte, descrizione, gravità (low/medium/high/critical), stato (new/reviewed/dismissed), salvati come observation `darkweb`. `POST/PATCH/DELETE /tenants/{t}/darkweb/findings`.
- **Leaks**: email + nome del breach + numero di account. L'email viene salvata solo come SHA-256 del testo minuscolo, mai in chiaro; la stessa email nello stesso breach dà 409. I leak registrati alimentano la regola di correlazione `leak_identity` già esistente (verificato da un test). `GET/POST/DELETE /tenants/{t}/darkweb/leaks`.
- Scrivono analyst, tenant_admin, super_admin; il viewer legge. Il collector HIBP resta uno stub.

**Quick Report** (pagina Reports): nuovi dati nella stessa risposta (i campi vecchi non cambiano): asset per livello di rischio e quelli senza score, i 5 asset più a rischio, casi oltre SLA e casi a rischio SLA, vulnerabilità in KEV (campo sulla vulnerabilità o catalogo KEV), email in leak, findings Dark Web nuovi. Pagina: otto schede, barra per livello, tabella dei 5 asset, **Download CSV** (un file con riepilogo, asset, vulnerabilità e andamento; le celle che iniziano con `=`, `+`, `-`, `@` sono neutralizzate contro le formule di Excel) e **Print / PDF** (stile di stampa chiaro, senza menu).

**Verifiche**: pytest 417 passati/2 saltati, vitest 96, tsc e build ok. Su stack reale (Postgres con RLS, Keycloak): spiegazione di un asset con 8 finding = valore salvato (1.0 critical), viewer di un altro tenant 403, findings e leak creati/cambiati/cancellati con il ruolo giusto (viewer 403, duplicato 409), report con i conteggi giusti; nel browser spiegazione, Dark Web (aggiunta finding, cambio stato, aggiunta leak), download del CSV e anteprima di stampa.
**Non verificato**: la stampa su carta/PDF vera (provata l'anteprima in modalità print del browser); asset con centinaia di finding nella spiegazione (la tabella scorre, non c'è paginazione).
**Ancora da fare**: collector Dark Web vero (fonte esterna da scegliere), AbuseIPDB/OTX (servono chiavi), `R_group` e `R_tenant`.

**Dati dimostrativi (10/11/2026, dopo il passo 12)**: `python -m app.demo.seed` (script `carica-demo.ps1`) carica nel tenant di prova 8 asset con software, 8 vulnerabilità finte (`CVE-2099-D*`, vendor `demovendor`, due in KEV), indicatori in intervalli di indirizzi di documentazione, 3 attori e 3 campagne collegate, 5 identità con 2 leak, 4 findings Dark Web e 5 casi con note e timeline. Le esposizioni, i findings e gli score non sono scritti a mano: li producono il motore di correlazione e quello di rischio, più una breve storia di score per il grafico. `--reset` ricarica, `--remove` toglie; vengono toccate solo le righe con i marcatori demo (verificato da test). Verificato su Postgres reale (carica, secondo giro "skipped", reset). Trovato lungo la strada: la confidenza degli indicatori si salva da 0 a 1 (la UI converte la percentuale); GUIDA.md diceva "0-100" per l'utente, che resta giusto.
