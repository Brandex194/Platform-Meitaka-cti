> **Documento storico.** Si riferisce al vecchio codice di Sentinel AI (cartella `Desktop\File piattaforma per mediaminer`), sostituito dal rebuild iniziato il 23/10/2026. Sostituito da `IMPLEMENTATION_PLAN.md` nella radice. Conservato così com'era per riferimento; lo stato attuale è in `docs/STATO-PROGETTO.md`.

---

# Piano di Implementazione - Sentinel AI

Data: 26 maggio 2026  
Versione: 0.1  
Fonte: Architettura.md

## 1. Obiettivo del piano

Tradurre l'architettura in un percorso esecutivo progressivo, con focus MVP fase 1:
- Ingest base (CVE, IoC, Leak).
- Pipeline normalizzazione, enrichment, correlazione, scoring.
- API e dashboard cliente per esposizione rischio.
- Sicurezza multi-tenant e audit fin da subito.

## 2. Principi di implementazione

- Start lean: PostgreSQL + Redis Streams + FastAPI + Celery.
- No componenti phase-2 come default (Neo4j, GraphQL esteso, feed enterprise).
- Multi-tenant by design: isolamento dati e controlli accesso in tutte le query.
- Scoring tracciabile: regole versionate, audit su cambi pesi/soglie.
- Ogni incremento deve essere deployabile e testabile end-to-end.

## 3. Struttura del lavoro (Workstreams)

### WS1 - Foundation e piattaforma
- Setup repository backend/frontend e struttura moduli.
- Docker Compose dev stack: API, worker, redis, postgres.
- Config centralizzata (env + YAML/JSON).
- Logging e tracing base.

Deliverable:
- Bootstrap progetto avviabile in locale con un comando.

### WS2 - Data model e persistenza
- Schema PostgreSQL per entita core: Tenant, Asset, Identity, Vulnerability, Indicator, Leak, Observation, Source, Score, ScoreRule, Case.
- Migrazioni versionate (Alembic).
- Indici su campi critici (tenant_id, timestamp, value, cve_id).
- Row level security per tenant.

Deliverable:
- Schema DB stabile per MVP + migrazione iniziale + seed base.

### WS3 - Collectors e ingest
- Collector CVE (NVD), IoC (AbuseIPDB/GreyNoise free), Leak (feed iniziale o import controllato).
- Scheduler e retry/backoff per sorgente.
- Validazione schema input e gestione errori.
- Pubblicazione su raw-observations.

Deliverable:
- Ingest continuo con metriche record ricevuti/scartati.

### WS4 - Normalizzazione, dedup, enrichment
- Parsing e normalizzazione formati (STIX/JSON/CSV dove applicabile).
- Dedup di entita e merge osservazioni.
- Enrichment per IoC, CVE e Leak.
- Pubblicazione su enriched-entities.

Deliverable:
- Entita normalizzate e arricchite persistite su DB.

### WS5 - Correlation e Risk Engine
- Regole correlazione MVP:
  - IoC <-> Asset
  - CVE <-> stack software asset
  - Leak <-> Identity
- Calcolo S_base, S_context, R_asset, R_tenant.
- Versionamento ScoreRule e invalidazione cache.
- Eventi correlation-events e alert su soglie.

Deliverable:
- Scoring aggiornato automaticamente e consultabile via API.

### WS6 - API, Auth e Client Dashboard
- REST API v1 per CRUD e viste rischio.
- Auth OIDC/JWT con ruoli base.
- Endpoint dashboard cliente: score, trend, top driver.
- WebSocket per notifiche critiche.

Deliverable:
- Dashboard cliente funzionante su dati reali ingestiti.

### WS7 - Qualita, sicurezza e operations
- Test unit e integrazione su pipeline.
- Controlli sicurezza: secret management, rate limiting, audit.
- CI con lint, test, scan immagini.
- Runbook operativo minimo.

Deliverable:
- Pipeline CI stabile e baseline di sicurezza verificata.

## 4. Sequenza per fasi

## Fase A - Setup tecnico (Settimana 1)
- Definizione repository layout.
- Ambiente locale con compose.
- Config e standard coding.

Exit criteria:
- Stack base avviabile localmente.

## Fase B - Core dati e ingest (Settimane 2-3)
- Modello dati + migrazioni.
- Primo collector CVE in produzione interna.
- raw-observations operativo.

Exit criteria:
- Dati CVE ingestiti e persistiti con audit minimo.

## Fase C - Enrichment e correlazione (Settimane 4-5)
- Normalizzazione, dedup e enrichment per CVE/IoC.
- Correlation engine con regole MVP.

Exit criteria:
- correlation-events generati su asset reali.

## Fase D - Scoring e API rischio (Settimane 6-7)
- Risk engine completo con formule ufficiali.
- Endpoint score asset/tenant + trend.

Exit criteria:
- Score coerenti con formule e test automatici verdi.

## Fase E - Dashboard cliente e hardening (Settimane 8-9)
- Dashboard cliente minima.
- Notifiche critiche.
- Hardening sicurezza e performance base.

Exit criteria:
- MVP demo-ready per 1-3 tenant pilota.

## 5. Backlog iniziale (primi ticket)

1. Definire mono-repo layout e convenzioni modulo.
2. Creare docker-compose con api, worker, redis, postgres.
3. Inizializzare FastAPI app + health endpoints.
4. Inizializzare Celery worker + test queue redis streams.
5. Definire modelli Pydantic principali.
6. Creare migrazione DB iniziale entita core.
7. Implementare collector NVD (CVE) con retry/backoff.
8. Persistenza Observation grezza e validazione schema.
9. Implementare normalizzazione CVE.
10. Implementare regole scoring e test unit matematici.
11. Endpoint REST score per asset e tenant.
12. Dashboard cliente semplice con trend 7/30 giorni.

## 6. Dipendenze esterne

- Accesso API NVD, EPSS, AbuseIPDB/GreyNoise (tier free).
- Credenziali HIBP quando si abilita leak verification.
- Scelta ambiente deploy iniziale (K3s single node o equivalente).
- Definizione tenant pilota e dataset asset iniziale.

## 7. Rischi principali e mitigazioni

- Qualita feed eterogenea -> introdurre validazione forte e confidence minima.
- Drift tra scoring teorico e implementazione -> test con fixture e casi noti.
- Complessita multi-tenant precoce -> imporre tenant_id obbligatorio in ogni layer.
- Debito operativo -> CI minima obbligatoria da fase A.
- Scope creep (phase-2 troppo presto) -> bloccare feature non MVP in backlog separato.

## 8. Definition of Done (MVP)

Il MVP e completato quando:
- Collectors CVE, IoC e Leak producono observation valide.
- Pipeline ingest -> enrichment -> correlation -> risk e attiva end-to-end.
- Score asset e tenant sono disponibili via API e dashboard.
- Audit, auth e isolamento tenant sono verificati.
- Test automatici coprono logica critica e passano in CI.

## 9. Next actions immediate (48 ore)

1. Confermare il layout tecnico (mono-repo o repo separati).
2. Generare scaffold backend FastAPI + Celery.
3. Creare schema DB iniziale e migrazioni.
4. Implementare il primo collector CVE.
5. Preparare dataset seed di tenant/asset per test correlazione.

## 10. Aggiornamento stato implementativo

Incremento completato (frontend mockup v9 support):
- Introdotto layer API dedicato `frontend/v9` per tenant con endpoint bootstrap e CRUD collection-based.
- Collection operative attualmente supportate:
  - `actors`, `campaigns`, `cases`, `reports`, `observables`, `darkweb_posts`, `connectors`, `scanner_targets`, `scanner_scans`, `scanner_findings`, `redteam_engagements`.
- Persistenza MVP su `Observation` (`entity_type = frontend_v9`) con metadati di collection/item e payload JSON flessibile.

Impatto sul piano:
- Consente avanzamento di WS6 (API e dashboard cliente) anche in assenza di schema relazionale completo per ogni modulo UI.
- Riduce time-to-integration con il mockup, mantenendo una traiettoria futura verso tabelle dedicate per domini ad alta cardinalità.

## 11. Stato reale al 23 settembre 2026

Aggiornamento onesto rispetto alle fasi A-E: cosa è verificato oggi (test
automatici + lettura diretta del codice) contro cosa resta pianificato.
Nota: il progetto prosegue come portfolio personale di Luca Brandalese,
non per un cliente reale — questo non cambia lo standard di qualità
richiesto, solo il contesto d'uso.

**Completato e verificato:**
- WS1 (Foundation): backend FastAPI + Celery + Docker Compose avviabile con un comando.
- WS2 (Data model): schema PostgreSQL, migrazioni Alembic, Row-Level Security **forzata** per tenant.
- WS3 (Collectors): collector CVE (NVD) e IoC (AbuseIPDB) reali, non simulati; enrichment VirusTotal aggiunto il 23/09/2026 (vedi sotto).
- WS4 (Normalizzazione/enrichment): pipeline attiva, enrichment KEV/EPSS incluso.
- WS5 (Correlation/Risk Engine): formule ufficiali (sezione 5 di `Architettura.md`) implementate e testate con fixture, `ScoreRule` versionata.
- WS6 (API/Auth/Dashboard): REST `/api/v1/...`, auth OIDC/JWT via Keycloak, RBAC a 5 ruoli, frontend React con dashboard cliente.
- WS7 (Qualità/sicurezza): 278/278 test pytest, `ruff check` e `bandit -r app` puliti sul backend (aggiornato 24/09/2026 con l'hardening dei segreti, vedi sotto; era 264 dopo l'audit del 23/09, 251 alla revisione stabile precedente); 24/24 test vitest, lint/typecheck/build puliti sul frontend; CI GitHub Actions attiva (lint, test, scan immagini/IaC).
- IaC: Terraform per Azure AKS e AWS EKS, Helm chart unico — non ancora eseguiti contro un cluster reale (vedi `docs/DEPLOY.md` per cosa è verificato solo a livello di piano/sintassi).
- Oltre il piano originale: modulo Quick Report (report sintetico per tenant), classificatore dark-web NLP e IOC similarity/embeddings (`app.ml`), forecasting trend rischio (regressione OLS interpretabile).
- **23/09/2026**: aggiunto provider di enrichment **VirusTotal** (`app.enrichment.providers.EnrichmentProviders.fetch_virustotal_ip`, v3 IP report) e agganciato a `_normalize_indicator` in `app.enrichment.engine` — secondo collector/provider IoC reale dopo AbuseIPDB. 9 nuovi test (`tests/test_enrichment_virustotal.py`).
- **Integrazione SIEM/SOAR bidirezionale (`app.ti`)** — scoperta durante l'audit del 23/09/2026, mai documentata prima in questo file né nel PDF: adapter reali e testati per Microsoft Sentinel, Splunk ES e IBM QRadar (REST + TAXII, conversione STIX, idempotenza, retry/backoff), 3 file di test dedicati (`test_ti_stix.py`, `test_ti_service.py`, `test_ti_retry.py`). Corrisponde ad `Architettura.md` §6.1 punto 5. **Disattivata di default** via feature flag (`ti_enabled=False` e un flag per adapter) — nessuna azione richiesta, era solo un buco nella documentazione, non nel codice.

**Correzioni rispetto alle revisioni precedenti di questo documento (audit 23/09/2026):**
Estratti programmaticamente tutti i 115 campi di `Settings` e verificato quali sono davvero letti dal codice (non solo dichiarati), più un giro su TODO/FIXME/stub/mock in tutto `app/`. Trovati e sistemati 4 casi di "config dichiarata ma mai usata" (stessa categoria di GreyNoise):
- **GreyNoise** era stato segnato "FATTO" nella v11 del PDF e in una bozza precedente di questo file. Non era corretto — `greynoise_api_key` non è usata da nessun metodo/collector. **Non implementato** (resta in roadmap sotto), solo corretta la documentazione.
- **`nvd_api_key`** era dichiarata ma mai inviata come header al collector NVD (impatto reale: rate limit NVD 5 req/30s invece di 50 req/30s). **Sistemato**: `NVDCollector.fetch_cves()` ora invia `apiKey` quando la chiave è configurata. 2 nuovi test in `test_nvd_collector.py`.
- **`attack_taxii_base_url`** era un campo morto, residuo di un approccio TAXII abbandonato a favore del mirror STIX unauthenticated (`attack_stix_bundle_url`, che è quello davvero usato). **Rimosso** da `config.py`.
- **`risk_forecast_min_points`** era dichiarata ma `app/ml/predictive.py` usava una costante hardcoded (`MIN_POINTS_FOR_TREND = 3`) invece di leggerla — cambiare la env var non aveva alcun effetto. **Sistemato**: `forecast_from_points()` ora accetta `min_points` come parametro reale, e `services.forecast_tenant_risk()` lo passa da `settings.risk_forecast_min_points`. 2 nuovi test in `test_ml_predictive.py`.

Verifica dopo i 4 fix: 264/264 test pytest, `ruff check` e `bandit -r app` puliti.

**24/09/2026 — Hardening dei segreti (API key e token) in memoria:**
Richiesta esplicita: "le chiavi non devono essere usate in modo chiaro" —
scope concordato è l'opzione "hardening leggero" (non l'integrazione con un
vault esterno reale, che avrebbe richiesto infrastruttura/credenziali non
disponibili in questo ambiente e sarebbe stata un'integrazione non
verificabile).

- Le 14 credenziali/token dichiarati in `Settings` (`secret_key`,
  `nvd_api_key`, `ioc_api_key`, `leak_api_key`, `abuseipdb_api_key`,
  `greynoise_api_key`, `virustotal_api_key`, `hibp_api_key`,
  `ti_sentinel_api_token`, `ti_sentinel_taxii_token`,
  `ti_splunk_api_token`, `ti_splunk_taxii_token`, `ti_qradar_api_token`,
  `ti_qradar_taxii_token`) sono ora tipizzate `pydantic.SecretStr` invece di
  `str`: `repr()`/`str()` del campo (e quindi anche di `Settings` nel suo
  insieme) stampano sempre una maschera fissa, mai il valore reale — quindi
  un log accidentale (`logger.info(settings)`, un traceback che include
  `self`) non può più esporre una chiave. Il valore reale si ottiene solo
  con `.get_secret_value()`, chiamato esplicitamente nel singolo punto in
  cui serve davvero (costruzione di un header HTTP) in
  `app/collectors/nvd.py`, `ioc.py`, `leak.py`,
  `app/enrichment/providers.py` e nei tre adapter TI
  (`app/ti/adapters/{sentinel,splunk,qradar}.py`, sia per l'header
  `Authorization`/`SEC` REST sia per il token passato al client TAXII).
  I controlli di verità esistenti (`if settings.x:`) restano invariati —
  `SecretStr` ha lo stesso comportamento booleano del valore contenuto.
- Aggiunto `app/core/secrets.py`: `mask_secret()` (mascheramento parziale
  per un'eventuale vista diagnostica ad operatore autorizzato, non il
  meccanismo di protezione primario) e il contratto `SecretResolver` +
  `EnvSecretResolver` — un seam pronto per essere sostituito da un vero
  client Vault/AWS Secrets Manager in futuro senza toccare i call site,
  senza però implementare oggi un client fittizio verso un backend che non
  esiste in questo ambiente.
- 14 nuovi test in `tests/test_secrets_hardening.py`: verificano che
  `repr()`/`str()` di ogni campo segreto (e di `Settings` nel suo insieme)
  non contenga mai il valore reale; che i controlli di verità restino
  invariati; e — end-to-end, non solo a livello di tipo — che il valore
  reale arrivi comunque nell'header HTTP effettivo (`SentinelAdapter._headers()`
  e la riga `leak_api_key or ""` di `LeakCollector`, riscritta perché con
  `SecretStr` l'`or` in Python restituirebbe l'oggetto `SecretStr` stesso
  invece della stringa vuota di fallback). Aggiornati anche i test/mock
  preesistenti che assegnavano questi campi come stringa semplice
  (`test_config.py`, `test_nvd_collector.py`, `test_enrichment_virustotal.py`,
  `mock/config.py`). Verifica: **278/278 test pytest**, `ruff check` e
  `bandit -r app` puliti.
- **Scoperta emersa da questo lavoro, non ancora risolta**: `secret_key` è
  un campo obbligatorio (validato non-vuoto) ma **non ha nessun
  consumatore reale in `app/`** — l'autenticazione è interamente
  OIDC/JWT RS256 via JWKS (Keycloak o altro IdP), che non richiede una
  chiave locale di firma. Gli unici riferimenti sono `mock/config.py`
  (placeholder) e l'asserzione in `test_config.py` che il campo stesso
  venga letto correttamente — nessuno dei due è un vero utilizzo. Stessa
  categoria di "config dichiarata ma morta" di GreyNoise/`nvd_api_key`/
  `attack_taxii_base_url`, ma la decisione qui è diversa da un semplice
  fix: bisogna decidere se `secret_key` debba iniziare a firmare
  qualcosa per davvero (es. un futuro CSRF token o un JWT interno
  service-to-service) o se vada rimosso — segnalato, nessuna azione
  presa finché non c'è una decisione esplicita.

**Non ancora fatto (nessuna evidenza nel codice):**
- Alert & notification engine (email/Slack/Teams) — il gap operativo più visibile.
- Vault dedicato per i segreti (HashiCorp Vault o equivalente) — le chiavi restano lette da variabili d'ambiente (oggi mascherate in memoria via `SecretStr`, vedi hardening 24/09/2026 sopra); `app/core/secrets.py` lascia il seam pronto per un client Vault/Secrets Manager reale, non ancora implementato.
- Modello ML addestrato (XGBoost/LightGBM) per risk scoring predittivo — resta un modello lineare interpretabile, scelta deliberata ma diversa da quanto originariamente ipotizzato.
- Integrazione MISP/OpenCTI (STIX/TAXII) — diversa dall'integrazione SIEM/SOAR sopra, che invece esiste.
- GreyNoise reale (solo chiave di config dichiarata, nessun uso) — o rimuovere il campo, o implementare `fetch_greynoise_ip` sullo stesso pattern di `fetch_virustotal_ip`.
- WAF, mTLS interno, pen test, certificazioni (ISO 27001/SOC 2).
- **Sandbox/detonation per hash IOC** (nuovo, 23/09/2026) — nessun reverse engineering nello scope del progetto (`Architettura.md` §2.2: "non è un SIEM, SOAR o EDR"), ma un'estensione realistica dell'enrichment: interrogare un sandbox esterno (Cuckoo/CAPE self-hosted, o API pubblica tipo Hybrid Analysis/MalwareBazaar) per ottenere un verdetto di detonazione su un hash IOC — stesso pattern lookup-only già usato per AbuseIPDB/VirusTotal (`EnrichmentProviders.fetch_*`), nessuna analisi statica/dinamica costruita in-house. Priorità Media — utile a completare la copertura IOC (oggi solo IP), non copre ancora hash/dominio/URL.

Questa sezione va aggiornata ad ogni incremento rilevante, sullo stesso
principio delle sezioni precedenti: nessuna voce segnata "fatto" senza
un test automatico o una lettura diretta del codice a supporto.
