> **Documento storico.** Si riferisce al vecchio codice di Sentinel AI (cartella `Desktop\File piattaforma (vecchio prototipo)`), sostituito dal rebuild iniziato il 23/10/2026. È l'analisi da cui è nato il rebuild; la verifica punto per punto dei 10 difetti nel nuovo codice è in `docs/STATO-PROGETTO.md`. Conservato così com'era per riferimento; lo stato attuale è in `docs/STATO-PROGETTO.md`.

---

# Sentinel AI — Reverse engineering dal codice

Oct 23, 2026 · @Brandex

## Sintesi

Il codice implementa davvero la catena ingest → enrichment → normalizzazione/correlazione → risk engine, con RLS Postgres e auth OIDC solide. Ma la pipeline ha difetti che rendono lo score poco affidabile in produzione, e mezza UI non legge i dati CTI raccolti. Analisi fatta leggendo i sorgenti copiati dal tuo PC il 23/10/2026 (≈310 file); nessun file è stato modificato.

I 10 punti che contano di più, in ordine di impatto:

1. **Il collector NVD non prende mai CVE nuove.** Chiama l'API 2.0 con `startIndex=0` e nessun filtro data: ogni ora riceve le stesse 200 CVE più vecchie (anni '90) e le scarta come duplicate (`app/collectors/nvd.py`, `fetch_cves`).
2. **Lo score non scende mai.** Nessun codice mette un `CorrelationEvent` a `inactive`: segnare un exposure match come risolto o falso positivo non cambia il rischio, e `f_recency` resta congelata al momento della correlazione.
3. **`ScoreRule.weights` è ignorato.** `s_base()` usa sempre i pesi di default 0.5/0.3/0.2 e la confidence è cablata per regola (0.9 NVD, 0.6 IoC, 0.8 leak, 0.5 phishing). Cambiare i pesi nella ScoreRule non ha effetto.
4. **EPSS viene scaricato ma non entra nello score.** Sta solo come colonna in `exposure_matches`.
5. **Match CPE impreciso.** Le range di versione NVD (`versionEndExcluding` ecc.) sono ignorate: un CPE con versione `*` matcha qualsiasi versione del prodotto (confidence 0.7), quindi anche software già patchato. Il match prodotto è per sottostringa.
6. **Le pagine Actors, Campaigns, Observables, Dark Web, Cases, Scanner, Red Team, Reports, Connectors non mostrano i dati reali.** Sono tabelle a inserimento manuale salvate come righe `observations` con `entity_type="frontend_v9"`. Le tabelle `threat_actors`, `campaigns`, `indicators`, `cases` non sono esposte da nessuna API.
7. **Leak di un cliente copiati in tutti i tenant.** Il collector HIBP usa una watchlist globale e crea un'osservazione con email e dettagli breach in ogni tenant attivo (`app/collectors/leak.py`). Spento di default, ma è una fuga di dati cross-tenant.
8. **Alert: lo step finale della pipeline manca ancora.** Gli adapter Slack/email/webhook esistono (dal 14/10) ma nessuno chiama il task `notify_alert`, e non c'è logica di transizione di livello.
9. **Buchi RBAC.** Un Viewer può creare/modificare/cancellare item delle collection frontend\_v9; un Tenant Admin può cancellare il proprio tenant (cascade su tutto).
10. **KEV scaricato per intero a ogni CVE.** `fetch_kev_status` riscarica tutto il catalogo CISA (oltre 1 MB) per ogni CVE distinta del batch, moltiplicato per il numero di tenant.

Restano validi i problemi della revisione del 09/10 (`reviews/revisione-2026-10-09.md` nella cartella del progetto): dashboard con numeri sbagliati, realm demo nel chart Helm di produzione, CI assente. I file coinvolti non sono stati toccati da allora.

## Stack reale e struttura

Lo stack backend coincide con quello dichiarato; il frontend no (React 19, niente shadcn/ui), e l'infra ha due alberi paralleli.

| Livello | Dichiarato (istruzioni / .copilot-instructions) | Nel codice |
| --- | --- | --- |
| API | FastAPI | FastAPI 0.115, Pydantic v2, SQLAlchemy 2.0, psycopg 3 |
| Worker | Celery + Redis | Celery 5.4, un solo worker + beat, coda `sentinel` |
| Stream | Redis Streams | Redis Streams con `XREAD` e cursori salvati in chiavi Redis (non consumer group) |
| DB | PostgreSQL 16 + Alembic + RLS | Uguale, 7 migrazioni, RLS forzata |
| Auth | Keycloak OIDC | Keycloak 25, JWT RS256 verificato via JWKS (PyJWT) |
| Frontend | React 18 + TS + Vite + shadcn/ui | React 19.2, Vite 8, TypeScript 6, Tailwind 3, TanStack Query/Table, Recharts, Zustand, oidc-client-ts; componenti UI scritti a mano, nessuna libreria shadcn/Radix |
| ML | non previsto in MVP | numpy, scikit-learn, faiss-cpu (forecast OLS, classificatore dark web, similarità IoC) |
| Runtime prod | K3s single-node | `infra/`: Helm + Terraform per AKS ed EKS gestiti. `iac/`: K3s su Hetzner con manifest semplici |

Cartelle principali:

- `backend/app/` — `api/` (router, `services.py` da 32 KB con quasi tutta la logica di lettura), `auth/`, `audit/`, `collectors/` (nvd, ioc, leak, phishing, attack), `enrichment/`, `normalize/`, `correlation/`, `risk/`, `ml/`, `ti/` (integrazione SIEM), `notifications/`, `reports/`, `worker/`, `core/` (config, rate limit, segreti, middleware).
- `backend/alembic/versions/` — 7 migrazioni dal 26/05 al 03/09/2026.
- `backend/mock/` + `mock_server.py` — backend di demo su SQLite senza Redis.
- `backend/tests/` — 43 file di test.
- `frontend/src/` — `pages/` (19 pagine), `api/`, `hooks/`, `auth/`, `layout/`, `components/ui/`.
- `infra/` (Helm chart `sentinel` + Terraform moduli aks/eks/postgres/redis/networking) e `iac/` (Hetzner K3s): due proposte di deploy sovrapposte, nessuna scelta.
- Materiale non di codice nella root: `demo/` (HTML v9 e v10, PDF), `Claude outputs/`, `github/` (copia vecchia del repo), `graphify-out/`, `provaDemo/`, `prompts/`. Non c'è `.git` e `.github/workflows/` è vuota.

## Modello dati

Ci sono 19 tabelle: 11 isolate per tenant con RLS forzata, 8 di catalogo condiviso senza RLS. Due tabelle (`cases`, `identities` lato API) esistono ma nessun endpoint le scrive.

| Tabella | Migrazione | Tenant / RLS | Chi la scrive davvero |
| --- | --- | --- | --- |
| `tenants` | 0001 | RLS su `id` | API `/tenants` (super\_admin) |
| `assets` | 0001 | RLS | API assets; seed demo |
| `sources` | 0001 | condivisa | collector (auto-creazione), seed |
| `score_rules` | 0001 | RLS, `tenant_id NULL` = globale | solo seed (`global-default` v1). Nessuna API di scrittura |
| `observations` | 0001 | RLS | collector (una riga per CVE/IoC/leak **per ogni tenant**) e collection frontend\_v9 |
| `scores` | 0001 | RLS (dalla 0006) | risk engine, append-only, una riga a ogni ricalcolo |
| `vulnerabilities` | 0002 | condivisa | normalizzazione. `description`, `cvss_vector`, `mitre_techniques` mai valorizzati; nessuna colonna KEV |
| `indicators` | 0002 | condivisa | normalizzazione |
| `leaks` | 0002 | condivisa (email in chiaro, senza tenant) | normalizzazione |
| `identities` | 0002 | RLS | nessuna API: solo via DB |
| `threat_actors`, `campaigns` | 0003 | condivise | solo seed (LockBit + una campagna) |
| `phishing_domains` | 0003 | condivisa | collector phishing |
| `cases` | 0003 | RLS | nessuno: i case della UI finiscono in `observations` |
| `software` | 0003 | RLS | API exposure |
| `exposure_matches` | 0003 | RLS | correlation engine; stato aggiornabile da API |
| `attack_techniques` | 0005 | condivisa | collector MITRE ATT&CK |
| `correlation_events` | 0006 | RLS | correlation engine, porta `s_context` precalcolato |
| `audit_logs` | 0007 | RLS, append-only via trigger | middleware audit |

Isolamento: le route usano `get_tenant_scoped_db`, che verifica il claim tenant del JWT e imposta `app.current_tenant_id` a ogni transazione. Worker e collector usano `bypass_session()` (GUC `app.bypass_tenant_scope=on`). In docker-compose l'app gira come ruolo `sentinel_app` senza superuser e senza BYPASSRLS, le migrazioni come `postgres`. Il disegno è buono. Le due query senza filtro tenant segnalate il 09/10 ci sono ancora (`_upsert_exposure_match`, `get_tenant_dashboard`).

## Pipeline come è implementata

L'ordine reale è ingest → enrichment → (normalizzazione ∥ correlazione) → risk engine: l'enrichment viene prima della normalizzazione, al contrario di Architettura §3.2 e del README, e la correlazione non aspetta la normalizzazione. Tutto gira come task Celery beat in polling ogni 5 minuti, sfasati di un minuto.

```
collector (NVD, IoC, leak, phishing, ATT&CK)  ── una riga observations per tenant
        │  raw-observations
        ▼
enrichment (EPSS, KEV, GeoIP, AbuseIPDB, VT, GreyNoise, MalwareBazaar, HIBP, SSL/MX)
        │  enriched-entities
        ├──────────────► normalizzazione/dedup → vulnerabilities, indicators, leaks, phishing_domains
        ▼
correlazione (5 regole) → correlation_events, exposure_matches
        │  correlation-events
        ▼
risk engine → scores (append-only)
        │
        ✗ alert (notify_alert mai chiamato)
```

Come funziona ogni passo:

1. **Collector** (`app/collectors/`): scaricano dal feed, scrivono una riga `observations` **per ogni tenant attivo** e pubblicano un evento su `raw-observations` per ciascuna. Con N clienti ogni CVE produce N eventi, N chiamate EPSS e N download KEV.
2. **Enrichment** (`app/enrichment/engine.py`): legge `raw-observations`, estrae CVSS/CPE, chiama EPSS, KEV, GeoIP, AbuseIPDB, VirusTotal, GreyNoise, MalwareBazaar, HIBP breach, controlli SSL/MX, pubblica su `enriched-entities`. Cache solo in memoria per un ciclo.
3. **Normalizzazione/dedup** (`app/normalize/engine.py`): legge `enriched-entities` e fa upsert su `vulnerabilities`, `indicators`, `leaks`, `phishing_domains` con merge della confidence. Il dato KEV viene scartato qui.
4. **Correlazione** (`app/correlation/engine.py`): legge lo stesso stream con un cursore proprio. 5 regole: vulnerability↔software (CPE), ioc↔asset (IP esatto o CIDR, dominio), leak↔identity o dominio, phishing↔brand, campaign↔asset (sweep separato ogni 6 h). Scrive `correlation_events` con `s_context` già calcolato e gli `exposure_matches`, poi pubblica un evento per tenant su `correlation-events`.
5. **Risk engine** (`app/risk/engine.py`): legge `correlation-events`, ricalcola R\_asset, R\_identity e R\_tenant da tutti gli eventi attivi del tenant e aggiunge nuove righe `scores`.
6. **Alert**: assente. Le notifiche esistono come codice ma non sono collegate.

Due rami laterali: `ti_outbound` spinge ogni entità arricchita (di tutti i tenant) verso un unico SIEM configurato a livello piattaforma; `ti_inbound` legge feedback dal SIEM e li pubblica su `feedback-events`, che **nessuno consuma**.

Semantica: `XREAD` con cursore salvato a fine batch, quindi at-least-once senza ack per messaggio. Un'eccezione a metà batch fa riprocessare l'intero batch. Gli stream non hanno `MAXLEN`, quindi crescono senza limite.

| Task beat | Frequenza | Note |
| --- | --- | --- |
| `collect_nvd` | ogni ora | bug `startIndex=0`, vedi Sintesi |
| `collect_ioc` (AbuseIPDB blacklist) | ogni 15 min | spento di default |
| `collect_leak` (HIBP) | 03:00 | spento di default, watchlist globale |
| `collect_phishing` | ogni 6 h | acceso: genera 60 permutazioni per dominio del cliente e le risolve in DNS |
| `collect_attack_techniques` | 04:30 | bundle STIX MITRE da GitHub |
| enrichment / normalizzazione / correlazione / rischio | ogni 5 min (minuti 0/2/3/4) |  |
| campaign sweep | ogni 6 h |  |
| `ti_outbound` / `ti_inbound` | 5 / 10 min | spenti di default |
| rebuild indice IoC FAISS | ogni 30 min | salvato sul disco del worker, l'API non lo vede senza volume condiviso |

## Scoring: codice contro Architettura.md

Le formule in `app/risk/formulas.py` sono quelle di Architettura §5, testate (`test_risk_formulas.py`). Il problema non sono le formule ma gli input con cui vengono chiamate e il fatto che nessuno le ricalcola.

| Formula | Architettura §5 | Nel codice | Scostamento |
| --- | --- | --- | --- |
| S\_base | sev×0.5 + conf×0.3 + rec×0.2, pesi da ScoreRule | stessa formula, ma i pesi sono sempre i default: `ScoreRule.weights` non è mai letto | config morta |
| f\_severity CVE | CVSS/10 | CVSS/10, oppure 1.0 se in KEV | aggiunta KEV, sensata ma non documentata in §5 |
| f\_severity IoC/leak/phishing | Alta/Media/Bassa 1.0/0.6/0.3 | AbuseIPDB ≥75/≥25; leak per pwn\_count ≥1M/≥10k; phishing per SSL+MX | mappature inventate nel codice, non nella spec |
| f\_confidence | 0.3 / 0.7 / 1.0 per tipo sorgente | costanti cablate: 0.9 CVE, 0.6 IoC, 0.8 leak, 0.5 phishing, 0.8 campagna | ignora `Source.reliability_default` e la confidence normalizzata dell'indicatore |
| f\_recency | 1.0 <7 gg, 0.5 ≤30, 0.2 oltre | uguale, calcolata una sola volta alla correlazione | non decade mai |
| E\_exposure, I\_impact | 0.2/0.5/1.0 e 0.3/0.6/1.0 | uguale, da `multipliers`; `data_type` valorizzato forza impatto 1.0 | ok |
| R\_asset | min(1, Σ S\_context × α\_i) | uguale, α da `multipliers.alpha` | ok |
| R\_group | λ·max + (1−λ)·avg | uguale, usato anche per calcolare R\_dominio(t) | interpretazione ragionevole, non scritta nella spec |
| R\_tenant | Σ R\_dominio × β\_d | uguale; "reputation" vale sempre 0, nessuna regola la produce | 10% del peso sempre vuoto |
| Soglie | 0.2 / 0.4 / 0.7 | uguale, da ScoreRule | ok |
| EPSS | citato come segnale di priorità | scaricato, non entra in nessuna formula | assente |
| Settore cliente | priorità di prodotto | `Tenant.sector` non usato | assente |

Versionamento: c'è una sola ScoreRule (`global-default` v1) creata dal seed, e nessuna API per crearne o modificarne. La regola attiva è "la più recente per `created_at`", non per versione. Il requisito "modifica pesi tramite ScoreRule versionata + audit log" oggi si soddisfa solo scrivendo a mano nel DB, e l'audit log non registra quella modifica.

Tre effetti pratici: uno score cresce e non torna giù dopo la remediation; una CVE correlata quando era recente resta a f\_recency 1.0 per sempre; la "spiegazione dello score" chiesta per Exposure Intelligence oggi non può citare EPSS né il settore perché non entrano nel calcolo.

## API, autenticazione e ruoli

Tutte le route stanno sotto `/api/v1`; solo `/health` e `/ready` sono pubbliche. Ogni altra route verifica un JWT RS256 contro il JWKS di Keycloak (issuer, audience `sentinel-ai`) ed è soggetta a rate limit Redis a finestra fissa.

| Area | Endpoint | DB session | Chi può scrivere |
| --- | --- | --- | --- |
| Tenant | `GET/POST /tenants`, `GET/PATCH/DELETE /tenants/{id}` | admin (lista, crea) / tenant | lista e creazione: super\_admin. PATCH e **DELETE: anche tenant\_admin** |
| Asset | `/tenants/{id}/assets[/{asset_id}]` CRUD | tenant | super\_admin, tenant\_admin, api\_user |
| Software | `/tenants/{id}/assets/{asset_id}/software`, `/tenants/{id}/software[/{sw_id}]` | tenant | come asset |
| Exposure | `GET /exposure-matches`, `PATCH /exposure-matches/{id}` (stato) | tenant | PATCH: analyst e superiori |
| Rischio | `/assets/{asset_id}/risk-contributions`, `/assets/risk-group`, `/scores`, `POST /scores/compute`, `/scores/forecast` | tenant | compute: analyst e superiori |
| Dashboard / report | `/dashboard`, `/reports/quick`, `/observations` | tenant | sola lettura |
| Configurazione | `GET /score-rules`, `GET /sources` | plain (qualsiasi ruolo) | sola lettura |
| Analisi | `GET /analysis/iocs/similar`, `POST /analysis/iocs/reindex`, `POST /analysis/darkweb/classify` | plain | reindex: analyst e superiori; classify: chiunque |
| Frontend v9 | `/tenants/{id}/frontend/v9/bootstrap`, `/{collection}[/{item_id}]` CRUD | bootstrap: super\_admin; resto: tenant | **nessun controllo ruolo: anche viewer scrive e cancella** |

Ruoli (`app/auth/roles.py`): super\_admin, tenant\_admin, analyst, viewer, api\_user, letti dal claim `roles` o da `realm_access.roles`. Nessuna tabella utenti locale. Super admin accede a qualsiasi tenant; gli altri solo al tenant del claim `tenant_id`.

Scostamenti rispetto a Architettura §3.1 e §6.1:

- Rate limit **per utente** (`sub`), non per tenant come dicono le istruzioni.
- Nessun permesso granulare (export, configurazione scoring, connettori): esistono solo 3 insiemi di ruoli di scrittura.
- Nessun "error model" comune: si usano le `HTTPException` di FastAPI.
- Tenant admin può cancellare il proprio tenant, con cascade su asset, osservazioni, score e case.
- Il frontend chiama `bootstrap` anche per utenti non super\_admin, che ricevono un 403 a ogni pagina collection.

Middleware attivi, dall'esterno: limite dimensione body → CORS con origini esplicite → security headers → audit log append-only (utente, ruoli, tenant, azione, IP, esito).

## Servizi esterni e feed

Tutte le integrazioni puntano a servizi reali e documentati; con la configurazione di default sono attivi solo NVD, MITRE, phishing (DNS) ed EPSS/KEV.

| Servizio | Uso | Chiave | Stato reale nel codice |
| --- | --- | --- | --- |
| NVD CVE API 2.0 | collector CVE | opzionale (`NVD_API_KEY`) | attivo ma rotto: legge sempre la prima pagina storica |
| FIRST EPSS | enrichment CVE | no | funziona; non usato nello score |
| CISA KEV | enrichment CVE | no | funziona; scarica il JSON completo per ogni CVE, non persistito in `vulnerabilities` |
| MITRE ATT&CK (STIX su GitHub) | catalogo tecniche | no | attivo, giornaliero |
| AbuseIPDB | collector blacklist + check IP | sì | collector spento di default; il check viene chiamato anche su domini e URL, dove l'API accetta solo IP |
| ip-api.com | GeoIP | no | URL configurato in `https://`: il piano gratuito di ip-api risponde solo in HTTP, quindi presumibilmente fallisce in silenzio (non verificato in rete) |
| VirusTotal v3 | IP report | sì | collegato dal 23/09 |
| GreyNoise Community | IP noise | sì | collegato il 14/10 (README e commento in `config.py` dicono ancora il contrario) |
| MalwareBazaar | hash lookup | no | collegato il 14/10 |
| HIBP | breach per account + dettaglio breach | sì | spento di default; watchlist globale copiata in tutti i tenant |
| DNS / TLS / MX | verifica domini typosquat | no | attivo: permutazioni stile dnstwist dei domini cliente, non un feed esterno |
| Splunk, Microsoft Sentinel, QRadar | export STIX e feedback | sì | spento; path REST generici (`/api/alerts`, `/api/feedback`) che non corrispondono alle API reali dei tre prodotti; TAXII 2.1 più realistico |
| Slack / SMTP / webhook | notifiche | sì | codice pronto, nessun chiamante |
| HashiCorp Vault, AWS Secrets Manager | segreti | sì | resolver aggiunti il 14/10, errori ingoiati: un segreto mancante diventa stringa vuota senza log |

Il "ML": forecast lineare OLS sulla storia degli score (onesto e interpretabile), classificatore dark web TF-IDF + regressione logistica addestrato su circa 30 frasi di esempio (è una demo, non un modello), similarità IoC con TF-IDF + SVD + FAISS. Nessuno dei tre tocca il risk score.

## Frontend React

Delle 14 voci di menu per tenant, 5 leggono dati calcolati dal backend; le altre 9 sono la stessa pagina generica `CollectionPage` su dati inseriti a mano.

| Pagina | Fonte dati | Cosa mostra davvero |
| --- | --- | --- |
| Dashboard | `/dashboard` | score tenant, conteggi, trend, driver, top asset, osservazioni grezze in JSON troncato; "Open Cases" = numero di osservazioni recenti (bug del 09/10, ancora presente) |
| Assets | `/assets`, `/software`, `/risk-contributions` | inventario e contributi al rischio per asset |
| Scores | `/scores`, `/scores/forecast`, `/assets/risk-group` | storico score, forecast, rischio di gruppo |
| Exposure | `/exposure-matches` | tabella dei match già calcolati con filtro di stato; nessun "Analyze exposure" e nessuna spiegazione dello score |
| Analysis | `/analysis/*` | ricerca IoC simili, classificazione testo dark web |
| Cases, Actors, Campaigns, Observables, Dark Web, Scanner, Red Team, Reports, Connectors | `/frontend/v9/{collection}` | item JSON creati a mano dall'utente; non leggono `threat_actors`, `campaigns`, `indicators`, `cases` né il quick report |
| Tenant list, Settings | `/tenants`, `/score-rules` | lista clienti (solo super\_admin), regola di scoring in sola lettura |

Auth: oidc-client-ts con Authorization Code + PKCE verso Keycloak, sessione in `sessionStorage`, ruoli letti dal token come nel backend. L'endpoint `GET /reports/quick` esiste ma nessuna pagina lo usa.

Lo stile React è già abbastanza sobrio (slate/blu); l'estetica "cyberpunk" sta nelle demo HTML statiche (`demo/SENTINEL_AI_v10.html`), separate dall'app React (non le ho rilette in questa analisi).

## Infrastruttura

Il deploy che funziona oggi è solo docker-compose. Per la produzione ci sono due proposte incompatibili, nessuna mai eseguita contro un cluster reale.

| Ambito | docker-compose (dev) | `infra/` (Helm + Terraform) | `iac/` (Hetzner) |
| --- | --- | --- | --- |
| Target | laptop | AKS (Azure) o EKS (AWS) | VM Hetzner con K3s single-node |
| Postgres / Redis | container | servizi cloud gestiti, moduli Terraform postgres-aws/azure e redis-aws/azure | Helm chart Bitnami nel cluster |
| Keycloak | container `start-dev`, realm demo | Deployment nel chart, `--import-realm` con lo **stesso realm demo** e password nel repo | chart Bitnami |
| Migrazioni | servizio `migrate` come superuser | Job Helm con secret dedicato | assenti |
| Frontend | Vite dev server | Deployment nginx | assente |
| Extra |  | HPA sull'API (2–6 repliche), ingress nginx + cert-manager | MinIO, che il codice non usa |
| Immagini | build locale | `ghcr.io/CHANGEME/...:latest` | `ghcr.io/ORG/...:latest` |

Le istruzioni del progetto dicono "K3s single-node in prod"; `infra/` va su Kubernetes gestito. Va scelto un albero e cancellato l'altro prima del primo commit. Tag `latest` in produzione rende i rollback non riproducibili. Con 2 repliche del worker, ogni replica tiene la propria cache FAISS su disco locale.

## Scostamenti codice vs documentazione

Ogni riga è una cosa che un documento afferma e il codice non fa (o fa diversamente). Gravità: A = rompe una promessa al cliente o la sicurezza, M = rende lo score o i dati inaffidabili, B = documentazione da correggere.

| # | Documento dice | Il codice fa | Dove | Grav. |
| --- | --- | --- | --- | --- |
| 1 | Collector CVE NVD reale e funzionante (IMPLEMENTATION\_PLAN §11) | rilegge sempre le prime 200 CVE storiche, nessun filtro `lastModStartDate` | `collectors/nvd.py` | A |
| 2 | Alert su superamento soglia o cambio livello (Arch. §3.2, istruzioni) | nessuna logica di soglia; `notify_alert` mai invocato | `worker/tasks.py`, `notifications/` | A |
| 3 | Isolamento multi-tenant su ogni dato | leak HIBP di una watchlist globale copiati in tutti i tenant | `collectors/leak.py` | A |
| 4 | Viewer in sola lettura (Arch. §3.1) | viewer scrive e cancella le collection frontend\_v9 | `routes/frontend_v9.py` | A |
| 5 | Tenant Admin gestisce asset e configurazione | può anche cancellare l'intero tenant | `routes/tenants.py` | A |
| 6 | Realm Keycloak di produzione | il chart Helm importa gli utenti demo con password nel repo (dal 09/10) | `infra/helm/sentinel/files/realm-export.json` | A |
| 7 | Pesi S\_base configurabili via ScoreRule (Arch. §3.1, §5.1) | `weights` mai letto | `correlation/engine.py` | M |
| 8 | Modifiche a pesi/soglie via ScoreRule versionata + audit | nessuna API di scrittura; regola attiva = la più recente per data | `routes/score_rules.py`, `risk/engine.py` | M |
| 9 | Score che riflette lo stato attuale | eventi di correlazione mai disattivati, recency mai ricalcolata | `correlation/engine.py`, `services.update_exposure_match_status` | M |
| 10 | Match CPE/prodotto/versione (Arch. §3.2) | range di versione ignorate, match per sottostringa | `enrichment/cpe.py` | M |
| 11 | KEV ed EPSS guidano la priorità | KEV solo come severity 1.0, non salvato in `vulnerabilities`; EPSS fuori dallo score | `normalize/engine.py`, `risk/formulas.py` | M |
| 12 | Ordine pipeline normalizzazione → enrichment → correlazione (Arch. §3.2; README) | enrichment → normalizzazione e correlazione in parallelo | `worker/celery_app.py` | B |
| 13 | Workspace investigativo con Case, timeline, export STIX/PDF (Arch. §3.2) | tabella `cases` mai usata; i "case" sono JSON liberi in `observations` | `services.py` (frontend\_v9) | M |
| 14 | Viste Campagne attive, Threat actor, Dark web mentions | pagine su dati inseriti a mano, non sui cataloghi CTI | `frontend/src/pages/*Page.tsx` | M |
| 15 | Rate limiting per tenant (istruzioni, Arch. §6.1) | per utente (`sub`) | `core/rate_limit.py` | B |
| 16 | Gestione connettori con stato, retry, periodicità configurabile (Arch. §3.1) | collector cablati nel beat schedule, configurabili solo da env | `worker/celery_app.py` | B |
| 17 | Frontend React 18 + shadcn/ui | React 19, componenti propri | `package.json` | B |
| 18 | K3s single-node in produzione | `infra/` targetizza AKS/EKS; `iac/` (K3s) incompleto | `infra/`, `iac/` | B |
| 19 | GreyNoise non collegato, niente alerting, niente vault (README, §11) | GreyNoise collegato, adapter notifiche e resolver Vault/AWS presenti dal 14/10 | `README.md` | B |
| 20 | CI GitHub Actions attiva (§11) | `.github/workflows/` vuota, nessun repo git | root | B |
| 21 | `secret_key` obbligatoria | non usata da nessuna parte | `core/config.py` | B |
| 22 | Modello: `s_context` nullo per le identity | il codice calcola `s_context` anche per le identity (esposizione 1.0, impatto 0.6) | commento in `db/models.py` | B |
| 23 | Feedback dal SIEM rientra nella pipeline (Arch. §6.1 punto 5) | pubblicato su `feedback-events`, nessun consumer | `ti/service.py` | M |

## Cosa è verificato e cosa no

Tutto quanto sopra viene dalla lettura del codice, non dall'esecuzione. Non ho modificato nessun file.

- **Letto per intero:** modelli, migrazioni (sezioni RLS), deps/auth, router e route, motori di enrichment, normalizzazione, correlazione e rischio, formule, collector NVD e HIBP, worker, stream, notifiche, segreti, App.tsx e pagine principali, docker-compose, values Helm.
- **Letto a campione:** collector IoC/phishing/ATT&CK, adapter TI, moduli ML, Terraform, manifest `iac/`.
- **Non eseguito in questa sessione:** `pytest`, `npm test`, lint. L'ultimo giro verificato è del 09/10 (278 pytest verdi, vitest verde solo con `.env.test`). I file cambiati il 14/10 (enrichment, notifiche, segreti, config, health) hanno test nuovi che non ho lanciato.
- **Dedotto, non provato contro i servizi reali:** il comportamento della NVD API senza filtro data (ordinamento per data di pubblicazione crescente, quindi prime pagine ferme alle CVE più vecchie) e il rifiuto di HTTPS sul piano gratuito di ip-api. Sono comportamenti documentati dai fornitori, ma vanno confermati con una chiamata reale.
- **Non letto:** demo HTML v9/v10, cartelle `github/`, `Claude outputs/`, `graphify-out/`, `provaDemo/`, `prompts/`.

Il lavoro con il miglior rapporto valore/sforzo resta lo stesso del 09/10, con due voci in più davanti: aggiustare il collector NVD (filtro `lastModStartDate`/`lastModEndDate` + paginazione) e far disattivare i `CorrelationEvent` quando un match viene risolto. Senza questi due, Exposure Intelligence mostrerebbe dati vecchi e score che non scendono.
