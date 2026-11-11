> **Documento storico.** Si riferisce al vecchio codice di Sentinel AI (cartella `Desktop\File piattaforma per mediaminer`), sostituito dal rebuild iniziato il 23/10/2026. I problemi elencati qui (realm demo nel chart Helm, dashboard, CI) non si applicano al rebuild, che non ha né chart Helm né realm. Conservato così com'era per riferimento; lo stato attuale è in `docs/STATO-PROGETTO.md`.

---

# Revisione Sentinel AI — 9 ottobre 2026

Cartella analizzata: `File piattaforma per mediaminer` sul tuo PC (copia letta il 09/10/2026). Confronto con l'audit del 22/09/2026 (`knowledge/claude/audit-2026-09-22-tutto-il-progetto.md`).

## Comandi di qualità: eseguiti davvero

| Comando | Esito | Note |
|---|---|---|
| `pytest` (backend, env come nella CI) | **278/278 verdi** | erano 251 all'audit del 22/09 |
| `ruff check .` | pulito | |
| `bandit -r app` | 0 issue | |
| `npm test` **così com'è sul tuo PC** | **FALLISCE** (1 file di test su 4) | manca ancora `frontend/.env.test` |
| `npm test` con `.env.test` | 24/24 verdi | |
| `npm run lint` | 0 errori, 1 warning (già noto) | |
| `npm run typecheck` / `npm run build` | OK | bundle unico ~1 MB, come prima |
| `npm audit` | **10 vulnerabilità (7 high, 3 moderate)** | all'audit erano 0; 9 su 10 sono dipendenze di sviluppo |

Ambiente: Python 3.11 (Linux), Node 22. Sotto Python 3.13 l'installazione fallisce perché `faiss-cpu==1.9.0` non ha una build per la 3.13. Il Dockerfile usa la 3.12, quindi nessun problema lì; conta solo se sviluppi in locale con la 3.13.

## Problemi in ordine di impatto

### 1. Il chart Helm di produzione crea utenti demo con una password che sta nel repo (sicurezza, alta)
`infra/helm/sentinel/files/realm-export.json` è una copia identica del realm di sviluppo (`docker/keycloak/realm-export.json`). Contiene 5 utenti, tra cui `super.admin` con ruolo `super_admin`, tutti con password `SentinelDemo!2026` e `temporary: false`. Keycloak parte con `--import-realm` (`infra/helm/sentinel/values.yaml:121`), quindi **qualsiasi deploy su AKS/EKS espone un super admin cross-tenant con una password pubblica**. Questo annulla tutto il lavoro su RLS e RBAC.
Fix: un realm di produzione senza utenti (o con utenti `temporary: true` e password iniettata da Secret), e la copia demo usata solo da docker-compose.

### 2. La dashboard mostra numeri sbagliati (bug, alta perché si vede in demo)
- **"Open Cases" mostra in realtà `recent_observations.length`** (`frontend/src/pages/DashboardPage.tsx`, KPI strip). È sempre al massimo 10 e non c'entra con i case.
- **"Top Risk Assets" duplica gli asset.** Il Risk Engine aggiunge una nuova riga `Score` a ogni ricalcolo (`app/risk/engine.py`, `_persist_entity_score`). La dashboard prende le 5 righe con valore più alto su **tutto lo storico** (`app/api/services.py`, `get_tenant_dashboard`) invece dell'ultimo score per asset. Lo stesso asset può comparire più volte (con chiavi React duplicate), e un asset già bonificato resta in cima con un valore vecchio. `compute_group_risk` lo fa giusto (prende l'ultimo per asset): stesso approccio da riusare.
- **`trend_7d_delta` non copre 7 giorni**: confronta gli ultimi 7 *ricalcoli*, che possono essere a pochi minuti di distanza. In più è mostrato sotto il KPI "Assets", quindi sembra una variazione del numero di asset.

Nessuno di questi tre ha un test. La regola §9 (test sulla logica di business) qui non è rispettata.

### 3. La documentazione dice cose non vere sullo stato del repo (alta per un progetto da presentare)
`IMPLEMENTATION_PLAN.md` §11 (aggiornato il 24/09) dichiara:
- "**CI GitHub Actions attiva**": falso. `.github/workflows/` è ancora vuota, i workflow sono ancora in `Claude outputs/` e non c'è un repo git (nessuna `.git`).
- "24/24 test vitest": vero solo con `.env.test`, che sul tuo PC non c'è.

In pratica `setup-repo-v2.ps1` dell'audit del 22/09 **non è mai stato eseguito**: sono ancora lì `Claude outputs/`, `github/` (copia vecchia del repo più lo zip da 1,4 MB), `demo/SENTINEL_AI_v9.html`, e sia `iac/` sia `infra/`.

C'è anche un'incoerenza di contesto: §11 dice "il progetto prosegue come portfolio personale, non per un cliente reale", mentre le istruzioni del progetto lo descrivono come piattaforma B2B per mediaminer. Non cambia il codice, ma decide come presentarlo: da chiarire.

### 4. Exposure Intelligence: la feature prioritaria non c'è ancora (gap di prodotto, alta)
Rispetto alla priorità n. 2:
- Non c'è un flusso "seleziona cliente → Analyze Exposure". La pagina `ExposurePage` è una tabella di match già calcolati dal Correlation Engine, con filtro di stato.
- Non c'è nessuna spiegazione "why this score". `ExposureMatchRead` restituisce CVSS/EPSS/KEV come colonne separate, ma nessun breakdown di `S_base`, `E_exposure`, `I_impact` e α (i dati ci sono già in `CorrelationEvent.s_context` e in `formulas`).
- **`exploit_active` è sempre `"unknown"`** (`app/correlation/engine.py`, `_upsert_exposure_match`): il segnale "exploit activity" della spiegazione oggi non esiste.
- Il settore del cliente non entra da nessuna parte nello score.

Il backend ha già tutti i pezzi (formule, match CPE, KEV/EPSS). Manca l'endpoint di spiegazione più la UI. È il lavoro con il miglior rapporto valore/sforzo.

### 5. La dashboard non è ancora "cosa conta oggi" (priorità n. 1, media)
La dashboard React mostra Risk Score, Assets, Observations, un falso "Open Cases", il trend, i driver a torta, i top asset e le **observation grezze in JSON troncato** (`JSON.stringify(obs.raw_data).slice(0, 80)`). Non c'è nulla di Active Campaigns Today, Critical CVEs Today (KEV/EPSS), Customers At Risk o IOC Correlation Matches. Questo vale per l'app React; la demo HTML v10 non l'ho rianalizzata.

### 6. Manca lo step finale della pipeline: gli alert (media)
`Architettura`/istruzioni: "alert solo su superamento soglie/transizione livello". Nel codice non c'è nessuna logica di transizione di livello né di notifica (grep su `app/`: zero). Il piano lo segnala onestamente come "gap più visibile". Lo riporto perché è un vincolo di pipeline, non un nice-to-have.

### 7. `npm audit`: 10 vulnerabilità nuove (media-bassa)
Sono comparse advisory nuove dopo il 22/09. Solo 1 riguarda il runtime (`fast-uri`, moderate); le altre sono nella toolchain di sviluppo (braces/micromatch/postcss via tailwind). `npm audit fix` (senza `--force`) ne risolve la maggior parte. Va rilanciato con i test.

### 8. Isolamento multi-tenant: solido, due query da stringere (bassa)
Il modello è buono: RLS forzata, `get_tenant_scoped_db` con controllo del claim tenant, `bypass_session` esplicita per i worker, e filtro `tenant_id` applicativo su quasi tutte le query. Due eccezioni, entrambe protette da RLS e da UUID unici, ma che per la regola del progetto vanno sistemate:
- `app/correlation/engine.py`, `_upsert_exposure_match`: il lookup dell'`ExposureMatch` esistente non filtra per `tenant_id`, e gira in `bypass_session`, quindi **senza** la rete RLS.
- `app/api/services.py`, `get_tenant_dashboard`: `db.get(Asset, asset_score.entity_id)` senza filtro tenant (qui c'è la RLS).

### 9. Dati demo: reali, con una data falsata (bassa)
`CVE-2026-21643` nel seed mock è reale (FortiClient EMS SQLi, sfruttata in the wild: [Qualys](https://threatprotect.qualys.com/2026/02/11/forticlient-endpoint-management-server-ems-sql-injection-vulnerability-cve-2026-21643/), [Picus](https://www.picussecurity.com/resource/blog/cve-2026-21643-critical-sql-injection-in-fortinet-forticlient-ems-exploited-in-the-wild)). Però `published` è impostato a "oggi − 3 giorni", mentre la CVE è di febbraio 2026: `f_recency` vale 1.0 invece di 0.2 e lo score demo risulta gonfiato. Va usata la data vera.

### 10. Minori
- `secret_key` obbligatoria ma non usata da nessuna parte (già segnalato da te il 24/09, decisione ancora aperta).
- Le collection `frontend_v9` caricano tutte le righe del tenant e filtrano in Python: va bene ora, non a volume.
- UI React: tono già abbastanza sobrio (palette slate/blu, poche animazioni). La parte "cyberpunk" sta soprattutto nella demo HTML, che qui non ho rivalutato.

## Cosa è cambiato dal 22/09
- **Fatto**: enrichment VirusTotal (+9 test), `nvd_api_key` finalmente inviata, `risk_forecast_min_points` reale, campo morto `attack_taxii_base_url` rimosso, hardening segreti con `SecretStr` (+14 test). Test backend da 251 a 278, tutti verdi.
- **Non fatto**: nulla dei punti "repo/CI" dell'audit (`.env.test`, workflow, git, pulizia doppioni, scelta `iac/` vs `infra/`). Nessun avanzamento sulle priorità di prodotto 1 (dashboard) e 2 (Exposure Intelligence).

## Cosa non ho verificato
- Migrazioni Alembic e RLS contro un Postgres reale (la suite unitaria non tocca il DB; il job CI che lo fa non è mai partito perché la CI non è installata).
- Terraform/Helm contro un cluster reale.
- La demo `SENTINEL_AI_v10.html` (900 KB) non l'ho riletta: vale quanto verificato il 22/09.
