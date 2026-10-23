# Sentinel AI — Design Spec

**Data:** 2026-10-23  
**Approccio:** B — Rebuild corretto in fasi  
**Fonte:** Analisi reverse engineering 23/10/2026 (≈310 file, cartella ora vuota — rebuild from scratch)

---

## 1. Obiettivo

Piattaforma CTI (Cyber Threat Intelligence) multi-tenant che:
1. Ingesta feed di minacce (CVE, IoC, leak, phishing, ATT&CK)
2. Arricchisce e normalizza le entità
3. Correla con gli asset/software dei clienti
4. Calcola un risk score affidabile (che sale e scende)
5. Notifica via Slack/email/webhook quando il livello cambia

I 10 bug dell'analisi non esistono in questo rebuild — sono evitati by design.

---

## 2. Stack

| Livello | Tecnologia |
|---------|-----------|
| API | FastAPI 0.115, Pydantic v2, SQLAlchemy 2.0, psycopg3 |
| Worker | Celery 5.4 + Redis (beat + 1 worker, coda `sentinel`) |
| Stream | Redis Streams con XREAD + cursori Redis, MAXLEN 50000 |
| DB | PostgreSQL 16, Alembic, RLS |
| Auth | Keycloak 25, JWT RS256 via JWKS (PyJWT) |
| Frontend | React 19, Vite, TypeScript, TailwindCSS, TanStack Query/Table, Recharts, Zustand, oidc-client-ts |
| ML | numpy, scikit-learn, faiss-cpu (forecast OLS, dark web classifier, IoC similarity) |
| Infra | K3s Hetzner (`iac/` unico albero — niente `infra/` AKS) |

---

## 3. Architettura e Fasi

### Fasi di consegna

| Fase | Contenuto | Output verificabile |
|------|-----------|-------------------|
| 1 | Backend completo: modelli DB, migrazioni, auth, pipeline collector→alert, API minima | `pytest` verde; NVD porta CVE degli ultimi 90 gg |
| 2 | Frontend che legge dati CTI reali; RBAC corretto; Cases/Identities/Actors/Campaigns API | Tutte le pagine mostrano dati calcolati dal backend |
| 3 | ML, SIEM outbound/inbound, connettori, report, infra K3s, CI | Deploy funzionante su K3s |

### Fix architetturali by design

1. **Ordine pipeline corretto** — normalize precede enrich e correlate; beat schedulato di conseguenza.
2. **HIBP per-tenant** — watchlist letta da colonna `tenant_id` nel DB, non variabile globale.
3. **No `frontend_v9`** — le tabelle CTI reali sono esposte da API dalla fase 2.
4. **ScoreRule versionata con API** — POST/PATCH con version bump e audit log; weights letti in `s_base()`.

---

## 4. Modello Dati

### Tabelle tenant-isolate (RLS) — 11

| Tabella | Note |
|---------|------|
| `tenants` | DELETE solo super_admin |
| `assets` | invariata |
| `software` | invariata |
| `observations` | solo raw collector |
| `exposure_matches` | invariata |
| `scores` | + colonna `epss_score FLOAT` |
| `correlation_events` | + `resolved_at TIMESTAMPTZ`, `is_active BOOL DEFAULT TRUE` |
| `cases` | usata con API CRUD (non `observations`) |
| `identities` | API di scrittura esposta |
| `score_rules` | API POST/PATCH + version bump + audit log |
| `audit_logs` | append-only via trigger |

### Tabelle catalogo condivise (no RLS) — 8

| Tabella | Note |
|---------|------|
| `vulnerabilities` | + `kev_date_added DATE`, `epss_score FLOAT`; `description`/`cvss_vector`/`mitre_techniques` popolati |
| `indicators` | invariata |
| `leaks` | + `tenant_id` + RLS |
| `phishing_domains` | invariata |
| `attack_techniques` | invariata |
| `threat_actors` | invariata, esposta da API |
| `campaigns` | invariata, esposta da API |
| `sources` | invariata |

### Tabelle nuove — 2

| Tabella | Scopo |
|---------|-------|
| `kev_catalog` | cache locale CISA KEV; aggiornata una volta al giorno |
| `feedback_events` | log feedback SIEM in entrata |

### Stream Redis (tutti con MAXLEN 50000)

`raw-observations` · `enriched-entities` · `correlation-events` · `feedback-events`

---

## 5. Pipeline

```
collector (NVD, IoC, leak, phishing, ATT&CK)
    │  raw-observations
    ▼
normalize/dedup → vulnerabilities, indicators, leaks, phishing_domains
    │  enriched-entities
    ▼
enrich (EPSS, KEV da kev_catalog, GeoIP, AbuseIPDB, VT, GreyNoise, MalwareBazaar, HIBP, SSL/MX)
    │  correlation-events
    ▼
correlate (5 regole) → correlation_events, exposure_matches
    │
    ▼
risk engine → scores (append-only)
    │
    ▼
alert → check_and_notify → Slack / email / webhook
```

### Beat schedule

| Task | Frequenza | Note |
|------|-----------|------|
| `collect_nvd` | ogni ora :00 | `lastModStartDate` = ultima run in Redis; prima run = ultimi 90 gg |
| `collect_ioc` | ogni ora :15 | spento di default |
| `collect_leak` | 03:00 | spento di default; watchlist per-tenant |
| `collect_phishing` | ogni 6h | acceso |
| `collect_attack_techniques` | 04:30 | acceso |
| `collect_kev` | 05:00 | nuovo; popola `kev_catalog` |
| `normalize` | ogni 5 min :01 | |
| `enrich` | ogni 5 min :02 | |
| `correlate` | ogni 5 min :03 | |
| `risk_and_alert` | ogni 5 min :04 | |
| `campaign_sweep` | ogni 6h | |
| `rebuild_faiss_index` | ogni 30 min | volume condiviso API+worker |

---

## 6. Scoring

### Formula S_base

```
S_base = sev * w["severity"] + conf * w["confidence"] + rec * w["recency"] + epss_boost * w["epss"]
```

- **`w`**: da `ScoreRule.weights` attiva; default `{severity:0.5, confidence:0.3, recency:0.2, epss:0.1}`
- **`f_severity` CVE**: `CVSS/10`; se in `kev_catalog`: `1.0`
- **`f_confidence`**: da `Source.reliability_default` o confidence normalizzata indicatore
- **`f_recency`**: ricalcolata a ogni run da `correlation_events.created_at` — non congelata
- **`epss_boost`**: `min(epss_score * 2, 0.3)` da `vulnerabilities.epss_score`

### Score decay

`PATCH /exposure-matches/{id}` con `status=resolved|false_positive`:
1. Setta `correlation_events.is_active = FALSE`, `resolved_at = now()`
2. Risk engine somma solo eventi `is_active=TRUE`
3. `f_recency` ricalcolata → score scende

### ScoreRule

- `POST /score-rules`: nuova versione (super_admin)
- `PATCH /score-rules/{id}`: modifica pesi con version bump automatico
- Regola attiva = `MAX(version)` per tenant (NULL = globale)
- Ogni modifica → riga in `audit_logs`

---

## 7. API e Auth

### Autenticazione

- JWT RS256, JWKS Keycloak, issuer + audience `sentinel-ai`
- Rate limit per `tenant_id` (chiave Redis `rl:{tenant_id}`), finestra fissa 60s
- Ruoli da claim `roles` o `realm_access.roles`; nessuna tabella utenti locale

### RBAC

| Azione | super_admin | tenant_admin | analyst | viewer | api_user |
|--------|-------------|--------------|---------|--------|----------|
| Crea/elimina tenant | ✅ | ❌ | ❌ | ❌ | ❌ |
| CRUD asset/software | ✅ | ✅ | ❌ | ❌ | ✅ |
| PATCH exposure status | ✅ | ✅ | ✅ | ❌ | ❌ |
| CRUD cases/identities | ✅ | ✅ | ✅ | ❌ | ❌ |
| Compute score | ✅ | ✅ | ✅ | ❌ | ❌ |
| POST/PATCH score_rules | ✅ | ❌ | ❌ | ❌ | ❌ |
| Lettura qualsiasi | ✅ | ✅ | ✅ | ✅ | ✅ |

### Endpoint aggiunti

| Endpoint | Scopo |
|----------|-------|
| `POST /score-rules` / `PATCH /score-rules/{id}` | gestione regola scoring |
| `GET|POST|PATCH|DELETE /tenants/{id}/cases` | workspace investigativo |
| `GET|POST /tenants/{id}/identities` | gestione identità |
| `GET /threat-actors` / `GET /campaigns` | catalogo CTI |
| `GET /reports/quick` | report collegato alla UI |
| `POST /kev/refresh` | aggiornamento manuale KEV (super_admin) |

**Error model comune:**
```json
{"error": {"code": "SNAKE_CASE_CODE", "message": "...", "detail": {}}}
```

---

## 8. Frontend

14 pagine, tutte su dati calcolati (niente `frontend_v9`):

| Pagina | Fase | API |
|--------|------|-----|
| Dashboard | 1 | `/dashboard` (Open Cases da `cases`) |
| Assets, Scores, Exposure, Analysis | 1 | invariate |
| Cases | 2 | `/tenants/{id}/cases` |
| Actors | 2 | `/threat-actors` |
| Campaigns | 2 | `/campaigns` |
| Observables | 2 | `/indicators` |
| Dark Web | 2 | `/observations?type=darkweb` + classify |
| Reports | 2 | `/reports/quick` |
| Scanner, Red Team, Connectors | 3 | TBD |

Auth: oidc-client-ts, Authorization Code + PKCE, sessionStorage.

---

## 9. Infrastruttura

`iac/` K3s Hetzner — unico albero.

| Componente | Scelta |
|-----------|--------|
| Cluster | K3s single-node Hetzner |
| Postgres / Redis | Helm Bitnami nel cluster |
| Keycloak | Helm Bitnami; realm prod separato (niente password nel repo) |
| Migrazioni | Job K8s pre-deploy |
| Frontend | Deployment nginx (build Vite) |
| Immagini | Tag semver `v1.0.0`, mai `latest` |
| Segreti | `.env` in dev; Kubernetes Secrets in prod; fallback Vault/AWS con log |
| Volume FAISS | PersistentVolumeClaim condiviso API+worker |
| CI | `.github/workflows/`: lint → pytest → vitest → build Docker → push ghcr.io |

---

## 10. Fuori scope (fase corrente)

- TAXII 2.1 (path SIEM restano placeholder fino alla fase 3)
- MinIO
- Tenant sector nel risk score
- HPA multi-node (fase 3)

---

## 11. Rischi noti

| Rischio | Mitigazione |
|---------|-------------|
| NVD API throttling senza chiave (5 req/30s) | retry con backoff esponenziale; `NVD_API_KEY` opzionale ma consigliata |
| ip-api.com free risponde solo HTTP | `GEO_IP_URL` default su HTTP; documentato |
| K3s single-node: no HA | accettato per MVP |
| Celery beat single: SPOF | accettato per MVP |
