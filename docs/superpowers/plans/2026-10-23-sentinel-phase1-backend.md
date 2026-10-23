# Sentinel AI Phase 1 — Backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the complete backend pipeline (collector → normalize → enrich → correlate → risk → alert) with multi-tenant auth, PostgreSQL RLS, and all API endpoints needed by the Phase 1 frontend.

**Architecture:** FastAPI + Celery worker communicate via 4 Redis Streams (MAXLEN 50000). PostgreSQL with RLS isolates tenant data; pipeline stages use bypass session. Auth is JWT RS256 verified against Keycloak JWKS. Pipeline order: normalize → enrich → correlate → risk+alert.

**Tech Stack:** Python 3.12, FastAPI 0.115, Pydantic v2, SQLAlchemy 2.0 async, psycopg3, Celery 5.4, Redis 7, PostgreSQL 16, Alembic, PyJWT, httpx, packaging.

**Spec:** `docs/superpowers/specs/2026-10-23-sentinel-ai-design.md`

## Global Constraints

- Python 3.12+; all deps pinned in `pyproject.toml [project.dependencies]`
- All API routes under `/api/v1/`; only `GET /health` and `GET /ready` are public
- Error model on every endpoint: `{"error": {"code": "SNAKE_CASE", "message": "...", "detail": {}}}` — no bare `HTTPException` in route handlers
- Rate limit: per `tenant_id`, Redis key `rl:{tenant_id}`, fixed window 60s, limit 100 req/min
- All 4 streams use `XADD MAXLEN ~ 50000`: `raw-observations`, `enriched-entities`, `correlation-events`, `feedback-events`
- `correlation_events.is_active` defaults `TRUE`; set `FALSE` + `resolved_at=now()` when exposure resolved/false_positive
- `ScoreRule.weights` always read from DB — never hardcode `0.5/0.3/0.2`; normalize weights on use: `w = {k: v/sum(w.values()) for k,v in w.items()}`
- NVD: store last-run in Redis key `collector:nvd:last_run`; first run uses `now() - 90 days`; paginate until `startIndex >= totalResults`
- KEV: fetched once daily by `collect_kev` → `kev_catalog` table; enrichment reads the table only — never HTTP per CVE
- HIBP: `LeakCollector.run(tenant_id, watchlist)` — watchlist loaded per-tenant from DB; email stored as SHA-256 hex, never plaintext
- `s_base = sev*w.severity + conf*w.confidence + rec*w.recency + epss*w.epss`
- `epss_boost(score) = min(score * 2.0, 0.3)`; returns `0.0` when score is `None`
- `f_recency` calculated at risk-engine run time from `correlation_events.created_at`, never stored
- App DB role: `sentinel_app` (no superuser, no BYPASSRLS); migration role: `postgres`

---

## File Map

```
backend/
  pyproject.toml
  .env.example
  alembic.ini
  docker-compose.yml
  alembic/
    env.py
    versions/
      0001_initial_schema.py
      0002_rls_policies.py
  app/
    __init__.py
    main.py
    core/
      config.py
      db.py
      rate_limit.py
      middleware.py
      secrets.py
      streams.py
    auth/
      jwt.py
      roles.py
      deps.py
    db/
      base.py
      models.py
    collectors/
      base.py
      nvd.py
      kev.py
      ioc.py
      leak.py
      phishing.py
      attack.py
    normalize/
      engine.py
    enrichment/
      cpe.py
      engine.py
    correlation/
      rules.py
      engine.py
    risk/
      formulas.py
      engine.py
    notifications/
      engine.py
      adapters/
        slack.py
        email.py
        webhook.py
    api/
      v1/
        errors.py
        router.py
        routes/
          health.py
          tenants.py
          assets.py
          software.py
          exposure.py
          scores.py
          dashboard.py
          observations.py
          score_rules.py
          cases.py
          identities.py
          kev.py
          threat_actors.py
          campaigns.py
          reports.py
    worker/
      celery_app.py
      tasks.py
  tests/
    conftest.py
    test_core/
      test_config.py
      test_streams.py
    test_collectors/
      test_nvd.py
      test_kev.py
      test_leak.py
    test_normalize/
      test_engine.py
    test_enrichment/
      test_cpe.py
      test_engine.py
    test_correlation/
      test_engine.py
    test_risk/
      test_formulas.py
      test_engine.py
    test_notifications/
      test_engine.py
    test_api/
      test_auth.py
      test_exposure.py
      test_scores.py
      test_rbac.py
      test_dashboard.py
    test_worker/
      test_tasks.py
    test_integration/
      test_pipeline_smoke.py
```

## Review Focus

- **Score decay after resolve**: marking an exposure match resolved must lower tenant score on the next risk run — not just change a status field. Covered by `test_score_decreases_after_resolve` (Task 11) and `test_patch_exposure_sets_correlation_event_inactive` (Task 13).
- **NVD pagination**: `fetch_cves` must follow all pages, not only page 0. Covered by `test_fetch_cves_paginates` (Task 7).
- **HIBP tenant isolation**: `LeakCollector.run` with two tenants must write to the owning tenant only. Covered by `test_leak_per_tenant_no_cross_contamination` (Task 7).
- **Viewer write blocked**: viewer token on any mutating endpoint returns 403 with correct error model. Covered by `test_viewer_patch_exposure_returns_403` (Task 13).
- **Stream cursor not advanced on exception**: if a pipeline stage raises mid-batch, cursor stays at pre-batch value so messages are reprocessed. Covered by `test_cursor_not_saved_on_exception` (Task 6).

---

### Task 1: Project Scaffold

**Files:**
- Create: `backend/pyproject.toml`
- Create: `backend/.env.example`
- Create: `backend/docker-compose.yml`
- Create: `backend/app/__init__.py`

**Interfaces:**
- Produces: `docker-compose config --quiet` exits 0

- [ ] **Step 1: Write `backend/pyproject.toml`**

  `[project]` with `name="sentinel-ai"`, `requires-python=">=3.12"`.
  Dependencies: `fastapi==0.115.*`, `uvicorn[standard]>=0.30`, `pydantic-settings>=2.3`, `sqlalchemy==2.0.*`, `psycopg[binary,pool]>=3.1`, `alembic>=1.13`, `celery[redis]==5.4.*`, `redis>=5.0`, `PyJWT[crypto]>=2.8`, `httpx>=0.27`, `packaging>=24`, `numpy>=1.26`, `scikit-learn>=1.5`, `faiss-cpu>=1.8`.
  `[project.optional-dependencies] dev`: `pytest>=8`, `pytest-asyncio>=0.23`, `pytest-cov`, `pytest-mock`, `pytest-httpx>=0.30`.

- [ ] **Step 2: Write `backend/.env.example`**

  Variables: `DATABASE_URL`, `MIGRATION_DATABASE_URL`, `REDIS_URL`, `KEYCLOAK_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID`, `NVD_API_KEY`, `ABUSEIPDB_KEY`, `VT_KEY`, `GREYNOISE_KEY`, `HIBP_KEY`, `GEO_IP_URL=http://ip-api.com/json`, `SLACK_WEBHOOK_URL`, `SMTP_HOST`, `SMTP_PORT=587`, `SMTP_USER`, `SMTP_PASS`, `CORS_ORIGINS=http://localhost:5173`, `LOG_LEVEL=INFO`, `IOC_COLLECTOR_ENABLED=false`, `LEAK_COLLECTOR_ENABLED=false`.

- [ ] **Step 3: Write `backend/docker-compose.yml`**

  Services: `postgres` (`postgres:16`, env `POSTGRES_DB=sentinel POSTGRES_USER=postgres POSTGRES_PASSWORD=postgres`, init script creates role `sentinel_app` without SUPERUSER and without BYPASSRLS), `redis` (`redis:7-alpine`), `keycloak` (`quay.io/keycloak/keycloak:25`, `start-dev --import-realm`, volume `./keycloak/realm-dev.json:/opt/keycloak/data/import/realm.json`), `migrate` (build `.`, command `alembic upgrade head`, uses `MIGRATION_DATABASE_URL`, `restart: "no"`, depends_on postgres), `api` (build `.`, `uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload`, depends_on migrate redis, volume for FAISS index), `worker` (same build, `celery -A app.worker.celery_app worker -Q sentinel -c 1`, same FAISS volume), `beat` (`celery -A app.worker.celery_app beat`).

- [ ] **Step 4: Verify**

  Run: `docker-compose config --quiet`
  Expected: exit 0.

- [ ] **Step 5: Commit**

  ```bash
  git add backend/
  git commit -m "chore: project scaffold, docker-compose, pyproject.toml"
  ```

---

### Task 2: Core Config + Secrets

**Files:**
- Create: `backend/app/core/config.py`
- Create: `backend/app/core/secrets.py`

**Interfaces:**
- Produces: `get_settings() -> Settings` (cached `@lru_cache`); `resolve_secret(key: str) -> str`

- [ ] **Step 1: Write failing tests**

  ```python
  # tests/test_core/test_config.py
  def test_settings_loads_from_env(monkeypatch):
      monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost/db")
      monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
      monkeypatch.setenv("KEYCLOAK_URL", "http://localhost:8080")
      monkeypatch.setenv("KEYCLOAK_REALM", "sentinel")
      monkeypatch.setenv("KEYCLOAK_CLIENT_ID", "sentinel-ai")
      from app.core.config import get_settings
      get_settings.cache_clear()
      s = get_settings()
      assert s.database_url.startswith("postgresql+psycopg://")

  def test_resolve_secret_reads_env(monkeypatch):
      monkeypatch.setenv("TEST_SECRET_XYZ", "myval")
      from app.core.secrets import resolve_secret
      assert resolve_secret("TEST_SECRET_XYZ") == "myval"

  def test_resolve_secret_missing_logs_warning_returns_empty(caplog):
      import logging
      from app.core.secrets import resolve_secret
      with caplog.at_level(logging.WARNING):
          result = resolve_secret("DEFINITELY_MISSING_KEY_12345")
      assert result == ""
      assert "DEFINITELY_MISSING_KEY_12345" in caplog.text
  ```

- [ ] **Step 2: Run — expect FAIL**

  Run: `pytest tests/test_core/test_config.py -v`

- [ ] **Step 3: Implement `app/core/config.py`**

  `class Settings(BaseSettings)` with all fields from `.env.example`. `model_config = SettingsConfigDict(env_file=".env", extra="ignore")`. `get_settings = lru_cache()(lambda: Settings())`.

- [ ] **Step 4: Implement `app/core/secrets.py`**

  `resolve_secret(key: str) -> str`: try `os.getenv(key)` first; try Vault if `VAULT_ADDR` set; try AWS Secrets Manager if `AWS_SECRET_ARN` set. On any miss or exception: `logger.warning("secret %s not found, using empty string", key)` and return `""`.

- [ ] **Step 5: Run — expect PASS**

  Run: `pytest tests/test_core/test_config.py -v`

- [ ] **Step 6: Commit**

  ```bash
  git add app/core/config.py app/core/secrets.py tests/test_core/test_config.py
  git commit -m "feat: core config (pydantic-settings) and secret resolver with logging"
  ```

---

### Task 3: DB Models

**Files:**
- Create: `backend/app/db/base.py`
- Create: `backend/app/db/models.py`

**Interfaces:**
- Produces: 21 SQLAlchemy model classes importable from `app.db.models`

Exact columns required by later tasks:
- `CorrelationEvent`: `id`, `tenant_id`, `rule_name`, `asset_id`, `identity_id`, `vulnerability_id`, `indicator_id`, `s_context FLOAT`, `is_active BOOL DEFAULT TRUE`, `resolved_at TIMESTAMPTZ nullable`, `created_at`
- `ExposureMatch`: `id`, `tenant_id`, `correlation_event_id`, `status VARCHAR DEFAULT 'active'`, `epss_score FLOAT nullable`, `updated_at`
- `Score`: `id`, `tenant_id`, `asset_id nullable`, `score_type VARCHAR`, `value FLOAT`, `level VARCHAR`, `epss_score FLOAT nullable`, `computed_at TIMESTAMPTZ DEFAULT now()`
- `ScoreRule`: `id`, `tenant_id nullable`, `version INT DEFAULT 1`, `weights JSONB DEFAULT {"severity":0.45,"confidence":0.27,"recency":0.18,"epss":0.10}`, `thresholds JSONB DEFAULT {"low":0.2,"medium":0.4,"high":0.7}`, `created_at`, `created_by nullable`
- `Vulnerability`: `id`, `cve_id VARCHAR UNIQUE`, `cvss_score FLOAT nullable`, `cvss_vector nullable`, `description TEXT nullable`, `mitre_techniques ARRAY(VARCHAR) nullable`, `kev_date_added DATE nullable`, `epss_score FLOAT nullable`
- `Leak`: `id`, `tenant_id FK+RLS`, `email_hash VARCHAR` (SHA-256, 64 chars), `breach_name`, `pwn_count INT nullable`, `created_at`
- `Case`: `id`, `tenant_id`, `title`, `description nullable`, `status DEFAULT 'open'`, `severity DEFAULT 'medium'`, `created_by`, `created_at`, `updated_at`
- `KevCatalog`: `id`, `cve_id VARCHAR UNIQUE`, `date_added DATE`, `updated_at`

- [ ] **Step 1: Write failing tests**

  ```python
  # tests/test_db_models.py
  def test_all_21_models_importable():
      from app.db.models import (
          Tenant, Asset, Software, Observation, Vulnerability,
          Indicator, Leak, PhishingDomain, CorrelationEvent,
          ExposureMatch, Score, ScoreRule, Case, Identity,
          ThreatActor, Campaign, AttackTechnique, Source,
          KevCatalog, FeedbackEvent, AuditLog,
      )
      tables = {m.__tablename__ for m in [
          Tenant, Asset, Software, Observation, Vulnerability,
          Indicator, Leak, PhishingDomain, CorrelationEvent,
          ExposureMatch, Score, ScoreRule, Case, Identity,
          ThreatActor, Campaign, AttackTechnique, Source,
          KevCatalog, FeedbackEvent, AuditLog,
      ]}
      assert len(tables) == 21

  def test_correlation_event_is_active_defaults_true():
      from app.db.models import CorrelationEvent
      c = CorrelationEvent(rule_name="test", s_context=0.5)
      assert c.is_active is True
      assert c.resolved_at is None

  def test_score_rule_weights_default_sums_to_1():
      from app.db.models import ScoreRule
      import json
      col = ScoreRule.__table__.c["weights"]
      default = json.loads(col.server_default.arg if col.server_default else '{}')
      if default:
          assert abs(sum(default.values()) - 1.0) < 0.001
  ```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement `app/db/base.py`**

  `from sqlalchemy.orm import DeclarativeBase; class Base(DeclarativeBase): pass`

- [ ] **Step 4: Implement `app/db/models.py`**

  All 21 models inheriting `Base`. UUID PKs via `default=uuid.uuid4`. Array columns via `postgresql.ARRAY(String)`. JSONB via `postgresql.JSONB`. `ScoreRule.weights` server default: `'{"severity": 0.45, "confidence": 0.27, "recency": 0.18, "epss": 0.10}'::jsonb`.

- [ ] **Step 5: Run — expect PASS**

  Run: `pytest tests/test_db_models.py -v`

- [ ] **Step 6: Commit**

  ```bash
  git add app/db/ tests/test_db_models.py
  git commit -m "feat: 21 DB models with is_active, resolved_at, kev_date_added, epss_score"
  ```

---

### Task 4: Alembic Migrations + RLS

**Files:**
- Create: `backend/alembic.ini`
- Create: `backend/alembic/env.py`
- Create: `backend/alembic/versions/0001_initial_schema.py`
- Create: `backend/alembic/versions/0002_rls_policies.py`

**Interfaces:**
- Produces: `alembic upgrade head` creates 21 tables; RLS enabled on 13 tenant tables

Tenant-isolated tables (RLS on `tenant_id`): `assets`, `software`, `observations`, `exposure_matches`, `scores`, `correlation_events`, `cases`, `identities`, `score_rules`, `audit_logs`, `leaks`, `feedback_events`.
`tenants` uses `id` column in the RLS policy (not `tenant_id`).

RLS policy (apply to each table, substituting `{col}` and `{t}`):
```sql
ALTER TABLE {t} ENABLE ROW LEVEL SECURITY;
ALTER TABLE {t} FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON {t}
  USING ({col} = current_setting('app.current_tenant_id', true)::uuid
         OR current_setting('app.bypass_tenant_scope', true) = 'on');
```

- [ ] **Step 1: Write failing tests**

  ```python
  # tests/test_migrations.py
  def test_kev_catalog_exists(pg_conn):
      r = pg_conn.execute(text(
          "SELECT 1 FROM information_schema.tables WHERE table_name='kev_catalog'"
      )).scalar()
      assert r == 1

  def test_rls_on_correlation_events(pg_conn):
      r = pg_conn.execute(text(
          "SELECT relrowsecurity FROM pg_class WHERE relname='correlation_events'"
      )).scalar()
      assert r is True

  def test_no_rls_on_vulnerabilities(pg_conn):
      r = pg_conn.execute(text(
          "SELECT relrowsecurity FROM pg_class WHERE relname='vulnerabilities'"
      )).scalar()
      assert r is False
  ```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement `alembic/env.py`**

  Use `MIGRATION_DATABASE_URL` (postgres superuser). `target_metadata = Base.metadata`. Async-compatible with `asyncio.run`.

- [ ] **Step 4: Write `0001_initial_schema.py`**

  `op.create_table(...)` for all 21 tables in dependency order (sources → tenants → assets → ... → audit_logs). Column definitions match Task 3 models exactly.

- [ ] **Step 5: Write `0002_rls_policies.py`**

  `op.execute(...)` for each of the 13 tenant-isolated tables.
  `op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sentinel_app")`.
  `op.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sentinel_app")`.

- [ ] **Step 6: Run migration + tests**

  Run: `alembic upgrade head && pytest tests/test_migrations.py -v`
  Expected: PASS.

- [ ] **Step 7: Commit**

  ```bash
  git add alembic/ alembic.ini tests/test_migrations.py
  git commit -m "feat: migrations — 21 tables, RLS on 13 tenant-isolated tables"
  ```

---

### Task 5: Auth — JWT, Roles, Tenant Session

**Files:**
- Create: `backend/app/auth/jwt.py`
- Create: `backend/app/auth/roles.py`
- Create: `backend/app/auth/deps.py`
- Create: `backend/app/core/db.py`

**Interfaces:**
- Produces:
  - `class TokenData`: fields `sub: str`, `tenant_id: UUID`, `roles: list[str]`
  - `verify_token(token: str) -> TokenData` — raises `HTTPException(401)` on invalid/expired
  - `class Role(str, Enum)`: `SUPER_ADMIN`, `TENANT_ADMIN`, `ANALYST`, `VIEWER`, `API_USER`
  - `require_roles(*roles: Role) -> Depends` — raises `HTTPException(403)` if user has none of the roles
  - `get_current_user: Depends` — returns `TokenData`
  - `get_tenant_scoped_db(token: TokenData) -> AsyncGenerator[AsyncSession]`
  - `bypass_session() -> AsyncGenerator[AsyncSession]`

- [ ] **Step 1: Write failing tests**

  ```python
  # tests/test_api/test_auth.py
  def test_missing_auth_header_returns_401(client):
      r = client.get("/api/v1/assets")
      assert r.status_code == 401
      assert r.json()["error"]["code"] == "UNAUTHORIZED"

  def test_malformed_token_returns_401(client):
      r = client.get("/api/v1/assets",
                     headers={"Authorization": "Bearer not.valid.jwt"})
      assert r.status_code == 401

  def test_viewer_cannot_patch_exposure(client, viewer_token, exposure_match_id):
      r = client.patch(f"/api/v1/exposure-matches/{exposure_match_id}",
                       headers={"Authorization": f"Bearer {viewer_token}"},
                       json={"status": "resolved"})
      assert r.status_code == 403
      assert r.json()["error"]["code"] == "FORBIDDEN"
  ```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement `app/auth/jwt.py`**

  `verify_token(token)`: fetch JWKS from `{keycloak_url}/realms/{realm}/protocol/openid-connect/certs` (module-level cache, refresh after 5 min). Decode RS256 JWT with `PyJWT`. Verify `iss` and `aud == settings.keycloak_client_id`. Extract `sub`, `tenant_id`, roles from `realm_access.roles` or `roles` claim. Return `TokenData`.

- [ ] **Step 4: Implement `app/auth/roles.py`**

  `class Role(str, Enum)` with 5 values (snake_case values matching Keycloak role names). `require_roles(*roles)`: returns `Depends` that raises `HTTPException(403, detail=error_response("FORBIDDEN", "Insufficient permissions"))` if user has none of the required roles.

- [ ] **Step 5: Implement `app/core/db.py`**

  Async SQLAlchemy engine. `get_tenant_scoped_db(token_data)`: `async with session.begin(): await session.execute(text("SET LOCAL app.current_tenant_id = :id"), {"id": str(token_data.tenant_id)})`. `bypass_session()`: `SET LOCAL app.bypass_tenant_scope = 'on'`.

- [ ] **Step 6: Run — expect PASS**

  Run: `pytest tests/test_api/test_auth.py -v`

- [ ] **Step 7: Commit**

  ```bash
  git add app/auth/ app/core/db.py tests/test_api/test_auth.py
  git commit -m "feat: JWT RS256 auth (JWKS cache), Role enum, tenant-scoped session"
  ```

---

### Task 6: Redis Stream Utilities

**Files:**
- Create: `backend/app/core/streams.py`

**Interfaces:**
- Produces:
  - `publish(stream: str, data: dict) -> None`
  - `read_batch(stream: str, cursor_key: str, count: int = 100) -> tuple[list[dict], str]`
  - `save_cursor(cursor_key: str, last_id: str) -> None`
  - `get_cursor(cursor_key: str) -> str` — returns `"0"` if not set

- [ ] **Step 1: Write failing tests**

  ```python
  # tests/test_core/test_streams.py
  def test_publish_and_read(redis_client):
      from app.core.streams import publish, read_batch
      publish("test-s1", {"k": "v"})
      msgs, last_id = read_batch("test-s1", "cur:s1")
      assert len(msgs) == 1
      assert msgs[0]["k"] == "v"
      assert last_id != "0"

  def test_cursor_not_saved_on_exception(redis_client):
      from app.core.streams import publish, read_batch, save_cursor, get_cursor
      publish("test-s2", {"k": "v"})
      before = get_cursor("cur:s2")
      try:
          msgs, last_id = read_batch("test-s2", "cur:s2")
          raise RuntimeError("simulated failure")
          save_cursor("cur:s2", last_id)  # unreachable
      except RuntimeError:
          pass
      assert get_cursor("cur:s2") == before

  def test_get_cursor_default_is_zero(redis_client):
      from app.core.streams import get_cursor
      assert get_cursor("cur:nonexistent:xyz") == "0"
  ```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement `app/core/streams.py`**

  Sync `redis.Redis` from `settings.redis_url`. `publish`: `r.xadd(stream, data, maxlen=50000, approximate=True)`. `read_batch`: `r.xread({stream: get_cursor(cursor_key)}, count=count)`; parse result to list of dicts + last id. `save_cursor`: `r.set(cursor_key, last_id)`. `get_cursor`: `r.get(cursor_key) or "0"`.

- [ ] **Step 4: Run — expect PASS**

  Run: `pytest tests/test_core/test_streams.py -v`

- [ ] **Step 5: Commit**

  ```bash
  git add app/core/streams.py tests/test_core/test_streams.py
  git commit -m "feat: Redis stream helpers — explicit cursor, MAXLEN 50000"
  ```

---

### Task 7: Collectors

**Files:**
- Create: `backend/app/collectors/base.py`
- Create: `backend/app/collectors/nvd.py`
- Create: `backend/app/collectors/kev.py`
- Create: `backend/app/collectors/ioc.py`
- Create: `backend/app/collectors/leak.py`
- Create: `backend/app/collectors/phishing.py`
- Create: `backend/app/collectors/attack.py`

**Interfaces:**
- Produces:
  - `BaseCollector.write_observation(tenant_id, entity_type, entity_id, raw_data) -> None`
  - `NvdCollector.fetch_cves(since: datetime) -> list[dict]`
  - `NvdCollector.run(since: datetime | None = None) -> int`
  - `KevCollector.run() -> int`
  - `LeakCollector.run(tenant_id: UUID, watchlist: list[str]) -> int`
  - All others: `.run() -> int`

- [ ] **Step 1: Write failing tests**

  ```python
  # tests/test_collectors/test_nvd.py
  def test_fetch_cves_sends_lastModStartDate(httpx_mock):
      import re
      httpx_mock.add_response(
          url=re.compile(r".*lastModStartDate.*"),
          json={"vulnerabilities": [], "totalResults": 0, "resultsPerPage": 200, "startIndex": 0}
      )
      from app.collectors.nvd import NvdCollector
      NvdCollector().fetch_cves(since=datetime(2026, 1, 1, tzinfo=timezone.utc))
      assert any("lastModStartDate" in str(r.url) for r in httpx_mock.get_requests())

  def test_fetch_cves_paginates_all_pages(httpx_mock):
      page1 = {"vulnerabilities": [{"cve": {"id": f"CVE-2026-{i:04d}", "metrics": {}}}
                                    for i in range(200)],
               "totalResults": 300, "resultsPerPage": 200, "startIndex": 0}
      page2 = {"vulnerabilities": [{"cve": {"id": f"CVE-2026-{i:04d}", "metrics": {}}}
                                    for i in range(200, 300)],
               "totalResults": 300, "resultsPerPage": 200, "startIndex": 200}
      httpx_mock.add_response(json=page1)
      httpx_mock.add_response(json=page2)
      from app.collectors.nvd import NvdCollector
      results = NvdCollector().fetch_cves(since=datetime(2026, 1, 1, tzinfo=timezone.utc))
      assert len(results) == 300

  # tests/test_collectors/test_leak.py
  def test_leak_no_cross_tenant(db_session, tenant_a, tenant_b, httpx_mock):
      import re
      httpx_mock.add_response(url=re.compile(r".*haveibeenpwned.*"),
                              json=[{"Name": "TestBreach", "PwnCount": 5000}])
      from app.collectors.leak import LeakCollector
      LeakCollector().run(tenant_id=tenant_a.id, watchlist=["user@a.com"])
      assert db_session.query(Observation).filter_by(tenant_id=tenant_a.id).count() >= 1
      assert db_session.query(Observation).filter_by(tenant_id=tenant_b.id).count() == 0

  def test_leak_email_hashed_sha256(db_session, tenant_a, httpx_mock):
      import re, hashlib
      httpx_mock.add_response(url=re.compile(r".*haveibeenpwned.*"),
                              json=[{"Name": "Breach", "PwnCount": 1000}])
      from app.collectors.leak import LeakCollector
      LeakCollector().run(tenant_id=tenant_a.id, watchlist=["secret@test.com"])
      leak = db_session.query(Leak).filter_by(tenant_id=tenant_a.id).first()
      expected_hash = hashlib.sha256("secret@test.com".lower().encode()).hexdigest()
      assert leak.email_hash == expected_hash
  ```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement `app/collectors/base.py`**

  `BaseCollector.write_observation`: insert `Observation` via `bypass_session()`; publish to `raw-observations` stream.

- [ ] **Step 4: Implement `app/collectors/nvd.py`**

  `fetch_cves(since)`: params `lastModStartDate=since.isoformat()`, `lastModEndDate=now.isoformat()`, `startIndex=0`, `resultsPerPage=200`. If `NVD_API_KEY`: add header `apiKey`. Loop: fetch, append `response["vulnerabilities"]`, increment `startIndex += 200`; sleep 0.6s without key. Stop when `startIndex >= totalResults`.
  `run(since=None)`: load cursor from Redis `collector:nvd:last_run` (or `now()-90d`); call `fetch_cves`; `write_observation` per CVE per active tenant; save cursor only after all writes succeed.

- [ ] **Step 5: Implement `app/collectors/kev.py`**

  `KevCollector.run()`: GET CISA KEV JSON; upsert all rows into `kev_catalog` via `bypass_session()`; return count.

- [ ] **Step 6: Implement remaining collectors**

  `IocCollector`: return early if `not settings.ioc_collector_enabled`.
  `LeakCollector.run(tenant_id, watchlist)`: hash each email with `hashlib.sha256(email.lower().encode()).hexdigest()`; query HIBP; store `Leak(tenant_id=tenant_id, email_hash=hash, ...)`; skip if `not settings.leak_collector_enabled`.
  `PhishingCollector.run(tenant_id, domains)`: generate ≤60 permutations per domain, DNS resolve, store `PhishingDomain`.
  `AttackCollector.run()`: fetch STIX from GitHub, upsert `AttackTechnique`.

- [ ] **Step 7: Run — expect PASS**

  Run: `pytest tests/test_collectors/ -v`

- [ ] **Step 8: Commit**

  ```bash
  git add app/collectors/ tests/test_collectors/
  git commit -m "feat: collectors — NVD paginated+date filter, KEV catalog, HIBP per-tenant"
  ```

---

### Task 8: Normalize Engine

**Files:**
- Create: `backend/app/normalize/engine.py`

**Interfaces:**
- Consumes: `read_batch("raw-observations", "normalize:cursor")`
- Produces: upserts to `Vulnerability`, `Indicator`, `Leak`, `PhishingDomain`; publishes to `enriched-entities`; advances cursor only on full-batch success
- `NormalizeEngine.run() -> int`

- [ ] **Step 1: Write failing tests**

  ```python
  # tests/test_normalize/test_engine.py
  def test_cve_obs_creates_vulnerability(db_session, redis_client):
      from app.core.streams import publish
      publish("raw-observations", {
          "tenant_id": str(uuid4()),
          "entity_type": "cve", "entity_id": "CVE-2024-9001",
          "raw_data": json.dumps({"cvss_score": 8.5, "description": "test"})
      })
      from app.normalize.engine import NormalizeEngine
      count = NormalizeEngine().run()
      assert count >= 1
      vuln = db_session.execute(
          select(Vulnerability).where(Vulnerability.cve_id == "CVE-2024-9001")
      ).scalar_one_or_none()
      assert vuln is not None
      assert vuln.cvss_score == 8.5

  def test_normalize_publishes_to_enriched(redis_client):
      from app.core.streams import publish, read_batch
      publish("raw-observations", {
          "entity_type": "cve", "entity_id": "CVE-2024-9002",
          "raw_data": json.dumps({"cvss_score": 5.0})
      })
      from app.normalize.engine import NormalizeEngine
      NormalizeEngine().run()
      msgs, _ = read_batch("enriched-entities", "test:enrich:check")
      assert any(m.get("entity_id") == "CVE-2024-9002" for m in msgs)
  ```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement `app/normalize/engine.py`**

  `NormalizeEngine.run()`: `read_batch("raw-observations", "normalize:cursor")`; dispatch by `entity_type`; upsert to catalog table (ON CONFLICT DO UPDATE); publish to `enriched-entities`; `save_cursor` only after all batch items processed without exception. Return count.

- [ ] **Step 4: Run — expect PASS**

  Run: `pytest tests/test_normalize/ -v`

- [ ] **Step 5: Commit**

  ```bash
  git add app/normalize/ tests/test_normalize/
  git commit -m "feat: normalize engine — raw-observations to catalog, at-least-once"
  ```

---

### Task 9: Enrich Engine + CPE Version Matching

**Files:**
- Create: `backend/app/enrichment/cpe.py`
- Create: `backend/app/enrichment/engine.py`

**Interfaces:**
- Consumes: `read_batch("enriched-entities", "enrich:cursor")`
- Produces: updated `vulnerabilities.epss_score`, `kev_date_added`; reads KEV from `kev_catalog` table only
- `match_cpe(software_cpe: str, vuln_configurations: list[dict]) -> tuple[bool, float]`

- [ ] **Step 1: Write failing tests**

  ```python
  # tests/test_enrichment/test_cpe.py
  def test_version_end_excluding_match_below():
      from app.enrichment.cpe import match_cpe
      configs = [{"criteria": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", "versionEndExcluding": "2.0.0"}]
      matched, conf = match_cpe("cpe:2.3:a:v:p:1.9.9:*:*:*:*:*:*:*", configs)
      assert matched is True

  def test_version_end_excluding_no_match_at_boundary():
      from app.enrichment.cpe import match_cpe
      configs = [{"criteria": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", "versionEndExcluding": "2.0.0"}]
      matched, _ = match_cpe("cpe:2.3:a:v:p:2.0.0:*:*:*:*:*:*:*", configs)
      assert matched is False

  def test_version_end_including_matches_at_boundary():
      from app.enrichment.cpe import match_cpe
      configs = [{"criteria": "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", "versionEndIncluding": "2.0.0"}]
      matched, _ = match_cpe("cpe:2.3:a:v:p:2.0.0:*:*:*:*:*:*:*", configs)
      assert matched is True

  # tests/test_enrichment/test_engine.py
  def test_kev_read_from_table_not_http(db_session, redis_client, httpx_mock):
      from sqlalchemy import insert
      db_session.execute(insert(KevCatalog).values(
          cve_id="CVE-2024-KEV1", date_added=date(2024, 1, 1)))
      db_session.commit()
      from app.core.streams import publish
      publish("enriched-entities", {
          "entity_type": "cve", "entity_id": "CVE-2024-KEV1", "raw_data": "{}"
      })
      from app.enrichment.engine import EnrichEngine
      EnrichEngine().run()
      assert not any("cisa.gov" in str(r.url) for r in httpx_mock.get_requests())
  ```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement `app/enrichment/cpe.py`**

  `match_cpe(software_cpe, vuln_configurations) -> (bool, float)`: parse version from CPE field 5 (colon-split). For each config: if version range fields exist, compare using `packaging.version.Version`; if version is `*`, return `(True, 0.7)`; otherwise substring match on product `(True, 0.5)`. Exact range match returns `(True, 0.9)`. No match: `(False, 0.0)`.

- [ ] **Step 4: Implement `app/enrichment/engine.py`**

  `EnrichEngine.run()`: `read_batch("enriched-entities", "enrich:cursor")`. CVE: query `kev_catalog` for `kev_date_added`; call EPSS API (in-memory run cache); update `vulnerabilities`. IP indicators: GeoIP, AbuseIPDB, VT, GreyNoise (each gated on key presence). `save_cursor` only after full batch success.

- [ ] **Step 5: Run — expect PASS**

  Run: `pytest tests/test_enrichment/ -v`

- [ ] **Step 6: Commit**

  ```bash
  git add app/enrichment/ tests/test_enrichment/
  git commit -m "feat: enrich engine — CPE version ranges, KEV from catalog table"
  ```

---

### Task 10: Correlation Engine

**Files:**
- Create: `backend/app/correlation/rules.py`
- Create: `backend/app/correlation/engine.py`

**Interfaces:**
- Consumes: tenant asset/software/identity data via `bypass_session()`
- Produces: `CorrelationEvent` rows (`is_active=True`), `ExposureMatch` rows; publishes to `correlation-events`
- `correlate_vuln_software(session, tenant_id) -> list[CorrelationEvent]`
- `correlate_ioc_asset(session, tenant_id) -> list[CorrelationEvent]`
- `correlate_leak_identity(session, tenant_id) -> list[CorrelationEvent]`
- `correlate_phishing_brand(session, tenant_id) -> list[CorrelationEvent]`
- `correlate_campaign_asset(session, tenant_id) -> list[CorrelationEvent]`
- `CorrelationEngine.run_for_tenant(tenant_id: UUID) -> int`

- [ ] **Step 1: Write failing tests**

  ```python
  # tests/test_correlation/test_engine.py
  def test_vuln_software_creates_event(db_session, tenant, asset, software_with_cpe, matching_vulnerability):
      from app.correlation.engine import CorrelationEngine
      CorrelationEngine().run_for_tenant(tenant.id)
      events = db_session.execute(
          select(CorrelationEvent).where(CorrelationEvent.tenant_id == tenant.id)
      ).scalars().all()
      assert len(events) >= 1

  def test_new_events_are_active(db_session, tenant, asset, software_with_cpe, matching_vulnerability):
      from app.correlation.engine import CorrelationEngine
      CorrelationEngine().run_for_tenant(tenant.id)
      inactive = db_session.execute(
          select(CorrelationEvent).where(
              CorrelationEvent.tenant_id == tenant.id,
              CorrelationEvent.is_active == False
          )
      ).scalars().all()
      assert len(inactive) == 0
  ```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement `app/correlation/rules.py`**

  `correlate_vuln_software`: for each `Software` with CPE, call `match_cpe` against all `Vulnerability` configurations; create event if matched.
  `correlate_ioc_asset`: exact IP or CIDR match against `Asset.ip`; domain suffix match against `Asset.hostname`.
  `correlate_leak_identity`: match `Leak.email_hash` against SHA-256 of `Identity.email` for same tenant.
  `correlate_phishing_brand`: `PhishingDomain.target_brand` in tenant `domains`.
  `correlate_campaign_asset`: `Campaign.target_sectors` intersects `Tenant.sector`.

- [ ] **Step 4: Implement `app/correlation/engine.py`**

  `CorrelationEngine.run_for_tenant(tenant_id)`: run all 5 rules; upsert events (ON CONFLICT: update `s_context`); create `ExposureMatch` for new events; publish to `correlation-events`; return count.

- [ ] **Step 5: Run — expect PASS**

  Run: `pytest tests/test_correlation/ -v`

- [ ] **Step 6: Commit**

  ```bash
  git add app/correlation/ tests/test_correlation/
  git commit -m "feat: correlation engine — 5 rules, is_active=True on all new events"
  ```

---

### Task 11: Risk Engine, Formulas, Notifications

**Files:**
- Create: `backend/app/risk/formulas.py`
- Create: `backend/app/risk/engine.py`
- Create: `backend/app/notifications/engine.py`
- Create: `backend/app/notifications/adapters/slack.py`
- Create: `backend/app/notifications/adapters/email.py`
- Create: `backend/app/notifications/adapters/webhook.py`

**Interfaces:**
- Produces:
  - `DEFAULT_WEIGHTS = {"severity": 0.45, "confidence": 0.27, "recency": 0.18, "epss": 0.10}`
  - `s_base(sev, conf, rec, epss, weights: dict) -> float`
  - `f_recency(created_at: datetime) -> float` — 1.0/<7d, 0.5/≤30d, 0.2/else
  - `epss_boost(score: float | None) -> float`
  - `level_from_score(value: float, thresholds: dict) -> str`
  - `RiskEngine.run_for_tenant(tenant_id: UUID) -> float`
  - `check_and_notify(tenant_id, new_level, prev_level, score_value, settings) -> None`

- [ ] **Step 1: Write failing tests**

  ```python
  # tests/test_risk/test_formulas.py
  def test_s_base_uses_weights():
      from app.risk.formulas import s_base
      w = {"severity": 1.0, "confidence": 0.0, "recency": 0.0, "epss": 0.0}
      assert abs(s_base(0.8, 0.5, 0.5, 0.0, w) - 0.8) < 0.001

  def test_default_weights_sum_to_1():
      from app.risk.formulas import DEFAULT_WEIGHTS
      assert abs(sum(DEFAULT_WEIGHTS.values()) - 1.0) < 0.001

  def test_f_recency_6_days_is_1():
      from app.risk.formulas import f_recency
      assert f_recency(datetime.utcnow() - timedelta(days=6)) == 1.0

  def test_f_recency_31_days_is_0_5():
      from app.risk.formulas import f_recency
      assert f_recency(datetime.utcnow() - timedelta(days=31)) == 0.5

  def test_f_recency_60_days_is_0_2():
      from app.risk.formulas import f_recency
      assert f_recency(datetime.utcnow() - timedelta(days=60)) == 0.2

  def test_epss_boost_none_zero():
      from app.risk.formulas import epss_boost
      assert epss_boost(None) == 0.0

  def test_epss_boost_capped_0_3():
      from app.risk.formulas import epss_boost
      assert epss_boost(1.0) == 0.3

  def test_epss_boost_proportional():
      from app.risk.formulas import epss_boost
      assert abs(epss_boost(0.1) - 0.2) < 0.001

  # tests/test_risk/test_engine.py
  def test_score_decreases_after_resolve(db_session, tenant, corr_event_fixture, exposure_fixture):
      from app.risk.engine import RiskEngine
      RiskEngine().run_for_tenant(tenant.id)
      before = db_session.execute(
          select(Score).where(Score.tenant_id == tenant.id, Score.score_type == "tenant")
          .order_by(Score.computed_at.desc())
      ).scalar_one().value

      exposure_fixture.status = "resolved"
      corr_event_fixture.is_active = False
      corr_event_fixture.resolved_at = datetime.utcnow()
      db_session.commit()

      RiskEngine().run_for_tenant(tenant.id)
      after = db_session.execute(
          select(Score).where(Score.tenant_id == tenant.id, Score.score_type == "tenant")
          .order_by(Score.computed_at.desc())
      ).scalar_one().value
      assert after < before

  def test_score_rule_weights_read_not_hardcoded(db_session, tenant):
      from app.risk.engine import RiskEngine
      rule = db_session.execute(
          select(ScoreRule).where(ScoreRule.tenant_id == None)
      ).scalar_one()
      rule.weights = {"severity": 1.0, "confidence": 0.0, "recency": 0.0, "epss": 0.0}
      db_session.commit()
      RiskEngine().run_for_tenant(tenant.id)  # must not raise

  # tests/test_notifications/test_engine.py
  def test_notify_on_level_change(mocker):
      slack_send = mocker.patch("app.notifications.adapters.slack.send")
      from app.notifications.engine import check_and_notify
      s = MagicMock(slack_webhook_url="https://hooks.slack.com/x", smtp_host=None)
      check_and_notify(uuid4(), "high", "medium", 0.75, s)
      slack_send.assert_called_once()

  def test_no_notify_same_level(mocker):
      slack_send = mocker.patch("app.notifications.adapters.slack.send")
      from app.notifications.engine import check_and_notify
      s = MagicMock(slack_webhook_url="https://hooks.slack.com/x", smtp_host=None)
      check_and_notify(uuid4(), "medium", "medium", 0.5, s)
      slack_send.assert_not_called()
  ```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement `app/risk/formulas.py`**

  `DEFAULT_WEIGHTS = {"severity": 0.45, "confidence": 0.27, "recency": 0.18, "epss": 0.10}`.
  `s_base(sev, conf, rec, epss, weights)`: normalize: `total = sum(weights.values()); w = {k: v/total for k,v in weights.items()}`; return `sev*w["severity"] + conf*w["confidence"] + rec*w["recency"] + epss*w["epss"]`.
  `f_recency(created_at)`: `age = (datetime.utcnow() - created_at).days`; return `1.0 if age < 7 else 0.5 if age <= 30 else 0.2`.
  `epss_boost(score)`: `0.0 if score is None else min(score * 2.0, 0.3)`.
  `level_from_score(value, thresholds)`: `"critical" if value >= 0.9 else "high" if value >= thresholds["high"] else "medium" if value >= thresholds["medium"] else "low"`.

- [ ] **Step 4: Implement `app/risk/engine.py`**

  `RiskEngine.run_for_tenant(tenant_id)`:
  1. Load active `ScoreRule` via `bypass_session()`: `SELECT ... WHERE (tenant_id=:id OR tenant_id IS NULL) ORDER BY version DESC LIMIT 1`
  2. Load all `CorrelationEvent WHERE tenant_id=:id AND is_active=TRUE`
  3. For each event: compute `s_base(f_severity(event), f_confidence(event), f_recency(event.created_at), epss_boost(vuln.epss_score if vuln else None), rule.weights)`
  4. Aggregate to `R_tenant`; load prev score for level comparison
  5. Insert `Score(score_type="tenant", value=R_tenant, level=level_from_score(...))`
  6. Call `check_and_notify(tenant_id, new_level, prev_level, R_tenant, settings)`
  7. Return `R_tenant`

- [ ] **Step 5: Implement notifications**

  `check_and_notify(tenant_id, new_level, prev_level, score_value, settings)`: return immediately if `new_level == prev_level`. Call `slack.send` if `settings.slack_webhook_url`. Call `email.send` if `settings.smtp_host`. Call `webhook.send` if configured.
  Each adapter: `httpx.post(url, json={...}, timeout=5)`. Log warning on failure; do not raise.

- [ ] **Step 6: Run — expect PASS**

  Run: `pytest tests/test_risk/ tests/test_notifications/ -v`

- [ ] **Step 7: Commit**

  ```bash
  git add app/risk/ app/notifications/ tests/test_risk/ tests/test_notifications/
  git commit -m "feat: risk engine (score decay, EPSS, ScoreRule weights), alert on level change"
  ```

---

### Task 12: Celery Worker + Beat

**Files:**
- Create: `backend/app/worker/celery_app.py`
- Create: `backend/app/worker/tasks.py`

**Interfaces:**
- Produces: tasks registered as `sentinel.tasks.*`; beat schedule with normalize before enrich

- [ ] **Step 1: Write failing test**

  ```python
  # tests/test_worker/test_tasks.py
  def test_required_tasks_registered():
      from app.worker.celery_app import celery_app
      names = set(celery_app.tasks.keys())
      for name in ["sentinel.tasks.collect_nvd", "sentinel.tasks.collect_kev",
                   "sentinel.tasks.normalize", "sentinel.tasks.enrich",
                   "sentinel.tasks.correlate", "sentinel.tasks.risk_and_alert"]:
          assert name in names

  def test_normalize_fires_before_enrich():
      from app.worker.celery_app import celery_app
      sched = celery_app.conf.beat_schedule
      norm_minutes = set(sched["normalize"]["schedule"].minute)
      enrich_minutes = set(sched["enrich"]["schedule"].minute)
      assert min(norm_minutes) < min(enrich_minutes)
  ```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement `app/worker/celery_app.py`**

  Beat schedule: `normalize` at minutes `1,6,11,...,56`; `enrich` at `2,7,...,57`; `correlate` at `3,8,...,58`; `risk_and_alert` at `4,9,...,59`. `collect_nvd`: `crontab(minute=0)`. `collect_kev`: `crontab(hour=5, minute=0)`. Others per spec §5 beat table.

- [ ] **Step 4: Implement `app/worker/tasks.py`**

  Each `@celery_app.task(name="sentinel.tasks.X")`. `risk_and_alert`: load active tenants, run `RiskEngine().run_for_tenant(t.id)` for each. Disabled collectors check settings flag and return 0.

- [ ] **Step 5: Run — expect PASS**

  Run: `pytest tests/test_worker/ -v`

- [ ] **Step 6: Commit**

  ```bash
  git add app/worker/ tests/test_worker/
  git commit -m "feat: Celery beat schedule — normalize(:01) before enrich(:02)"
  ```

---

### Task 13: API Foundation + All Phase 1 Routes

**Files:**
- Create: `backend/app/main.py`
- Create: `backend/app/core/middleware.py`
- Create: `backend/app/core/rate_limit.py`
- Create: `backend/app/api/v1/errors.py`
- Create: `backend/app/api/v1/router.py`
- Create: all 15 route files under `backend/app/api/v1/routes/`

**Interfaces:**
- Produces: running FastAPI app with all Phase 1 endpoints; correct RBAC per spec §7

Pinned behaviours:
- `PATCH /api/v1/exposure-matches/{id}` with `status=resolved|false_positive`: sets `CorrelationEvent.is_active=False` AND `resolved_at=now()` in same transaction
- `DELETE /api/v1/tenants/{id}`: `require_roles(Role.SUPER_ADMIN)` only
- `POST/PATCH /api/v1/score-rules`: `require_roles(Role.SUPER_ADMIN)`; auto-increment `version`; write `AuditLog` entry
- `GET /api/v1/dashboard` → `open_cases` field counts rows in `cases` table, not `observations`
- `GET /api/v1/health`, `GET /api/v1/ready`: public, no auth required

- [ ] **Step 1: Write failing tests**

  ```python
  # tests/test_api/test_rbac.py
  def test_viewer_patch_exposure_403(client, viewer_token, exposure_id):
      r = client.patch(f"/api/v1/exposure-matches/{exposure_id}",
                       headers={"Authorization": f"Bearer {viewer_token}"},
                       json={"status": "resolved"})
      assert r.status_code == 403
      assert r.json()["error"]["code"] == "FORBIDDEN"

  def test_tenant_admin_delete_tenant_403(client, tenant_admin_token, tenant_id):
      r = client.delete(f"/api/v1/tenants/{tenant_id}",
                        headers={"Authorization": f"Bearer {tenant_admin_token}"})
      assert r.status_code == 403

  def test_unauthenticated_error_model(client):
      r = client.get("/api/v1/assets")
      assert r.status_code == 401
      assert set(r.json()["error"].keys()) >= {"code", "message"}

  def test_health_public(client):
      assert client.get("/api/v1/health").status_code == 200

  # tests/test_api/test_exposure.py
  def test_patch_resolved_deactivates_corr_event(
      client, analyst_token, db_session, exposure_match, corr_event
  ):
      r = client.patch(f"/api/v1/exposure-matches/{exposure_match.id}",
                       headers={"Authorization": f"Bearer {analyst_token}"},
                       json={"status": "resolved"})
      assert r.status_code == 200
      db_session.refresh(corr_event)
      assert corr_event.is_active is False
      assert corr_event.resolved_at is not None

  # tests/test_api/test_dashboard.py
  def test_open_cases_from_cases_table(client, analyst_token, db_session, tenant_id):
      db_session.add(Case(tenant_id=tenant_id, title="T", created_by="u@x.com"))
      db_session.commit()
      r = client.get("/api/v1/dashboard",
                     headers={"Authorization": f"Bearer {analyst_token}"})
      assert r.status_code == 200
      assert r.json()["open_cases"] >= 1
  ```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement `app/core/middleware.py`**

  Middleware stack (outer→inner): body size 10MB → CORS (`settings.cors_origins`) → security headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Strict-Transport-Security: max-age=31536000`) → audit log (append `AuditLog` row after response via `bypass_session()`).

- [ ] **Step 4: Implement `app/core/rate_limit.py`**

  `check_rate_limit(tenant_id, r)`: `INCR rl:{tenant_id}`; `EXPIRE rl:{tenant_id} 60` if result == 1; raise `HTTPException(429)` with error model if result > 100.

- [ ] **Step 5: Implement `app/api/v1/errors.py`**

  `error_response(code, message, detail={}) -> dict`.
  `http_exception_handler` and `validation_exception_handler` returning error model.

- [ ] **Step 6: Implement all route files**

  Apply `require_roles(...)` per RBAC table. `exposure.py`: PATCH sets `ExposureMatch.status` AND `CorrelationEvent.is_active=False` + `resolved_at=now()` in one transaction when status is resolved/false_positive. `score_rules.py`: POST/PATCH increments version, writes AuditLog. `dashboard.py`: `open_cases = count(Case WHERE tenant_id=X AND status='open')`.

- [ ] **Step 7: Implement `app/main.py`**

  `create_app()`: instantiate FastAPI, attach middleware, include `v1/router`, register exception handlers.

- [ ] **Step 8: Run full test suite**

  Run: `pytest tests/ -v -m "not integration" --tb=short`
  Expected: all PASS.

- [ ] **Step 9: Commit**

  ```bash
  git add app/main.py app/api/ app/core/middleware.py app/core/rate_limit.py tests/test_api/
  git commit -m "feat: Phase 1 API — routes, RBAC, error model, audit log, score decay via PATCH"
  ```

---

### Task 14: Integration Smoke Test

**Files:**
- Create: `backend/tests/test_integration/test_pipeline_smoke.py`

**Interfaces:**
- Validates: NVD collector uses date filter; full pipeline produces a Score row

- [ ] **Step 1: Write smoke tests**

  ```python
  # tests/test_integration/test_pipeline_smoke.py
  @pytest.mark.integration
  def test_nvd_collector_uses_date_filter(db_session, httpx_mock):
      httpx_mock.add_response(
          url=re.compile(r".*lastModStartDate.*"),
          json={"vulnerabilities": [
              {"cve": {"id": "CVE-2026-SMOKE",
               "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.0}}]}}}
          ], "totalResults": 1, "resultsPerPage": 200, "startIndex": 0}
      )
      from app.collectors.nvd import NvdCollector
      count = NvdCollector().run()
      assert count >= 1

  @pytest.mark.integration
  def test_full_pipeline_produces_score(db_session, tenant, asset, software_with_cpe):
      from app.normalize.engine import NormalizeEngine
      from app.enrichment.engine import EnrichEngine
      from app.correlation.engine import CorrelationEngine
      from app.risk.engine import RiskEngine

      NormalizeEngine().run()
      EnrichEngine().run()
      CorrelationEngine().run_for_tenant(tenant.id)
      RiskEngine().run_for_tenant(tenant.id)

      score = db_session.execute(
          select(Score).where(Score.tenant_id == tenant.id, Score.score_type == "tenant")
          .order_by(Score.computed_at.desc())
      ).scalar_one_or_none()
      assert score is not None
      assert 0.0 <= score.value <= 1.0
  ```

- [ ] **Step 2: Run unit tests (skip integration)**

  Run: `pytest tests/ -v -m "not integration"`
  Expected: all PASS.

- [ ] **Step 3: Run integration smoke (requires docker-compose up)**

  Run: `pytest tests/test_integration/ -v -m integration`
  Expected: all PASS.

- [ ] **Step 4: Commit**

  ```bash
  git add tests/test_integration/
  git commit -m "test: Phase 1 smoke tests — NVD date filter, full pipeline → Score row"
  ```
