# Sentinel AI Phase 3 — ML, SIEM, Infra & CI Implementation Plan

> **For agentic workers:** Use superpowers:subagent-driven-development to implement task-by-task.

**Goal:** Add ML capabilities (dark web classifier, IoC similarity, FAISS index, OLS forecast),
SIEM inbound/outbound connectors, infra-as-code (K3s Hetzner), and CI/CD pipeline.

**Architecture:**
- ML models run in the Celery worker; FAISS index rebuilt every 30 min on a shared PVC
- SIEM inbound: webhook endpoint → `feedback-events` Redis stream
- SIEM outbound: Celery task reads `feedback-events`, pushes to SIEM via configured webhook
- K3s: single-node Hetzner, Helm Bitnami for Postgres/Redis/Keycloak, Job for migrations
- CI: GitHub Actions — lint → pytest → vitest → Docker build → ghcr.io push

**Spec:** `docs/superpowers/specs/2026-10-23-sentinel-ai-design.md`
**Backend:** Phase 1 complete. **Frontend:** Phase 2 complete.

## Global Constraints

- All ML deps already in `pyproject.toml`: `numpy>=1.26`, `scikit-learn>=1.5`, `faiss-cpu>=1.8`
- FAISS index on shared PVC mounted at `/data/faiss/`; path env var `FAISS_INDEX_PATH=/data/faiss/ioc.index`
- Dark web classifier: binary sklearn pipeline (TF-IDF + LogisticRegression); retrain on first run if no model file
- IoC similarity: FAISS IndexFlatL2 over TF-IDF vectors of indicator values
- OLS forecast: numpy polyfit on last 30 daily score averages → next 7-day trend
- SIEM inbound endpoint: `POST /api/v1/siem/feedback` → write to `feedback-events` stream (no auth — API key header `X-SIEM-KEY` validated against `SIEM_INBOUND_KEY` env var)
- SIEM outbound: Celery task `push_siem_feedback` reads `feedback-events` stream; sends to `SIEM_OUTBOUND_URL` via HTTPS POST
- K3s: `iac/` directory; `iac/values/` per-service Helm values; `iac/jobs/migrate.yaml` for Alembic Job
- CI: `.github/workflows/ci.yml`; Docker images tagged `v{version}` from `pyproject.toml`; pushed to `ghcr.io/{owner}/sentinel-ai`
- All commits end with: `Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>`

---

## File Map

```
backend/
  app/
    ml/
      classifier.py           # dark web binary classifier (sklearn pipeline)
      similarity.py           # FAISS IoC similarity index
      forecast.py             # OLS score forecast (numpy polyfit)
    siem/
      inbound.py              # FastAPI route: POST /siem/feedback
      outbound.py             # Celery task: push_siem_feedback
  api/
    v1/
      routes/
        siem.py               # mounts inbound route
        ml.py                 # GET /ml/forecast, GET /ml/similar-iocs
  worker/
    tasks.py                  # add: rebuild_faiss_index, campaign_sweep, push_siem_feedback
  tests/
    test_ml/
      test_classifier.py
      test_similarity.py
      test_forecast.py
    test_siem/
      test_inbound.py
      test_outbound.py

frontend/
  src/
    pages/
      Scanner.tsx             # Phase 3 frontend page (placeholder → ML results)
      RedTeam.tsx             # Phase 3 frontend page (placeholder)
      Connectors.tsx          # Phase 3 frontend page (SIEM connector config)
    api/
      hooks/
        useForecast.ts
        useSimilarIocs.ts

iac/
  README.md
  k3s-install.sh              # K3s single-node install script (Hetzner)
  helmfile.yaml               # declares all Helm releases
  values/
    postgres.yaml
    redis.yaml
    keycloak.yaml
  manifests/
    namespace.yaml
    secrets-template.yaml     # template only; real secrets via kubectl create secret
    migrate-job.yaml          # Alembic upgrade head Job
    api-deployment.yaml
    worker-deployment.yaml
    beat-deployment.yaml
    frontend-deployment.yaml
    faiss-pvc.yaml

.github/
  workflows/
    ci.yml                    # lint → pytest → vitest → docker build → push ghcr.io
```

---

### Task 1: Dark Web Classifier

**Files:**
- Create: `backend/app/ml/classifier.py`
- Create: `backend/tests/test_ml/test_classifier.py`

**Interfaces:**
- Produces: `DarkWebClassifier.predict(texts: list[str]) -> list[float]`; `DarkWebClassifier.train(texts, labels)`; `DarkWebClassifier.save(path)`; `DarkWebClassifier.load(path)`

- [ ] **Step 1: Write failing tests**

  ```python
  # tests/test_ml/test_classifier.py
  import pytest
  from app.ml.classifier import DarkWebClassifier

  def test_predict_returns_probabilities():
      clf = DarkWebClassifier()
      clf.train(
          ["buy drugs tor", "financial report q3", "leaked credentials onion"],
          [1, 0, 1],
      )
      scores = clf.predict(["tor market", "quarterly earnings"])
      assert len(scores) == 2
      assert all(0.0 <= s <= 1.0 for s in scores)

  def test_predict_darkweb_scores_higher_than_benign():
      clf = DarkWebClassifier()
      clf.train(
          ["darknet market tor hidden", "annual report pdf", "leaked password onion site"],
          [1, 0, 1],
      )
      darkweb = clf.predict(["tor hidden service leak"])[0]
      benign = clf.predict(["quarterly financial report"])[0]
      assert darkweb > benign

  def test_save_load_roundtrip(tmp_path):
      path = str(tmp_path / "clf.pkl")
      clf = DarkWebClassifier()
      clf.train(["dark web", "normal text"], [1, 0])
      clf.save(path)
      clf2 = DarkWebClassifier.load(path)
      s1 = clf.predict(["tor leak"])
      s2 = clf2.predict(["tor leak"])
      assert abs(s1[0] - s2[0]) < 0.001
  ```

- [ ] **Step 2: Run — expect FAIL**

  ```bash
  cd backend && python -m pytest tests/test_ml/test_classifier.py -v
  ```

- [ ] **Step 3: Implement `app/ml/classifier.py`**

  ```python
  import pickle
  from sklearn.pipeline import Pipeline
  from sklearn.feature_extraction.text import TfidfVectorizer
  from sklearn.linear_model import LogisticRegression
  import numpy as np


  class DarkWebClassifier:
      def __init__(self) -> None:
          self._pipeline: Pipeline | None = None

      def train(self, texts: list[str], labels: list[int]) -> None:
          self._pipeline = Pipeline([
              ("tfidf", TfidfVectorizer(max_features=5000, ngram_range=(1, 2))),
              ("lr", LogisticRegression(max_iter=500, class_weight="balanced")),
          ])
          self._pipeline.fit(texts, labels)

      def predict(self, texts: list[str]) -> list[float]:
          if self._pipeline is None:
              raise RuntimeError("Model not trained. Call train() or load() first.")
          return self._pipeline.predict_proba(texts)[:, 1].tolist()

      def save(self, path: str) -> None:
          with open(path, "wb") as f:
              pickle.dump(self._pipeline, f)

      @classmethod
      def load(cls, path: str) -> "DarkWebClassifier":
          obj = cls()
          with open(path, "rb") as f:
              obj._pipeline = pickle.load(f)  # noqa: S301 — internal model file
          return obj
  ```

- [ ] **Step 4: Add `__init__.py`**

  ```bash
  touch backend/app/ml/__init__.py
  ```

- [ ] **Step 5: Run — expect PASS**

  ```bash
  python -m pytest tests/test_ml/test_classifier.py -v
  ```

- [ ] **Step 6: Commit**

  ```bash
  git add backend/app/ml/ backend/tests/test_ml/test_classifier.py
  git commit -m "feat: dark web binary classifier (TF-IDF + LogisticRegression, save/load)

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
  ```

---

### Task 2: IoC Similarity (FAISS)

**Files:**
- Create: `backend/app/ml/similarity.py`
- Create: `backend/tests/test_ml/test_similarity.py`

**Interfaces:**
- Produces: `IocSimilarityIndex.add(indicators: list[str])`; `IocSimilarityIndex.search(query: str, k: int) -> list[tuple[str, float]]`; `IocSimilarityIndex.save(path)`; `IocSimilarityIndex.load(path)`

- [ ] **Step 1: Write failing tests**

  ```python
  # tests/test_ml/test_similarity.py
  import pytest
  from app.ml.similarity import IocSimilarityIndex

  IOC_CORPUS = [
      "192.168.1.100",
      "192.168.1.101",
      "10.0.0.1",
      "malware.example.com",
      "evil.tor.onion",
  ]

  def test_search_returns_k_results():
      idx = IocSimilarityIndex()
      idx.add(IOC_CORPUS)
      results = idx.search("192.168.1.200", k=3)
      assert len(results) == 3

  def test_similar_ip_ranked_first():
      idx = IocSimilarityIndex()
      idx.add(IOC_CORPUS)
      results = idx.search("192.168.1.102", k=2)
      # 192.168.1.100 or .101 should be most similar
      top_value = results[0][0]
      assert "192.168.1" in top_value

  def test_save_load_roundtrip(tmp_path):
      idx = IocSimilarityIndex()
      idx.add(IOC_CORPUS)
      idx.save(str(tmp_path / "ioc.index"))
      idx2 = IocSimilarityIndex.load(str(tmp_path / "ioc.index"))
      r1 = idx.search("192.168.1.200", k=1)
      r2 = idx2.search("192.168.1.200", k=1)
      assert r1[0][0] == r2[0][0]
  ```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement `app/ml/similarity.py`**

  ```python
  import pickle
  import faiss
  import numpy as np
  from sklearn.feature_extraction.text import TfidfVectorizer


  class IocSimilarityIndex:
      def __init__(self) -> None:
          self._vectorizer: TfidfVectorizer | None = None
          self._index: faiss.Index | None = None
          self._items: list[str] = []

      def add(self, indicators: list[str]) -> None:
          self._vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4), max_features=1024)
          vecs = self._vectorizer.fit_transform(indicators).toarray().astype(np.float32)
          faiss.normalize_L2(vecs)
          self._index = faiss.IndexFlatIP(vecs.shape[1])
          self._index.add(vecs)
          self._items = list(indicators)

      def search(self, query: str, k: int = 10) -> list[tuple[str, float]]:
          if self._vectorizer is None or self._index is None:
              raise RuntimeError("Index not built. Call add() or load() first.")
          vec = self._vectorizer.transform([query]).toarray().astype(np.float32)
          faiss.normalize_L2(vec)
          k = min(k, len(self._items))
          dists, idxs = self._index.search(vec, k)
          return [(self._items[i], float(d)) for i, d in zip(idxs[0], dists[0]) if i >= 0]

      def save(self, path: str) -> None:
          faiss.write_index(self._index, path)
          with open(path + ".meta", "wb") as f:
              pickle.dump({"vectorizer": self._vectorizer, "items": self._items}, f)

      @classmethod
      def load(cls, path: str) -> "IocSimilarityIndex":
          obj = cls()
          obj._index = faiss.read_index(path)
          with open(path + ".meta", "rb") as f:
              meta = pickle.load(f)  # noqa: S301 — internal index file
          obj._vectorizer = meta["vectorizer"]
          obj._items = meta["items"]
          return obj
  ```

- [ ] **Step 4: Run — expect PASS**

  ```bash
  python -m pytest tests/test_ml/test_similarity.py -v
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add backend/app/ml/similarity.py backend/tests/test_ml/test_similarity.py
  git commit -m "feat: IoC similarity search with FAISS IndexFlatIP + char-ngram TF-IDF

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
  ```

---

### Task 3: OLS Score Forecast

**Files:**
- Create: `backend/app/ml/forecast.py`
- Create: `backend/tests/test_ml/test_forecast.py`

**Interfaces:**
- Produces: `forecast_scores(daily_avgs: list[float], horizon: int = 7) -> list[float]`

- [ ] **Step 1: Write failing tests**

  ```python
  # tests/test_ml/test_forecast.py
  import pytest
  from app.ml.forecast import forecast_scores

  def test_returns_horizon_values():
      data = [0.3 + i * 0.01 for i in range(30)]
      result = forecast_scores(data, horizon=7)
      assert len(result) == 7

  def test_upward_trend_continues():
      data = [0.1 * i / 29 for i in range(30)]  # 0.0 → 0.1 linear
      result = forecast_scores(data, horizon=7)
      # forecast should continue upward
      assert result[-1] > result[0]

  def test_all_values_clamped_0_to_1():
      data = [0.99] * 30
      result = forecast_scores(data, horizon=7)
      assert all(0.0 <= v <= 1.0 for v in result)

  def test_raises_on_too_few_points():
      with pytest.raises(ValueError, match="at least 2"):
          forecast_scores([0.5], horizon=3)
  ```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement `app/ml/forecast.py`**

  ```python
  import numpy as np


  def forecast_scores(daily_avgs: list[float], horizon: int = 7) -> list[float]:
      """OLS linear forecast over daily_avgs for `horizon` future steps.

      Returns values clamped to [0.0, 1.0].
      """
      if len(daily_avgs) < 2:
          raise ValueError("forecast_scores requires at least 2 data points")
      x = np.arange(len(daily_avgs), dtype=float)
      coeffs = np.polyfit(x, daily_avgs, deg=1)
      future_x = np.arange(len(daily_avgs), len(daily_avgs) + horizon, dtype=float)
      forecast = np.polyval(coeffs, future_x)
      return np.clip(forecast, 0.0, 1.0).tolist()
  ```

- [ ] **Step 4: Run — expect PASS**

  ```bash
  python -m pytest tests/test_ml/test_forecast.py -v
  ```

- [ ] **Step 5: Commit**

  ```bash
  git add backend/app/ml/forecast.py backend/tests/test_ml/test_forecast.py
  git commit -m "feat: OLS score forecast (numpy polyfit, 7-day horizon, clamped 0-1)

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
  ```

---

### Task 4: FAISS Index Celery Task + ML API Routes

**Files:**
- Create: `backend/app/api/v1/routes/ml.py`
- Modify: `backend/app/worker/tasks.py` (add `rebuild_faiss_index`, `campaign_sweep`)

**Interfaces:**
- Produces: `rebuild_faiss_index` Celery task (every 30 min); `GET /ml/forecast?tenant_id=`; `GET /ml/similar-iocs?value=&k=`

- [ ] **Step 1: Write failing tests**

  ```python
  # tests/test_ml/test_rebuild_task.py
  import pytest
  from unittest.mock import patch, MagicMock
  from app.worker.tasks import rebuild_faiss_index

  def test_rebuild_faiss_index_loads_indicators(db_session, tenant):
      from app.db.models import Indicator
      ind = Indicator(tenant_id=tenant.id, ioc_type="ip", value="192.168.1.1", confidence=0.9)
      db_session.add(ind)
      db_session.flush()
      with patch("app.worker.tasks.IocSimilarityIndex") as mock_cls:
          mock_idx = MagicMock()
          mock_cls.return_value = mock_idx
          rebuild_faiss_index()
          mock_idx.add.assert_called_once()
          args = mock_idx.add.call_args[0][0]
          assert "192.168.1.1" in args
  ```

  ```python
  # tests/test_ml/test_ml_routes.py
  from fastapi.testclient import TestClient
  from unittest.mock import patch
  from app.main import app

  client = TestClient(app)

  def test_forecast_endpoint(monkeypatch):
      monkeypatch.setenv("DATABASE_URL", "sqlite:///:memory:")
      with patch("app.api.v1.routes.ml.get_daily_score_avgs", return_value=[0.3 + i*0.01 for i in range(30)]):
          with patch("app.api.v1.routes.ml.decode_token", return_value=MagicMock(tenant_id="t1")):
              r = client.get("/api/v1/ml/forecast?tenant_id=t1", headers={"Authorization": "Bearer tok"})
      assert r.status_code == 200
      assert "forecast" in r.json()
      assert len(r.json()["forecast"]) == 7
  ```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement `app/api/v1/routes/ml.py`**

  ```python
  import os
  from fastapi import APIRouter, Depends, Query
  from sqlalchemy.orm import Session
  from app.core.db import get_tenant_scoped_db
  from app.auth.deps import get_current_user
  from app.db.models import Score, Indicator
  from app.ml.forecast import forecast_scores
  from app.ml.similarity import IocSimilarityIndex
  from app.core.errors import error_response
  import sqlalchemy as sa

  router = APIRouter(prefix="/ml", tags=["ml"])

  FAISS_PATH = os.getenv("FAISS_INDEX_PATH", "/data/faiss/ioc.index")


  def get_daily_score_avgs(db: Session, tenant_id: str, days: int = 30) -> list[float]:
      """Aggregate daily average scores for the last `days` days."""
      rows = (
          db.execute(
              sa.text("""
                  SELECT DATE(computed_at) as day, AVG(value) as avg_val
                  FROM scores
                  WHERE tenant_id = :tid
                  GROUP BY DATE(computed_at)
                  ORDER BY day DESC
                  LIMIT :days
              """),
              {"tid": tenant_id, "days": days},
          )
          .fetchall()
      )
      return [float(r.avg_val) for r in reversed(rows)]


  @router.get("/forecast")
  def get_forecast(
      tenant_id: str = Query(...),
      horizon: int = Query(7, ge=1, le=30),
      db: Session = Depends(get_tenant_scoped_db),
      _user=Depends(get_current_user),
  ):
      avgs = get_daily_score_avgs(db, tenant_id)
      if len(avgs) < 2:
          return {"forecast": [], "message": "Not enough score history"}
      return {"forecast": forecast_scores(avgs, horizon=horizon)}


  @router.get("/similar-iocs")
  def get_similar_iocs(
      value: str = Query(...),
      k: int = Query(10, ge=1, le=50),
      _user=Depends(get_current_user),
  ):
      if not os.path.exists(FAISS_PATH):
          return {"results": [], "message": "FAISS index not built yet"}
      idx = IocSimilarityIndex.load(FAISS_PATH)
      results = idx.search(value, k=k)
      return {"results": [{"value": v, "score": s} for v, s in results]}
  ```

- [ ] **Step 4: Add `rebuild_faiss_index` to `app/worker/tasks.py`**

  ```python
  @celery_app.task(name="sentinel.rebuild_faiss_index")
  def rebuild_faiss_index() -> None:
      """Rebuild FAISS IoC similarity index from all indicators in DB."""
      import os
      from app.ml.similarity import IocSimilarityIndex
      from app.core.db import bypass_session
      from app.db.models import Indicator
      import sqlalchemy as sa

      faiss_path = os.getenv("FAISS_INDEX_PATH", "/data/faiss/ioc.index")
      os.makedirs(os.path.dirname(faiss_path), exist_ok=True)

      with bypass_session() as db:
          values = [row.value for row in db.execute(sa.select(Indicator.value)).fetchall()]

      if not values:
          return

      idx = IocSimilarityIndex()
      idx.add(values)
      idx.save(faiss_path)
  ```

  Add to beat schedule in `celery_app.py`:
  ```python
  "rebuild-faiss-index": {
      "task": "sentinel.rebuild_faiss_index",
      "schedule": crontab(minute="*/30"),
  },
  ```

- [ ] **Step 5: Register `ml` router in `app/api/v1/router.py`**

  ```python
  from app.api.v1.routes.ml import router as ml_router
  router.include_router(ml_router)
  ```

- [ ] **Step 6: Run — expect PASS**

  ```bash
  python -m pytest tests/test_ml/ -v
  ```

- [ ] **Step 7: Commit**

  ```bash
  git add backend/app/ml/ backend/app/api/v1/routes/ml.py backend/app/worker/tasks.py backend/tests/test_ml/
  git commit -m "feat: FAISS rebuild task (every 30min) and ML forecast/similarity API routes

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
  ```

---

### Task 5: SIEM Inbound + Outbound

**Files:**
- Create: `backend/app/siem/inbound.py`
- Create: `backend/app/siem/outbound.py`
- Create: `backend/app/api/v1/routes/siem.py`
- Create: `backend/tests/test_siem/test_inbound.py`
- Create: `backend/tests/test_siem/test_outbound.py`

**Interfaces:**
- Produces: `POST /api/v1/siem/feedback` (API-key auth via `X-SIEM-KEY`); `push_siem_feedback` Celery task reads `feedback-events` stream and POSTs to `SIEM_OUTBOUND_URL`

- [ ] **Step 1: Write failing tests**

  ```python
  # tests/test_siem/test_inbound.py
  import pytest
  from fastapi.testclient import TestClient
  from unittest.mock import patch, MagicMock
  import os

  os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
  os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
  os.environ.setdefault("SIEM_INBOUND_KEY", "test-siem-key")

  from app.main import app

  client = TestClient(app)

  def test_missing_api_key_returns_401():
      r = client.post("/api/v1/siem/feedback", json={"event_type": "alert", "payload": {}})
      assert r.status_code == 401

  def test_wrong_api_key_returns_401():
      r = client.post(
          "/api/v1/siem/feedback",
          json={"event_type": "alert", "payload": {}},
          headers={"X-SIEM-KEY": "wrong-key"},
      )
      assert r.status_code == 401

  def test_valid_key_publishes_to_stream():
      with patch("app.siem.inbound.publish") as mock_pub:
          mock_pub.return_value = "123-0"
          r = client.post(
              "/api/v1/siem/feedback",
              json={"event_type": "alert", "payload": {"rule": "brute_force"}},
              headers={"X-SIEM-KEY": "test-siem-key"},
          )
      assert r.status_code == 200
      mock_pub.assert_called_once()
      call_args = mock_pub.call_args[0]
      assert call_args[1] == "feedback-events"
  ```

  ```python
  # tests/test_siem/test_outbound.py
  import pytest
  from unittest.mock import patch, MagicMock
  import os

  os.environ.setdefault("SIEM_OUTBOUND_URL", "https://siem.example.com/webhook")

  from app.siem.outbound import push_siem_feedback

  def test_push_posts_to_siem_url():
      messages = [{"event_type": "alert", "payload": {"rule": "brute_force"}}]
      with patch("app.siem.outbound.read_batch", return_value=(messages, "1000-0")):
          with patch("app.siem.outbound.save_cursor"):
              with patch("httpx.post") as mock_post:
                  mock_post.return_value = MagicMock(status_code=200, raise_for_status=lambda: None)
                  push_siem_feedback()
      mock_post.assert_called_once()
      call_kwargs = mock_post.call_args
      assert "siem.example.com" in call_kwargs[0][0]

  def test_push_skips_when_no_outbound_url(monkeypatch):
      monkeypatch.delenv("SIEM_OUTBOUND_URL", raising=False)
      with patch("app.siem.outbound.read_batch", return_value=([], "0-0")):
          push_siem_feedback()  # should not raise
  ```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement `app/siem/__init__.py`** (empty)

- [ ] **Step 4: Implement `app/siem/inbound.py`**

  ```python
  import os
  from fastapi import APIRouter, Header, HTTPException, status
  from pydantic import BaseModel
  from app.streams.streams import publish

  router = APIRouter(prefix="/siem", tags=["siem"])


  class FeedbackPayload(BaseModel):
      event_type: str
      payload: dict
      tenant_id: str | None = None


  @router.post("/feedback", status_code=200)
  async def siem_feedback(
      body: FeedbackPayload,
      x_siem_key: str | None = Header(default=None, alias="X-SIEM-KEY"),
  ) -> dict:
      expected = os.getenv("SIEM_INBOUND_KEY", "")
      if not expected or x_siem_key != expected:
          raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid SIEM key")
      msg_id = await publish(None, "feedback-events", body.model_dump())
      return {"accepted": True, "msg_id": msg_id}
  ```

- [ ] **Step 5: Implement `app/siem/outbound.py`**

  ```python
  import os
  import httpx
  import logging
  from app.streams.streams import read_batch, save_cursor, get_cursor

  logger = logging.getLogger(__name__)
  STREAM = "feedback-events"
  CURSOR_KEY = "stream:cursor:feedback-events:siem-out"


  def push_siem_feedback() -> None:
      """Read feedback-events stream and POST each message to SIEM_OUTBOUND_URL."""
      url = os.getenv("SIEM_OUTBOUND_URL", "")
      if not url:
          return

      cursor = get_cursor(CURSOR_KEY)
      messages, last_id = read_batch(STREAM, cursor, count=50)
      if not messages:
          return

      for msg in messages:
          try:
              httpx.post(url, json=msg, timeout=10).raise_for_status()
          except Exception as exc:
              logger.warning("SIEM outbound push failed: %s", exc)
              return  # stop; cursor not advanced; retry next run

      save_cursor(CURSOR_KEY, last_id)
  ```

- [ ] **Step 6: Implement `app/api/v1/routes/siem.py`** and register in router

  ```python
  # app/api/v1/routes/siem.py
  from app.siem.inbound import router
  ```

  In `app/api/v1/router.py`:
  ```python
  from app.api.v1.routes.siem import router as siem_router
  router.include_router(siem_router)
  ```

- [ ] **Step 7: Add `push_siem_feedback` Celery task to `tasks.py`**

  ```python
  @celery_app.task(name="sentinel.push_siem_feedback")
  def push_siem_feedback_task() -> None:
      from app.siem.outbound import push_siem_feedback
      push_siem_feedback()
  ```

  Add to beat schedule:
  ```python
  "push-siem-feedback": {
      "task": "sentinel.push_siem_feedback",
      "schedule": crontab(minute="*/5"),
  },
  ```

- [ ] **Step 8: Add `SIEM_INBOUND_KEY` and `SIEM_OUTBOUND_URL` to `Settings` in `config.py`**

  ```python
  siem_inbound_key: str = ""
  siem_outbound_url: str = ""
  ```

  Update `.env.example`:
  ```
  SIEM_INBOUND_KEY=
  SIEM_OUTBOUND_URL=
  ```

- [ ] **Step 9: Run — expect PASS**

  ```bash
  python -m pytest tests/test_siem/ -v
  ```

- [ ] **Step 10: Commit**

  ```bash
  git add backend/app/siem/ backend/app/api/v1/routes/siem.py backend/app/core/config.py backend/tests/test_siem/
  git commit -m "feat: SIEM inbound webhook (API-key auth) and outbound Celery task

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
  ```

---

### Task 6: Frontend Phase 3 Pages

**Files:**
- Create: `frontend/src/pages/Scanner.tsx`
- Create: `frontend/src/pages/RedTeam.tsx`
- Create: `frontend/src/pages/Connectors.tsx`
- Create: `frontend/src/api/hooks/useForecast.ts`
- Create: `frontend/src/api/hooks/useSimilarIocs.ts`
- Modify: `frontend/src/router.tsx` (add 3 new routes)

**Interfaces:**
- Produces: Scanner shows ML forecast chart + similar IoC search; Connectors shows SIEM webhook config; RedTeam is placeholder for Phase 3+

- [ ] **Step 1: Write failing tests**

  ```typescript
  // tests/pages/Scanner.test.tsx
  import { render, screen } from '@testing-library/react'
  import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
  import { vi } from 'vitest'

  vi.mock('@/auth/store', () => ({ useAuthStore: () => ({ user: { access_token: 'tok' } }) }))
  vi.mock('@/api/hooks/useForecast', () => ({
    useForecast: () => ({
      data: { forecast: [0.35, 0.36, 0.37, 0.38, 0.39, 0.40, 0.41] },
      isLoading: false,
    }),
  }))
  vi.mock('@/api/hooks/useSimilarIocs', () => ({
    useSimilarIocs: () => ({ data: { results: [] }, isLoading: false }),
  }))

  import { Scanner } from '@/pages/Scanner'

  test('renders forecast chart section', () => {
    render(<QueryClientProvider client={new QueryClient()}><Scanner tenantId="t1" /></QueryClientProvider>)
    expect(screen.getByText(/forecast/i)).toBeInTheDocument()
  })
  ```

- [ ] **Step 2: Run — expect FAIL**

- [ ] **Step 3: Implement `src/api/hooks/useForecast.ts`**

  ```typescript
  import { useQuery } from '@tanstack/react-query'
  import { apiGet } from '@/api/client'
  import { useAuthStore } from '@/auth/store'

  interface ForecastResponse { forecast: number[]; message?: string }

  export function useForecast(tenantId: string, horizon = 7) {
    const { user } = useAuthStore()
    return useQuery({
      queryKey: ['ml', 'forecast', tenantId, horizon],
      queryFn: () =>
        apiGet<ForecastResponse>(
          `/api/v1/ml/forecast?tenant_id=${tenantId}&horizon=${horizon}`,
          user?.access_token,
        ),
      enabled: !!user && !!tenantId,
    })
  }
  ```

- [ ] **Step 4: Implement `src/api/hooks/useSimilarIocs.ts`**

  ```typescript
  import { useQuery } from '@tanstack/react-query'
  import { apiGet } from '@/api/client'
  import { useAuthStore } from '@/auth/store'

  interface SimilarIocsResponse { results: { value: string; score: number }[]; message?: string }

  export function useSimilarIocs(value: string, k = 10) {
    const { user } = useAuthStore()
    return useQuery({
      queryKey: ['ml', 'similar-iocs', value, k],
      queryFn: () =>
        apiGet<SimilarIocsResponse>(`/api/v1/ml/similar-iocs?value=${encodeURIComponent(value)}&k=${k}`, user?.access_token),
      enabled: !!user && value.length > 2,
    })
  }
  ```

- [ ] **Step 5: Implement `src/pages/Scanner.tsx`**

  Two sections:
  1. **Risk Forecast** — Recharts LineChart of `forecast` array (day index on x-axis, score on y-axis, domain [0,1])
  2. **Similar IoCs** — search input (debounced 400ms); DataTable of results with value + similarity score (%)

- [ ] **Step 6: Implement `src/pages/Connectors.tsx`**

  Shows SIEM connector status:
  - Display whether `SIEM_INBOUND_KEY` is configured (from a `GET /api/v1/health/connectors` endpoint or just a static info card)
  - Webhook URL to copy: `{window.location.origin}/api/v1/siem/feedback`
  - Header name: `X-SIEM-KEY`
  - SIEM outbound status: configured / not configured (based on env)

- [ ] **Step 7: Implement `src/pages/RedTeam.tsx`** (Phase 3+ placeholder)

  ```typescript
  export function RedTeam() {
    return (
      <div className="flex h-64 items-center justify-center text-gray-400">
        Red Team features coming in a future phase.
      </div>
    )
  }
  ```

- [ ] **Step 8: Add routes to `src/router.tsx`**

  ```typescript
  { path: '/scanner', element: <Scanner tenantId={tenantId} /> },
  { path: '/red-team', element: <RedTeam /> },
  { path: '/connectors', element: <Connectors /> },
  ```

  Add 3 nav entries to `Layout.tsx` sidebar.

- [ ] **Step 9: Run — expect PASS**

  ```bash
  cd frontend && npm test
  ```

- [ ] **Step 10: Commit**

  ```bash
  git add frontend/src/pages/Scanner.tsx frontend/src/pages/RedTeam.tsx frontend/src/pages/Connectors.tsx frontend/src/api/hooks/useForecast.ts frontend/src/api/hooks/useSimilarIocs.ts frontend/src/router.tsx
  git commit -m "feat: scanner (ML forecast + IoC similarity), connectors and red-team pages

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
  ```

---

### Task 7: K3s Infrastructure (iac/)

**Files:**
- Create: `iac/README.md`
- Create: `iac/k3s-install.sh`
- Create: `iac/helmfile.yaml`
- Create: `iac/values/postgres.yaml`
- Create: `iac/values/redis.yaml`
- Create: `iac/values/keycloak.yaml`
- Create: `iac/manifests/namespace.yaml`
- Create: `iac/manifests/secrets-template.yaml`
- Create: `iac/manifests/migrate-job.yaml`
- Create: `iac/manifests/api-deployment.yaml`
- Create: `iac/manifests/worker-deployment.yaml`
- Create: `iac/manifests/beat-deployment.yaml`
- Create: `iac/manifests/frontend-deployment.yaml`
- Create: `iac/manifests/faiss-pvc.yaml`

**Interfaces:**
- Produces: `helmfile apply` deploys all services; `kubectl apply -f iac/manifests/` deploys app; migration Job runs before API starts

- [ ] **Step 1: Write `iac/k3s-install.sh`**

  ```bash
  #!/usr/bin/env bash
  set -euo pipefail
  # Single-node K3s install for Hetzner — run as root
  curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION=v1.31.0+k3s1 sh -s - \
    --disable traefik \
    --write-kubeconfig-mode 644

  echo "K3s installed. Export KUBECONFIG:"
  echo "  export KUBECONFIG=/etc/rancher/k3s/k3s.yaml"
  echo "Install helmfile and helm, then: helmfile apply -f /iac/helmfile.yaml"
  ```

- [ ] **Step 2: Write `iac/helmfile.yaml`**

  ```yaml
  repositories:
    - name: bitnami
      url: https://charts.bitnami.com/bitnami

  releases:
    - name: postgres
      namespace: sentinel
      chart: bitnami/postgresql
      version: "15.5.28"
      values:
        - values/postgres.yaml

    - name: redis
      namespace: sentinel
      chart: bitnami/redis
      version: "19.6.4"
      values:
        - values/redis.yaml

    - name: keycloak
      namespace: sentinel
      chart: bitnami/keycloak
      version: "21.4.5"
      values:
        - values/keycloak.yaml
  ```

- [ ] **Step 3: Write `iac/values/postgres.yaml`**

  ```yaml
  auth:
    postgresPassword: "REPLACE_IN_PROD"
    database: sentinel
  primary:
    initdb:
      scripts:
        create_role.sql: |
          CREATE ROLE sentinel_app LOGIN;
  ```

- [ ] **Step 4: Write `iac/values/redis.yaml`**

  ```yaml
  auth:
    enabled: false
  architecture: standalone
  ```

- [ ] **Step 5: Write `iac/values/keycloak.yaml`**

  ```yaml
  auth:
    adminUser: admin
    adminPassword: "REPLACE_IN_PROD"
  extraEnvVars:
    - name: KC_IMPORT_REALM
      value: /opt/keycloak/data/import/realm.json
  ```

- [ ] **Step 6: Write `iac/manifests/namespace.yaml`**

  ```yaml
  apiVersion: v1
  kind: Namespace
  metadata:
    name: sentinel
  ```

- [ ] **Step 7: Write `iac/manifests/secrets-template.yaml`**

  ```yaml
  # Template only — never commit real values.
  # Create with: kubectl create secret generic sentinel-env --from-env-file=.env -n sentinel
  # Fields required: DATABASE_URL, MIGRATION_DATABASE_URL, REDIS_URL,
  #   KEYCLOAK_URL, KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID,
  #   NVD_API_KEY, HIBP_KEY, SLACK_WEBHOOK_URL,
  #   SMTP_HOST, SMTP_USER, SMTP_PASS,
  #   SIEM_INBOUND_KEY, SIEM_OUTBOUND_URL
  ```

- [ ] **Step 8: Write `iac/manifests/faiss-pvc.yaml`**

  ```yaml
  apiVersion: v1
  kind: PersistentVolumeClaim
  metadata:
    name: faiss-data
    namespace: sentinel
  spec:
    accessModes: [ReadWriteMany]
    resources:
      requests:
        storage: 1Gi
  ```

- [ ] **Step 9: Write `iac/manifests/migrate-job.yaml`**

  ```yaml
  apiVersion: batch/v1
  kind: Job
  metadata:
    name: sentinel-migrate
    namespace: sentinel
  spec:
    template:
      spec:
        restartPolicy: OnFailure
        containers:
          - name: migrate
            image: ghcr.io/OWNER/sentinel-ai:VERSION
            command: ["alembic", "upgrade", "head"]
            envFrom:
              - secretRef:
                  name: sentinel-env
  ```

- [ ] **Step 10: Write `iac/manifests/api-deployment.yaml`**

  Standard Deployment (2 replicas) running `uvicorn app.main:app --host 0.0.0.0 --port 8000`; envFrom sentinel-env; volumeMount `/data/faiss` from faiss-data PVC; readinessProbe `GET /health`.

- [ ] **Step 11: Write `iac/manifests/worker-deployment.yaml`**

  1 replica, `celery -A app.worker.celery_app worker -Q sentinel -c 2`; same envFrom + FAISS volume mount.

- [ ] **Step 12: Write `iac/manifests/beat-deployment.yaml`**

  1 replica, `celery -A app.worker.celery_app beat --loglevel=info`; same envFrom. No FAISS mount needed.

- [ ] **Step 13: Write `iac/manifests/frontend-deployment.yaml`**

  1 replica nginx serving Vite dist; ConfigMap with nginx.conf for SPA fallback (`try_files $uri /index.html`). Image `ghcr.io/OWNER/sentinel-ai-frontend:VERSION`.

- [ ] **Step 14: Write `iac/README.md`**

  Deployment steps: K3s install → `helmfile apply` → `kubectl apply -f iac/manifests/` → create secrets → run migrate Job → verify `kubectl get pods -n sentinel`.

- [ ] **Step 15: Commit**

  ```bash
  git add iac/
  git commit -m "feat: K3s Hetzner infra (helmfile + manifests for all services, FAISS PVC, migrate Job)

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
  ```

---

### Task 8: CI/CD Pipeline

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `backend/Dockerfile`
- Create: `frontend/Dockerfile`

**Interfaces:**
- Produces: GitHub Actions pipeline — lint → pytest → vitest → Docker build → push to ghcr.io on tag push

- [ ] **Step 1: Write `backend/Dockerfile`**

  ```dockerfile
  FROM python:3.12-slim

  WORKDIR /app
  COPY pyproject.toml .
  RUN pip install --no-cache-dir -e ".[dev]"
  COPY . .

  CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
  ```

- [ ] **Step 2: Write `frontend/Dockerfile`**

  ```dockerfile
  FROM node:22-alpine AS build
  WORKDIR /app
  COPY package.json .
  RUN npm install
  COPY . .
  RUN npm run build

  FROM nginx:alpine
  COPY --from=build /app/dist /usr/share/nginx/html
  COPY nginx.conf /etc/nginx/conf.d/default.conf
  EXPOSE 80
  ```

- [ ] **Step 3: Write `frontend/nginx.conf`**

  ```nginx
  server {
      listen 80;
      root /usr/share/nginx/html;
      index index.html;
      location / {
          try_files $uri /index.html;
      }
  }
  ```

- [ ] **Step 4: Write `.github/workflows/ci.yml`**

  ```yaml
  name: CI

  on:
    push:
      branches: [main, feature/**]
    pull_request:
      branches: [main]

  jobs:
    backend:
      runs-on: ubuntu-latest
      services:
        postgres:
          image: postgres:16
          env:
            POSTGRES_PASSWORD: postgres
            POSTGRES_DB: sentinel_test
          ports: ["5432:5432"]
          options: >-
            --health-cmd pg_isready
            --health-interval 10s
            --health-timeout 5s
            --health-retries 5
      steps:
        - uses: actions/checkout@v4
        - uses: actions/setup-python@v5
          with:
            python-version: "3.12"
        - run: pip install -e ".[dev]"
          working-directory: backend
        - name: Lint (ruff)
          run: pip install ruff && ruff check app/
          working-directory: backend
        - name: Test
          run: python -m pytest --cov=app --cov-report=xml -q
          working-directory: backend
          env:
            DATABASE_URL: postgresql+psycopg://postgres:postgres@localhost/sentinel_test
            REDIS_URL: redis://localhost:6379/0
            KEYCLOAK_URL: http://localhost:8080
            KEYCLOAK_REALM: sentinel
            KEYCLOAK_CLIENT_ID: sentinel-ai

    frontend:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v4
        - uses: actions/setup-node@v4
          with:
            node-version: "22"
        - run: npm install
          working-directory: frontend
        - name: Test
          run: npm test
          working-directory: frontend
        - name: Build
          run: npm run build
          working-directory: frontend

    docker:
      needs: [backend, frontend]
      runs-on: ubuntu-latest
      if: startsWith(github.ref, 'refs/tags/v')
      steps:
        - uses: actions/checkout@v4
        - uses: docker/login-action@v3
          with:
            registry: ghcr.io
            username: ${{ github.actor }}
            password: ${{ secrets.GITHUB_TOKEN }}
        - name: Build and push backend
          uses: docker/build-push-action@v6
          with:
            context: backend
            push: true
            tags: ghcr.io/${{ github.repository_owner }}/sentinel-ai:${{ github.ref_name }}
        - name: Build and push frontend
          uses: docker/build-push-action@v6
          with:
            context: frontend
            push: true
            tags: ghcr.io/${{ github.repository_owner }}/sentinel-ai-frontend:${{ github.ref_name }}
  ```

- [ ] **Step 5: Verify CI file is valid YAML**

  ```bash
  python -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"
  ```
  Expected: exits 0.

- [ ] **Step 6: Commit**

  ```bash
  git add .github/ backend/Dockerfile frontend/Dockerfile frontend/nginx.conf
  git commit -m "feat: GitHub Actions CI (lint+pytest+vitest+docker build+push on tag)

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
  ```

---

## Integration Verification

After all Phase 3 tasks:

```bash
# Backend ML tests
cd backend && python -m pytest tests/test_ml/ tests/test_siem/ -v

# Full backend suite
python -m pytest -q

# Frontend
cd frontend && npm test && npm run build

# K3s (requires Hetzner node)
helmfile apply -f iac/helmfile.yaml
kubectl apply -f iac/manifests/
kubectl get pods -n sentinel  # all Running

# CI validation
# Push a tag: git tag v1.0.0 && git push origin v1.0.0
# → GitHub Actions runs backend + frontend + docker push
```
