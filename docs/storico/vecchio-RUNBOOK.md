> **Documento storico.** Si riferisce al vecchio codice di Sentinel AI (cartella `Desktop\File piattaforma per mediaminer`), sostituito dal rebuild iniziato il 23/10/2026. Non applicabile finché il rebuild non ha un ambiente deployato. Conservato così com'era per riferimento; lo stato attuale è in `docs/STATO-PROGETTO.md`.

---

# Runbook operativo (Blocco 12)

Operazioni di routine e di incident response su un ambiente già
deployato (docker-compose locale o Azure/AWS via `infra/`). Per il primo
deploy vedi `docs/DEPLOY.md`; per il modello di auth vedi `docs/AUTH.md`.

## Log

- **docker-compose**: `docker compose logs -f api worker beat` (aggiungi
  `frontend`/`keycloak`/`postgres`/`redis` se serve). `AuditLogMiddleware`
  (`backend/app/audit/middleware.py`) scrive un log strutturato per ogni
  richiesta API con `request.state.principal` (tenant/utente) e l'esito —
  è il primo posto da guardare per "chi ha fatto cosa".
- **Kubernetes (Azure/AWS)**: `kubectl -n sentinel logs -f deploy/sentinel-api` (o `-worker`, `-beat`, `-frontend`). Per i log del Job di
  migrazione (gira una volta per deploy, come hook pre-install Helm):
  `kubectl -n sentinel logs job/sentinel-migration` (il nome esatto è in
  `infra/helm/sentinel/templates/migration-job.yaml`).

## Migrazioni database (Alembic)

Le migrazioni vivono in `backend/alembic/versions/`. In docker-compose
girano automaticamente all'avvio (container `migrate`); in produzione
girano come hook pre-install del chart Helm ad ogni `helm upgrade`.

Per crearne una nuova durante lo sviluppo:
```bash
cd backend
alembic revision --autogenerate -m "descrizione breve"
alembic upgrade head   # applica in locale prima di committare
```
Per applicare manualmente le migrazioni contro un ambiente già deployato
(es. dopo un hotfix che non richiede un intero `helm upgrade`):
```bash
kubectl -n sentinel run migrate-manual --rm -it --restart=Never \
  --image=<stessa immagine backend del deploy corrente> \
  --env-from=configmap/sentinel-api-config --env-from=secret/sentinel-api-secrets \
  -- alembic upgrade head
```
**Non fare mai downgrade in produzione senza un backup verificato** — vedi
la sezione backup più sotto.

## Scaling

- **API** (`sentinel-api`): ha un HPA basato su CPU (vedi
  `infra/helm/sentinel/values.yaml`, chiave `autoscaling.api` — 2-6
  repliche, target 70% CPU di default) — richiede
  `metrics-server` installato sul cluster (preinstallato su AKS, add-on a
  parte su EKS, vedi `docs/DEPLOY.md`). Per uno scale manuale temporaneo:
  `kubectl -n sentinel scale deploy/sentinel-api --replicas=N`.
- **Worker Celery** (`sentinel-worker`): scala in base alla profondità
  delle code Redis, non alla CPU — non ha HPA automatico di default;
  monitora la lunghezza coda (`redis-cli -n <db> llen <nome coda>`, o
  Flower se abilitato) e scala manualmente con lo stesso comando `kubectl
  scale` sopra.
- **Beat** (`sentinel-beat`, lo scheduler dei task periodici): **non va
  mai scalato oltre 1 replica** — più istanze accodano gli stessi task
  periodici più volte.
- **Postgres/Redis gestiti**: scaling verticale (cambio SKU/tier) via
  Terraform (`infra/terraform/modules/postgres-*`, `redis-*` — modifica
  la variabile SKU/tier e riapplica); non richiede downtime su Azure
  Flexible Server/AWS RDS in modalità Multi-AZ, causa un breve failover
  altrimenti (vedi il backlog di hardening in `docs/DEPLOY.md` sulle
  variabili HA/multi-AZ, spente di default nel tier "starter").

## Rotazione segreti

- **Segreti applicativi** (DB password, chiavi API dei collector, secret
  JWT/OIDC): oggi sono Kubernetes Secret creati direttamente da Terraform
  (`infra/terraform/modules/k8s-app-secrets` — scelta deliberata del
  Blocco 11, vedi `docs/DEPLOY.md`). Per ruotarli: aggiorna il valore in
  `terraform.tfvars` (o nella sorgente della password, es. rigenerando la
  master password RDS/Flexible Server) e rilancia `terraform apply` — poi
  fai un rollout dei pod che la leggono (`kubectl -n sentinel rollout
  restart deploy/sentinel-api deploy/sentinel-worker deploy/sentinel-beat`)
  perché un Secret aggiornato non si ripropaga da solo ai pod già in
  esecuzione.
- **Client secret OIDC (Keycloak)**: rigeneralo dalla Admin Console di
  Keycloak (Clients → il client interessato → Credentials → Regenerate),
  poi aggiorna lo stesso valore nel Secret Kubernetes che lo contiene e
  fai il rollout come sopra.
- **Credenziali cloud della CI** (`AZURE_CREDENTIALS`, `AWS_DEPLOY_ROLE_ARN`
  e affini in `.github/workflows/deploy.yml`): ruotale dai GitHub Secrets
  dell'Environment `production-azure`/`production-aws` — AWS usa già OIDC
  federation (nessuna chiave statica da ruotare), Azure sì.

## Incident response di base

- **Sospetto client OIDC/API key compromessa**: disabilita l'utente o il
  client in Keycloak (Admin Console → Users/Clients → Disable) — effetto
  immediato sui nuovi login/token, i JWT già emessi restano validi fino a
  scadenza (vedi `docs/AUTH.md` per la durata configurata). Per revocare
  anche le sessioni già attive: Keycloak Admin Console → Sessions →
  Revoke, oppure `kcadm.sh` in scripting.
- **Sospetto abuso/flood su un endpoint**: `AuditLogMiddleware`
  (`backend/app/audit/middleware.py`) registra tenant/route/esito solo
  per le richieste che hanno superato l'autenticazione (200 e 403
  "denied" — un 401 non ha un principal a cui attribuire la riga, per
  design, vedi il docstring del middleware) — utile per un abuso da un
  account legittimo, ma un flood anonimo/non autenticato non ci compare:
  per quello servono i log di accesso convenzionali dell'Ingress/WAF
  davanti al cluster (IP sorgente, rate). `MaxBodySizeMiddleware` (`backend/app/core/body_limit.py`,
  Blocco 12) limita già la dimensione del payload per richiesta (default
  2 MiB, `settings.max_request_body_bytes`); per un vero rate limiting
  per IP/tenant a livello di richieste/secondo, oggi non c'è un
  componente dedicato nello stack applicativo — la mitigazione più
  rapida è a livello di Ingress: aggiungi
  `nginx.ingress.kubernetes.io/limit-rps: "<N>"` sotto
  `ingress.annotations` in `values-azure.yaml`/`values-aws.yaml` e fai un
  `helm upgrade` — il template `infra/helm/sentinel/templates/ingress.yaml`
  propaga già qualunque annotazione passata lì, non serve modificarlo.
- **Servizio non pronto (`/api/v1/ready` risponde 503)**: il body indica
  quale dipendenza è `"unreachable"` (`database` o `redis`, vedi
  `backend/app/api/routes/health.py`, riscritto nel Blocco 12 per non
  esporre più le connection string) — controlla prima quel servizio
  specifico (`kubectl -n sentinel get pods` per Redis se è in-cluster,
  lo stato del server gestito sul portale Azure/AWS per Postgres/Redis
  gestiti) invece di riavviare alla cieca i pod API.
- **Rollback di un deploy applicativo**: `helm -n sentinel rollback
  sentinel <REVISION>` (`helm -n sentinel history sentinel` per
  l'elenco) — attenzione: se la revisione da cui torni indietro ha
  applicato una migrazione Alembic non retrocompatibile, il rollback
  dell'app senza un downgrade coordinato dello schema può rompere la
  compatibilità; verifica prima cosa ha cambiato la migrazione più
  recente.

## Backup

- **Postgres gestito**: sia Azure Flexible Server che AWS RDS fanno
  backup automatici point-in-time by default (finestra di retention
  configurabile via Terraform, vedi `infra/terraform/modules/postgres-*`)
  — verifica la retention configurata per il tuo ambiente prima di
  affidarti a un ripristino, e testa periodicamente un ripristino su un
  ambiente non di produzione: un backup mai ripristinato per prova non è
  un backup verificato.
- **Redis**: usato come broker Celery e cache, non come store dati
  primario di alcun tenant — la sua perdita comporta il rischio di
  perdere task in coda non ancora eseguiti, non dati persistenti del
  cliente; non è configurato con persistenza AOF/RDB dedicata nei moduli
  Terraform di questo blocco.
