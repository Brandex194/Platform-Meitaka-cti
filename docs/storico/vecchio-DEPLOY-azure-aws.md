> **Documento storico.** Si riferisce al vecchio codice di Sentinel AI (cartella `Desktop\File piattaforma per mediaminer`), sostituito dal rebuild iniziato il 23/10/2026. L'infrastruttura descritta (Terraform AKS/EKS, Helm) non esiste nel rebuild, che prevede K3s su Hetzner in fase 3. Utile come checklist di hardening. Conservato così com'era per riferimento; lo stato attuale è in `docs/STATO-PROGETTO.md`.

---

# Deploy su Azure e AWS (Blocco 11) e hardening applicativo (Blocco 12)

Questo documento spiega come portare Sentinel AI da "gira in docker-compose
sul mio laptop" a un deployment reale su Azure (AKS) o AWS (EKS), usando
Terraform (`infra/terraform/`) per l'infrastruttura e Helm
(`infra/helm/sentinel/`) per l'applicazione. Copre anche, con la stessa
onestà usata in `docs/AUTH.md` per Keycloak, cosa di questo lavoro è stato
davvero verificato in questa sandbox e cosa no.

## Architettura in breve

- **Un solo registro immagini**: `ghcr.io` (GitHub Container Registry),
  condiviso da entrambi i cloud. `docker/build-push-action` in
  `.github/workflows/deploy.yml` builda le immagini una volta sola; sia
  AKS che EKS le tirano da lì.
- **Un solo chart Helm** (`infra/helm/sentinel`), parametrizzato con
  `values-azure.yaml` / `values-aws.yaml` per le (poche, deliberate)
  differenze specifiche di cloud.
- **Segreti applicativi come Kubernetes Secret creati da Terraform**
  (`infra/terraform/modules/k8s-app-secrets`), non da un secret manager
  esterno + operator — scelta deliberata per Block 11 (più semplice, zero
  componenti extra da installare nel cluster), documentata come possibile
  upgrade più sotto.
- **Postgres e Redis sono servizi gestiti** (Azure Flexible
  Server/Cache for Redis, RDS/ElastiCache), mai pod nel cluster — a
  differenza di `docker-compose.yml`, dove girano come container per
  comodità di sviluppo locale.
- **Keycloak gira invece nel cluster** (Deployment Helm), con un suo
  database dedicato sullo stesso server Postgres gestito (vedi
  `infra/terraform/modules/db-bootstrap`) — non esiste un equivalente
  gestito "Keycloak-as-a-service" su nessuno dei due cloud, quindi
  continuare a farlo girare containerizzato, come in locale, è la scelta
  più diretta.

## Prerequisiti (da installare una tantum sul cluster, fuori da Terraform)

Questo Terraform crea il cluster (AKS/EKS) ma non i suoi componenti
add-on; vanno installati separatamente prima del primo `helm install`:

1. **ingress-nginx** (`helm install ingress-nginx ingress-nginx/ingress-nginx`)
   — il chart Sentinel presume che esista già una IngressClass `nginx`.
2. **cert-manager**, con un `ClusterIssuer` chiamato
   `letsencrypt-prod` (o il nome che passi in
   `ingress.clusterIssuer` nei values) — per i certificati TLS automatici
   dei tre hostname pubblici.
3. **metrics-server** — richiesto perché l'HPA di `sentinel-api`
   funzioni. Su AKS è preinstallato di default; su EKS va aggiunto
   esplicitamente (è un add-on EKS separato, non incluso di default).
4. **AWS Load Balancer Controller** (solo EKS) — perché il Service di
   ingress-nginx ottenga un Application/Network Load Balancer pubblico
   reale. Su AKS non serve un equivalente: il Service di tipo
   LoadBalancer di ingress-nginx crea già un Azure Load Balancer
   nativamente.
5. **Record DNS** per i tre hostname (`app.`, `api.`, `auth.` del tuo
   dominio, o quelli che scegli) che puntino all'IP pubblico del Load
   Balancer di ingress-nginx.

## Primo deploy, passo per passo

1. **Bootstrap dello state backend** (una tantum per cloud):
   ```
   cd infra/terraform/bootstrap-azure   # o bootstrap-aws
   terraform init && terraform apply
   terraform output backend_config_snippet
   ```
   Incolla i valori stampati in `environments/azure/main.tf` (o
   `environments/aws/main.tf`), sostituendo i placeholder `REPLACE_ME_*`
   nel blocco `backend`.

2. **Copia `terraform.tfvars.example` in `terraform.tfvars`** nella
   cartella dell'environment scelto e compila i valori (hostname
   pubblici, credenziali GHCR, eventuali chiavi API dei collector). Non
   committare mai questo file (è già in `.gitignore`).

3. **Primo `terraform apply`, in due passate** (vedi il commento in cima a
   ciascun `environments/*/main.tf` per il perché): i provider
   `kubernetes` e `postgresql` in questo stesso file leggono output di
   risorse che il file stesso crea, quindi al primissimo apply Terraform
   non può ancora conoscere quella configurazione.
   ```
   terraform init
   terraform apply -target=module.aks -target=module.postgres        # Azure
   terraform apply -target=module.eks -target=module.postgres        # AWS
   terraform apply                                                    # tutto il resto
   ```
   **Nota operativa importante**: sia il Postgres gestito che (su AWS)
   Redis sono raggiungibili SOLO dalla rete privata (VNet/VPC) — vedi
   `infra/terraform/modules/db-bootstrap`'s header comment. Questo
   significa che il comando sopra deve girare da qualcosa con visibilità
   di rete su quella VNet/VPC (un runner self-hosted dentro al cluster,
   una VPN/peering, o temporaneamente un bastion) — da un runner
   GitHub-hosted "normale" o dal tuo laptop, questa parte del comando va
   in timeout. `terraform apply` per `module.aks`/`module.eks` invece
   funziona da ovunque (l'endpoint pubblico dell'API server è aperto di
   default, vedi la sezione hardening più sotto).

4. **Ottieni le credenziali kubectl**:
   ```
   terraform output get_credentials_command   # stampa il comando az/aws esatto
   ```

5. **Installa i prerequisiti** (sezione sopra) sul cluster appena creato.

6. **Primo deploy dell'app**: usa il workflow `deploy.yml` (GitHub Actions
   → Deploy → Run workflow, scegliendo `azure` o `aws`), oppure a mano:
   ```
   helm upgrade --install sentinel infra/helm/sentinel \
     --namespace sentinel --create-namespace \
     --values infra/helm/sentinel/values-azure.yaml \
     --set image.repository=<tuo-org>/sentinel-ai \
     --set image.backendTag=<tag> --set image.frontendTag=<tag> \
     --wait --timeout 10m
   ```
   Il primo `helm upgrade` esegue anche il Job di migrazione
   (`templates/migration-job.yaml`) come hook pre-install, che applica
   tutte le migrazioni Alembic e il seed contro il Postgres gestito prima
   che i pod `api`/`worker`/`beat` partano.

Per `deploy.yml` servono questi GitHub Secrets configurati sul repo
(sotto l'Environment `production-azure` / `production-aws`, non a livello
di repo, per poter richiedere reviewer di approvazione sul deploy reale):
`AZURE_CREDENTIALS`, `AZURE_RESOURCE_GROUP`, `AZURE_AKS_CLUSTER_NAME` (Azure);
`AWS_DEPLOY_ROLE_ARN`, `AWS_REGION`, `AWS_EKS_CLUSTER_NAME` (AWS, con OIDC
federation invece di chiavi statiche — vedi `aws-actions/configure-aws-credentials`).

## Cosa NON è stato verificato end-to-end in questo ambiente

Nello stesso spirito di `docs/AUTH.md` (dove il vero container Keycloak
non poteva partire in sandbox e si è verificato il flusso OIDC/PKCE con un
provider-mock scritto da zero): questa sandbox non ha accesso di rete a
`releases.hashicorp.com`, `get.helm.sh`, `kind.sigs.k8s.io`, né a
`proxy.golang.org` (che avrebbe permesso di compilare `terraform`/`helm`/
`kind` da sorgente con `go install`) — solo un allowlist ristretto di
registri pacchetti (npm, PyPI, apt di Ubuntu, crates.io). Questo significa
che **né `terraform` né `helm`/`kubectl`/`kind` come binari reali erano
disponibili** per validare questo codice. Il demone Docker invece
funzionava (novità rispetto ai blocchi precedenti), ma **il pull di
qualunque immagine base, da qualunque registro (docker.io, ghcr.io,
quay.io), veniva bloccato allo stesso modo** — quindi nemmeno una build
reale delle immagini Docker era possibile.

Quello che è stato effettivamente verificato, per davvero, in questa
sandbox:

- **Sintassi HCL** di tutti i 38 file `.tf`: parsing reale con la libreria
  Python `python-hcl2`.
- **Correttezza strutturale** di ogni modulo/environment Terraform: con
  `terraform-config-inspect`, il tool Go ufficiale di HashiCorp per
  l'ispezione "shallow" di una configurazione (disponibile via apt di
  Ubuntu) — non sostituisce `terraform validate` (non conosce gli schemi
  dei provider azurerm/aws/kubernetes/postgresql), ma individua errori di
  sintassi/struttura reali.
- **Scansione di sicurezza reale** con `checkov` (installato via pip) su
  tutto `infra/terraform/` e su entrambi i Dockerfile — non simulata: ha
  trovato bug veri (es. subnet AWS pubbliche con IP pubblico automatico,
  security group con egress `0.0.0.0/0` non necessario, l'immagine
  backend che girava come root nonostante i Pod la richiedano
  `runAsNonRoot`), tutti corretti in questo stesso blocco. La lista
  completa dei check accettati/rimandati (con motivazione) è nella
  sezione successiva.
- **Il nuovo Dockerfile di produzione del frontend + il suo
  `docker-entrypoint.sh`**: non potendo buildare l'immagine reale, il
  meccanismo di iniezione della config a runtime (env-config.js reso con
  `envsubst` — lo stesso identico comando, non una simulazione) e
  `frontend/nginx.conf` sono stati verificati con `envsubst` e un vero
  binario `nginx` (via apt) girato realmente: richieste HTTP reali a
  `/healthz`, `/env-config.js` (cache-control corretto), un asset con
  hash (cache immutabile 1 anno), e il fallback SPA su una route inventata
  (`/tenants/qualcosa`) che correttamente restituisce `index.html`. Questo
  ha trovato e corretto un bug reale (due header `Content-Type`
  contrastanti su `/healthz`).
- **Il chart Helm**: nessun `helm lint`/`helm template` reale è stato
  possibile. Al suo posto, uno script Python scritto apposta per QUESTI
  14 template (non un motore Go-template generico) ha sostituito
  manualmente `.Values.*`, i due `include` con nome, `toYaml`/`toJson`/
  `nindent`/`dict`, `{{- if }}`/`{{- with }}`, e `.Files.Get` +
  `sha256sum`, poi validato l'output con `yaml.safe_load` — ha confermato
  che tutti e 14 i file producono YAML strutturalmente valido con i
  `values.yaml` di default, ma NON è un sostituto delle garanzie
  semantiche di un vero motore Helm o di un vero kube-apiserver.

Il file `.github/workflows/infra-ci.yml` è quindi, letteralmente, il primo
posto dove questo codice incontrerà `terraform validate`, `helm lint` e
un vero `kubectl apply --dry-run=server` contro un vero (seppur
effimero, via kind) control plane Kubernetes — i runner di GitHub Actions
hanno accesso di rete pieno, a differenza di questa sandbox. Prima di
qualunque deploy reale, esegui tu stesso, con gli strumenti reali:
```
terraform -chdir=infra/terraform/environments/azure validate
helm lint infra/helm/sentinel --values infra/helm/sentinel/values-azure.yaml
helm template infra/helm/sentinel --values infra/helm/sentinel/values-azure.yaml | kubectl apply --dry-run=server -f -
```

## Backlog di hardening (checkov: check accettati/rimandati, con motivo)

Ognuno di questi ha un commento nel file `.tf` corrispondente che spiega
il trade-off; questa è solo la lista riassuntiva, tenuta sincronizzata con
lo `skip_check` di `.github/workflows/infra-ci.yml` (26 check accettati
all'ultima esecuzione di checkov su `infra/terraform`).

- **Cluster API endpoint pubblico** (`CKV_AWS_38`, `CKV_AWS_39`,
  `CKV_AZURE_115`; AKS `authorized_ip_ranges` e EKS `public_access_cidrs`,
  entrambi di default `0.0.0.0/0`): un cluster davvero privato
  richiederebbe un runner CI o bastion dentro alla VNet/VPC. Restringi
  questi due valori al tuo range IP ufficio/VPN e ai range dei runner CI
  non appena li conosci; il passo successivo (privato al 100%) è un
  lavoro a parte.
- **HA/multi-AZ/geo-redundanza spente di default** (`CKV_AWS_157`,
  `CKV_AZURE_136`, `CKV_AZURE_170`, `CKV2_AWS_50`; Postgres, Redis, AKS
  SKU tier "Free"): ogni variabile è documentata nel modulo corrispondente
  e pensata per essere accesa quando serve un vero SLA di produzione — di
  default scelto il costo più basso per un deployment "starter".
- **ElastiCache Redis senza CMK dedicata** (`CKV_AWS_191`): a differenza
  di Postgres (che ha una CMK dedicata, vedi `modules/postgres-aws`), la
  cache resta sulla chiave AWS-managed di default — non è lo store
  primario dei dati del tenant, e l'unico segreto che ci transita (la
  `auth_token`) è comunque già in un Kubernetes Secret separato.
- **Keycloak: singola replica** (nessun check specifico, gap architetturale
  noto): il clustering Keycloak richiede un meccanismo di discovery
  (JGroups DNS_PING via headless Service) non ancora implementato in
  questo chart — un vero gap di disponibilità, non solo un costo.
- **Nessun Key Vault/Secrets Manager + External Secrets Operator**
  (`CKV_AZURE_172`): scelta esplicita di questo blocco (vedi la domanda
  posta e la risposta scelta) a favore di Kubernetes Secret creati
  direttamente da Terraform — più semplice, rotazione via
  `terraform apply` invece che automatica.
- **AKS: disco/host non cifrati con CMK dedicata** (`CKV_AZURE_117`
  disk encryption set, `CKV_AZURE_226` ephemeral OS disk, `CKV_AZURE_227`
  host encryption): tutti e tre richiedono una precondizione fuori dal
  controllo di questo Terraform -- rispettivamente un Key Vault + Disk
  Encryption Set dedicato, una VM SKU con storage locale abbastanza
  grande da ospitare il disco OS, e la feature di sottoscrizione Azure
  "EncryptionAtHost" registrata in anticipo (`az feature register
  --namespace Microsoft.Compute --name EncryptionAtHost`) -- impostare
  `enable_host_encryption = true` senza quella registrazione fa fallire
  `terraform apply` a metà, quindi non è un flag "gratis" da accendere
  alla cieca.
- **AKS: account admin locale abilitato** (`CKV_AZURE_141`): Terraform
  stesso usa le credenziali admin locali del cluster (via il provider
  `kubernetes`/`kubectl`) per creare i Secret applicativi in
  `modules/k8s-app-secrets` -- disabilitarlo richiederebbe prima
  un'integrazione Azure AD RBAC completa per l'identity che esegue
  `terraform apply`, un lavoro a parte rispetto a questo blocco.
- **RDS senza autenticazione IAM** (`CKV_AWS_161`): l'app si autentica con
  utente/password Postgres nativo (stesso schema di `docker-compose`, per
  parità dev/prod -- vedi `modules/db-bootstrap`); passare a IAM auth
  richiederebbe generare e rinnovare token IAM lato applicazione invece
  di leggere una DSN statica da un Secret, un cambiamento nel codice
  dell'app e non solo nell'infrastruttura.
- **Storage account/bucket dello state Terraform: policy KMS di default,
  niente CMK/private endpoint/logging/replication/access-logging/event
  notification** (`CKV2_AWS_62`, `CKV2_AWS_64`, `CKV2_AZURE_1`,
  `CKV2_AZURE_21`, `CKV2_AZURE_33`, `CKV2_AZURE_57`, `CKV_AWS_18`,
  `CKV_AWS_144`, `CKV_AZURE_33`, `CKV_AZURE_59`, `CKV_AZURE_206`): stesso
  ragionamento bootstrap-chicken-egg dei cluster -- quei bucket/storage
  account devono restare raggiungibili da dove gira `terraform apply`
  (spesso un runner CI senza accesso di rete privato), e per un bucket
  che contiene solo lo stato Terraform di questo progetto (non dati di
  tenant) l'irrigidimento aggiuntivo non vale il costo operativo in
  questa fase "starter". Le CMK già presenti (`aws_kms_key.tfstate`,
  ora condivisa anche dalla tabella di lock DynamoDB) restano comunque il
  livello di cifratura reale.
- **Storage account del bootstrap Azure: Shared Key abilitata**
  (`CKV2_AZURE_40`, in tensione diretta con `CKV2_AZURE_41` già risolto
  sopra): `CKV2_AZURE_41` vuole una policy di scadenza SAS esplicita
  *quando* le chiavi condivise sono abilitate; `CKV2_AZURE_40` vorrebbe
  invece disabilitarle del tutto a favore di Azure AD auth. Terraform
  stesso (`terraform init`/`apply` con backend `azurerm`) usa oggi
  l'accesso via chiave dell'account storage per leggere/scrivere lo
  state -- passare ad Azure AD auth richiede `use_azuread_auth = true`
  nel blocco backend più un ruolo RBAC (`Storage Blob Data Contributor`)
  assegnato all'identity che esegue `terraform apply`, un cambiamento
  factibile ma volutamente rimandato a quando questo progetto avrà una
  identity CI dedicata invece di credenziali personali.

## Hardening applicativo (Blocco 12)

A differenza del Blocco 11 (infrastruttura), qui il lavoro è a livello di
codice applicativo (`backend/app`, `frontend/nginx.conf.template`), ed è
stato verificato con la stessa disciplina degli altri blocchi: Postgres 16
e Redis 7 reali (via apt, non mock) per le fix di `/ready`, un binario
`nginx` reale per gli header del frontend, e richieste HTTP reali
(incluso un client raw-socket in Python per simulare `Transfer-Encoding:
chunked` senza `Content-Length`) contro un vero processo `uvicorn` per le
fix di FastAPI. Questa verifica "vera" ha trovato due bug non banali che
una semplice code review avrebbe probabilmente perso — vedi sotto.

### Bug di sicurezza reale trovato e corretto: `/ready` esponeva le credenziali

Prima di questo blocco, `GET /api/v1/ready` (endpoint non autenticato,
pensato per i probe di readiness di Kubernetes) restituiva `DATABASE_URL`
e `REDIS_URL` per intero nel corpo JSON — entrambe le DSN includono
utente e password in chiaro — e in più non testava mai una connessione
reale, quindi non era nemmeno un readiness check funzionante. Corretto in
`backend/app/api/routes/health.py`: ora apre davvero una connessione
Postgres (`engine.connect()`) e un ping Redis reali, riporta solo
`"ok"`/`"unreachable"` per ciascun servizio (mai la DSN), e risponde `503`
se uno dei due non è raggiungibile invece di un `200` sempre ottimista.
Verificato con Postgres/Redis reali in tre stati (entrambi su, solo Redis
giù, entrambi giù): status code e body corretti in tutti e tre i casi, mai
un byte della connection string nella risposta. Copertura in
`backend/tests/test_health_routes.py`.

### Security header su backend e frontend

- **Backend** (`backend/app/core/security_headers.py`,
  `SecurityHeadersMiddleware`): aggiunge `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`,
  `Strict-Transport-Security: max-age=31536000; includeSubDomains` su ogni
  risposta, più una `Content-Security-Policy: default-src 'none';
  frame-ancestors 'none'` (l'API non serve mai HTML/JS proprio, quindi può
  essere massimamente restrittiva) — eccetto su `/docs`, `/redoc` e
  `/openapi.json` (`settings.docs_paths_exempt_from_csp`), dove Swagger UI
  carica i suoi asset da un CDN pubblico e una CSP così stretta li
  bloccherebbe. Verificato con `TestClient` reale (`backend/tests/
  test_security_headers.py`).
- **Frontend** (`frontend/nginx.conf.template` +
  `frontend/security-headers.conf.template`): stessi header, con una CSP
  più permissiva (deve servire l'app React reale — `'self'`, `'unsafe-inline'`
  su `style-src` perché React scrive `element.style.*` per ogni prop
  `style={{...}}`, `connect-src` verso l'origin API/OIDC dedotti a runtime
  dalle stesse variabili di `env-config.js`, vedi
  `docker-entrypoint.sh`). **Bug reale trovato durante la verifica**: la
  prima bozza metteva gli header a livello di `server {}`, ma nginx non fa
  ereditare `add_header` a un `location {}` che ne definisce uno proprio
  — e ognuna delle 4 location del sito (`/`, `/assets/`, `/env-config.js`,
  `/healthz`) definisce già il proprio `add_header Cache-Control`, quindi
  gli header di sicurezza sparivano silenziosamente ovunque tranne su
  `/healthz`. Corretto centralizzando tutti gli header in
  `security-headers.conf.template` e usando `include` dentro ciascuna
  location. Verificato avviando un vero `nginx` (apt) e facendo `curl` su
  tutti e 4 gli endpoint.

### Limite dimensione richiesta (`MaxBodySizeMiddleware`)

`backend/app/core/body_limit.py`, applicato prima di `CORSMiddleware`
nello stack (vedi il commento in `backend/app/main.py`). Rifiuta con
`413` sia il caso semplice (header `Content-Length` già oltre il limite,
rifiutato prima ancora di chiamare l'app) sia il caso di un body
streamato senza `Content-Length` che supera il limite durante la lettura.
**Bug reale trovato durante la verifica**: la prima implementazione
sollevava un'eccezione custom dal `receive()` avvolto e la intercettava
attorno alla chiamata `self.app(...)` — ma il parsing del body di FastAPI
(`await request.json()`) intercetta *qualunque* eccezione per conto suo e
la converte in un generico `400 "There was an error parsing the body"`
prima che possa mai raggiungere quel blocco `except` esterno. Il bug è
stato riprodotto per davvero con un client raw-socket Python che manda
`Transfer-Encoding: chunked` (niente `Content-Length`, quindi passa dal
percorso streaming) contro un vero `uvicorn`: il client riceveva `400`
invece del `413` atteso. Corretto mandando direttamente il `413` dal
`receive()` avvolto tramite `send()`, poi segnalando
`{"type": "http.disconnect"}` (che fa sollevare `ClientDisconnect` dentro
l'app) e avvolgendo anche `send` per scartare silenziosamente qualunque
cosa l'app provi comunque a mandare dopo. Ri-verificato con lo stesso test
raw-socket: `413` pulito, un solo log server pulito, nessun traceback.
Va posizionato *dentro* `CORSMiddleware` (non fuori) altrimenti la sua
risposta diretta non passa mai dal wrapping di `CORSMiddleware` e un
client browser (la SPA) vede un fallimento CORS opaco invece del vero
413 — verificato con una vera richiesta `curl` con header `Origin`, che
conferma `Access-Control-Allow-Origin` presente sulla risposta 413.
Copertura in `backend/tests/test_body_limit.py`. Limite di default:
2 MiB (`settings.max_request_body_bytes`), configurabile via env var.

### CORS ristretto

`allow_methods`/`allow_headers` in `backend/app/main.py` sono passati da
`["*"]` a liste esplicite (`GET, POST, PUT, PATCH, DELETE, OPTIONS` e
`Content-Type, Authorization`), allineate a cosa usa davvero
`frontend/src/api/apiClient.ts` e alle route esistenti — non era una
falla concreta (un wildcard con `allow_credentials=True` non espone comunque
origin arbitrarie), ma è inutile superficie extra concessa di default.
Verificato con una vera richiesta preflight `OPTIONS` + `curl`: gli header
`Access-Control-Allow-*` riflettono esattamente l'elenco ristretto.

### Voci riviste e accettate così come sono (non bug, scelte esplicite)

Nello stesso spirito di onestà delle altre sezioni di questo documento,
queste due voci sono state esaminate in questo blocco e **lasciate
invariate deliberatamente**, non dimenticate:

- **`/docs`, `/redoc`, `/openapi.json` restano pubblici e non
  autenticati**: è la Swagger UI/ReDoc auto-generata di FastAPI. Per un
  servizio B2B con partner tecnici che devono integrarsi con l'API, avere
  la documentazione interattiva raggiungibile senza login è una scelta di
  prodotto legittima (non espone dati di alcun tenant, solo lo schema
  dell'API) — non un bug. Se in produzione si preferisce nasconderla,
  l'opzione più semplice è bloccare quei tre path a livello di Ingress/
  reverse proxy (o passare `docs_url=None, redoc_url=None,
  openapi_url=None` a `FastAPI(...)`), non richiede modifiche al codice
  applicativo.
- **Nessun exception handler globale custom**: verificato per davvero
  (non per assunzione) che Starlette, con `debug=False` — il default di
  questa app, che non lo imposta mai a `True` da nessuna parte — risponde
  a un'eccezione non gestita con un generico `500 Internal Server Error`
  in testo semplice, senza traceback né dettagli, anche quando
  l'eccezione stessa contiene una stringa sensibile: test riprodotto con
  una vera app Starlette che solleva un errore con dentro un segreto
  finto, risposta confermata priva di quella stringa. Aggiungere un
  handler custom oggi non chiuderebbe una falla reale, quindi non è stato
  fatto — un candidato naturale per un lavoro futuro sarebbe invece
  arricchire i log server-side (che restano completi, traceback incluso)
  con un request-id da correlare alla risposta vista dal client.

## Nota di sincronizzazione: realm-export.json esiste in due copie

`docker/keycloak/realm-export.json` (usato da `docker-compose.yml` per lo
sviluppo locale, Blocco 9) e
`infra/helm/sentinel/files/realm-export.json` (usato dal chart Helm in
produzione) sono la stessa configurazione realm copiata due volte — Helm
`.Files.Get` legge solo file dentro alla cartella del chart, quindi non
possono essere un link simbolico allo stesso file senza complicare il
build. **Se aggiorni la configurazione del realm Keycloak (ruoli, client,
mapper), aggiorna entrambe le copie.**

Nota anche che, in produzione, Keycloak avviato con `start --import-realm`
importa il realm SOLO al primo avvio se non esiste già — a differenza
dello sviluppo locale (`start-dev`), aggiornare la configurazione di un
realm già esistente richiede un import manuale (`kc.sh import`) o
l'eliminazione del realm dalla UI admin, non un semplice restart del pod.
