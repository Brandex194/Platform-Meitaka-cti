# Avvio rapido di Meitaka CTI

Una pagina per accendere la piattaforma sul tuo PC Windows, entrare, controllare che funzioni e spegnerla. Per i dettagli di ogni pagina c'è `GUIDA.md`. Questo è solo per l'ambiente di sviluppo locale: password e chiavi qui sotto non vanno mai usate su un server raggiungibile da altri.

Aggiornata al 10 novembre 2026 (passo 12).

## Prima di cominciare (una volta sola)

- **Docker Desktop** installato e aperto: l'icona della balena deve essere ferma, non lampeggiante.
- **Node.js 20 o superiore** (`node --version` in PowerShell deve rispondere).
- Circa 4 GB di RAM liberi e una connessione a internet (la prima volta scarica le immagini).

## Accendere

1. Apri Docker Desktop e aspetta che sia pronto.
2. Apri PowerShell e lancia:

```powershell
cd "C:\percorso-progetto\piattaforma cti"
powershell -ExecutionPolicy Bypass -File .\avvia-sentinel.ps1
```

Lo script crea i file `.env` se mancano, avvia database, Redis, Keycloak, API e worker, applica le migrazioni, crea il tenant di prova, avvia il frontend e apre il browser su http://localhost:5173. La prima volta servono 5-10 minuti, poi meno di un minuto.

**Dopo aver ricevuto nuovi file (come il passo 12)** serve ricostruire l'immagine, altrimenti l'API usa il codice vecchio:

```powershell
cd "C:\percorso-progetto\piattaforma cti\backend"
docker compose up -d --build
```

Le migrazioni si applicano da sole (il passo 12 non ne ha di nuove).

## Entrare

Apri http://localhost:5173. Il login è quello di Keycloak, password per tutti: `sentinel-dev`.

| Utente | Per cosa |
|---|---|
| `tenant.admin` | provare tutto (asset, casi, Management, chiavi) |
| `analyst` | lavoro quotidiano: casi, findings Dark Web, ricalcolo score |
| `viewer` | solo lettura |
| `super.admin` | regole di scoring e tenant (non ha un tenant suo: molte pagine restano vuote) |

## Dati dimostrativi

La piattaforma parte vuota. Per vederla piena (8 asset, vulnerabilità, esposizioni, score, 5 casi, attori e campagne, leak e findings Dark Web) carica i dati finti:

```powershell
cd "C:\percorso-progetto\piattaforma cti"
powershell -ExecutionPolicy Bypass -File .\carica-demo.ps1
```

Prima ricostruisci l'immagine (`docker compose up -d --build` da `backend`), perché lo script demo è nel codice nuovo. I dati sono tutti inventati e marcati (host `demo-*`, CVE `CVE-2099-D*`, indirizzi di documentazione, nomi "DEMO"). Gli score e le esposizioni li calcola il motore vero, non sono scritti a mano. `-Reset` li ricarica da capo, `-Rimuovi` li toglie senza toccare i tuoi dati veri. Dopo, ricarica il browser con Ctrl+F5.

## Controllare che funzioni (2 minuti)

1. **Dashboard** si apre senza errori.
2. **Assets** → con i dati demo ne vedi 8; puoi aggiungerne altri (come `tenant.admin`) e impostare Esposizione e Impatto.
3. **Scores** → premi **Explain** su una riga: vedi perché l'asset ha quel valore. Se la tabella è vuota non hai caricato i dati demo.
4. **Dark Web** → *Add finding* (come `analyst`) e controlla che compaia in tabella.
5. **Reports** → vedi le schede, **Download CSV** e **Print / PDF**.

Per avere dati veri senza aspettare i feed automatici, da PowerShell nella cartella `backend`:

```powershell
docker compose exec worker celery -A app.worker.celery_app call sentinel.tasks.collect_kev
docker compose exec worker celery -A app.worker.celery_app call sentinel.tasks.collect_nvd
```

## Indirizzi

| Cosa | Indirizzo |
|---|---|
| Piattaforma | http://localhost:5173 |
| API (documentazione interattiva) | http://localhost:8000/docs |
| Keycloak (utente `admin`, password `admin`) | http://localhost:8080 |

## Spegnere

```powershell
cd "C:\percorso-progetto\piattaforma cti"
.\ferma-sentinel.ps1            # ferma e conserva i dati
.\ferma-sentinel.ps1 -Cancella  # ferma e CANCELLA tutti i dati (ripartenza da zero)
```

## Se qualcosa non va

| Sintomo | Cosa fare |
|---|---|
| "Docker non risponde" | Apri Docker Desktop e aspetta che la balena si fermi |
| "l'esecuzione di script è disabilitata" | Usa il comando con `-ExecutionPolicy Bypass` come sopra |
| Login con errore o pagina bianca | Keycloak impiega fino a un minuto: aspetta e ricarica |
| Porta occupata (5432, 6379, 8000, 8080, 5173) | Chiudi il programma che la usa (spesso un altro Postgres o un vecchio stack) |
| Le pagine nuove (Explain, Dark Web con tab) non compaiono | Hai ricostruito l'immagine? `docker compose up -d --build` in `backend`; poi `Ctrl+F5` nel browser |
| Errore 503 salvando una chiave in Management → Integrations | Manca `SECRETS_ENCRYPTION_KEY`: il compose ne ha una solo per sviluppo; ricrea con `docker compose up -d` |
| `migrate` è "Exited" con numero diverso da 0 | `docker compose logs migrate`, di solito basta rilanciare `docker compose up -d` |
| Vedere cosa succede | `docker compose logs -f api` oppure `docker compose logs -f worker` da `backend` |

## Chiavi di terze parti

La chiave VirusTotal si inserisce da **Management → Integrations**: una volta salvata non si può più leggere, nemmeno da te. Se l'hai incollata in chat o altrove, rigenerala dal tuo account VirusTotal.
