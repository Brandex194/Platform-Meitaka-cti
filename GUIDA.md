# Guida: come azionare Meitaka CTI

Questa guida serve a far partire la piattaforma sul tuo PC Windows, entrare, usarla e spegnerla. Vale per l'ambiente di sviluppo locale: utenti e password qui sotto non vanno mai usati su un server raggiungibile da altri.

Aggiornata al 9 novembre 2026.

## 1. Cosa serve (una volta sola)

| Programma | Dove si prende | Come controllare che c'è |
|---|---|---|
| Docker Desktop | https://www.docker.com/products/docker-desktop | l'icona della balena nella barra delle applicazioni è ferma (non lampeggia) |
| Node.js 20 o superiore | https://nodejs.org (versione LTS) | in PowerShell `node --version` risponde |

Servono circa 4 GB di RAM liberi.

## 2. Accendere la piattaforma

### Il modo semplice: lo script

1. Apri Docker Desktop e aspetta che sia pronto.
2. Apri PowerShell nella cartella del progetto:
   ```powershell
   cd "C:\Users\lucab\OneDrive\Desktop\claude progetti\piattaforma cti"
   ```
3. Lancia:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\avvia-sentinel.ps1
   ```

Lo script controlla Docker e Node, crea i file `.env` se mancano, avvia database, Redis, Keycloak, API e worker, aspetta che siano pronti, crea il tenant di prova, installa le dipendenze del frontend la prima volta, apre il frontend in una seconda finestra di PowerShell e poi il browser su http://localhost:5173.

La prima volta ci vogliono 5-10 minuti (scarica le immagini Docker e le librerie). Le volte successive meno di un minuto.

### A mano, se lo script non va

```powershell
cd "C:\Users\lucab\OneDrive\Desktop\claude progetti\piattaforma cti\backend"
copy .env.example .env                 # solo la prima volta
docker compose up -d --build
docker compose ps                      # tutto "Up", tranne "migrate" che deve essere "Exited (0)"
docker compose exec postgres psql -U postgres -d sentinel -c "INSERT INTO tenants (id, name, slug) VALUES ('00000000-0000-4000-8000-000000000001', 'Tenant demo', 'demo') ON CONFLICT DO NOTHING;"

cd ..\frontend
copy .env.example .env                 # solo la prima volta
npm install                            # solo la prima volta
npm run dev
```

Poi apri http://localhost:5173.

## 3. Entrare

La pagina di login è quella di Keycloak. Password per tutti gli utenti di prova: `sentinel-dev`.

| Utente | Ruolo | Cosa può fare |
|---|---|---|
| `tenant.admin` | Tenant Admin | tutto sul proprio tenant: asset e software (anche esposizione e impatto), casi, risoluzione delle esposizioni, ricalcolo dello score |
| `analyst` | Analyst | gestire i casi, risolvere esposizioni, ricalcolare lo score; non crea asset |
| `viewer` | Viewer | solo lettura |
| `api.user` | API User | crea asset via API, pensato per integrazioni |
| `super.admin` | Super Admin | accesso a tutti i tenant, gestione delle regole di scoring (pesi, soglie, parametri) |

Per provare la piattaforma usa `tenant.admin`. `super.admin` non ha un tenant suo, quindi le pagine del frontend per lui restano vuote.

## 4. Gli indirizzi

| Cosa | Indirizzo | Note |
|---|---|---|
| Piattaforma (frontend) | http://localhost:5173 | qui si lavora |
| Documentazione interattiva dell'API | http://localhost:8000/docs | si possono provare le chiamate |
| Console di Keycloak | http://localhost:8080 | utente `admin`, password `admin`; per gestire utenti e ruoli |

## 5. Cosa c'è dentro oggi

La piattaforma parte vuota. Per vederla con dati di esempio inventati usa `carica-demo.ps1` (vedi `AVVIO-RAPIDO.md`); i dati veri arrivano in due modi.

**Dai feed pubblici, in automatico.** Il worker scarica da solo:

| Feed | Quando |
|---|---|
| CVE modificate su NVD (la prima volta: ultimi 90 giorni) | ogni ora, al minuto 00 |
| Catalogo CISA KEV (vulnerabilità sfruttate) | ogni giorno alle 05:00 UTC |
| Tecniche MITRE ATT&CK | ogni giorno alle 04:30 UTC |

Per non aspettare, lanciali subito da PowerShell nella cartella `backend`:

```powershell
docker compose exec worker celery -A app.worker.celery_app call sentinel.tasks.collect_kev
docker compose exec worker celery -A app.worker.celery_app call sentinel.tasks.collect_nvd
```

Senza una chiave NVD (`NVD_API_KEY` in `backend\.env`, gratuita su https://nvd.nist.gov/developers/request-an-api-key) il primo scaricamento NVD è lento per i limiti del servizio.

**Dagli asset del cliente.** Oggi asset e software si inseriscono solo dalla documentazione interattiva dell'API (http://localhost:8000/docs), non dal frontend:

1. `POST /api/v1/tenants/{tenant_id}/assets` con `{"hostname": "web01", "ip": "10.0.0.5"}`; la risposta contiene l'`id` dell'asset.
2. `POST /api/v1/tenants/{tenant_id}/assets/{asset_id}/software` con nome, versione e CPE, per esempio `{"name": "Apache httpd", "version": "2.4.49", "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}`.

Le esposizioni nascono quando il CPE di un software corrisponde a una CVE scaricata. Il confronto gira da solo ogni 5 minuti; per non aspettare:

```powershell
docker compose exec worker celery -A app.worker.celery_app call sentinel.tasks.normalize
docker compose exec worker celery -A app.worker.celery_app call sentinel.tasks.correlate
```

Il CPE va scritto come lo usa NVD (si trova cercando il prodotto su https://nvd.nist.gov/products/cpe/search). Se hai scaricato CVE prima del 9 novembre 2026, quelle non hanno ancora i dati dei prodotti: per riscaricare gli ultimi 90 giorni lancia `docker compose exec redis redis-cli DEL nvd:last_run` e poi `collect_nvd`.

Casi e identità si creano dal frontend (pagina Cases) o dall'API.

**Attori, campagne e observables si inseriscono dal frontend** (pagine Threat Actors, Campaigns, Observables, pulsanti "New actor", "New campaign", "Add observable"; li vedono tutti, li scrivono `analyst`, `tenant.admin` e `super.admin`). Ognuno è del tuo tenant: modifica e cancellazione valgono solo per le voci "yours". Quelle "shared" (catalogo comune) o "feed" (scaricate dai collector) si leggono ma non si toccano. Una campagna può puntare a un attore condiviso o tuo. Un observable ha tipo (ip, domain, url, hash, email), valore e confidenza facoltativa da 0 a 100; lo stesso valore due volte nello stesso tenant viene rifiutato.

**Classificare gli asset (importante per il rischio).** Nella pagina Assets ogni asset ha due menu: *Esposizione* (internet, DMZ, interno) e *Impatto* (dati sensibili o essenziale, business critical, non critico). Lo score di rischio viene moltiplicato per questi due valori, come prevede `Architettura.md` §5. Un asset lasciato "Non classificato" conta come esposto su internet e critico, quindi risulta al massimo del rischio. Il nuovo valore conta dal prossimo ricalcolo, che il worker fa ogni 5 minuti; per farlo subito usa `POST /api/v1/tenants/{tenant_id}/scores/compute` da http://localhost:8000/docs.

Per usare http://localhost:8000/docs serve un token: in PowerShell

```powershell
(Invoke-RestMethod -Method Post -Uri http://localhost:8080/realms/sentinel/protocol/openid-connect/token -Body @{grant_type="password"; client_id="sentinel-ai"; username="tenant.admin"; password="sentinel-dev"}).access_token
```

copia il testo che esce, premi "Authorize" nella pagina e incollalo. Il token dura 15 minuti. L'ID del tenant di prova è `00000000-0000-4000-8000-000000000001`.

**Casi (Cases):** crea un caso con titolo, descrizione e severità; la scadenza SLA parte da subito (critical 4 h, high 24 h, medium 72 h, low 7 giorni; sono valori miei, da confermare). Clicca il titolo per aprire il pannello: con **Analyze** lo metti in analisi, con **Close** lo chiudi, con **False positive** lo scarti, con **Reopen** lo riapri. Nel pannello scrivi note (testo semplice) e leggi la timeline di tutto ciò che è successo. Il badge SLA è `on track`, `at risk` (resta meno di un quarto del tempo), `breached` (scaduto) o `met` (chiuso in tempo). I tab sopra la tabella filtrano per stato. Note e cambi di stato li fanno `analyst`, `tenant.admin` e `super.admin`; il viewer legge soltanto. Una nota la cancella chi l'ha scritta o un admin.

**Management** (solo `tenant.admin` e `super.admin`, voce "Management" nel menu): in **API keys** crei una chiave per un programma (per esempio un SIEM): la copi subito, perché non si rivede più, e la usi con l'header `X-API-Key`. Puoi revocarla in qualsiasi momento. In **Audit log** vedi chi ha fatto cosa, quando e da quale IP. **Tenants** (solo `super.admin`) crea e modifica i clienti: dopo averne creato uno, crea i suoi utenti in Keycloak con l'attributo `tenant_id`. **Roles** spiega i ruoli; gli utenti si gestiscono in Keycloak.

**STIX** (menu Knowledge Base, per `analyst` e admin): **Download bundle** scarica un file STIX 2.1 con indicatori, attori e campagne; la spunta "solo i miei" lascia fuori il catalogo comune. **Import** carica un bundle: crea ciò che manca come tuo, ignora i duplicati e ti elenca cosa non ha potuto importare e perché (pattern composti, tipi come malware, oggetti revocati).

**Arricchimento con VirusTotal:** un admin apre Management → Integrations → Add key e incolla la chiave di VirusTotal (account gratuito su virustotal.com, "API key" nel profilo). Dopo averla salvata nessuno può più vederla, nemmeno l'admin: si può solo sostituire o rimuovere. Poi, negli Observables, il pulsante **Enrich** accanto a un ip, dominio, url o hash chiede a VirusTotal e mostra le rilevazioni (per esempio `4/70`, cliccabile). Con la chiave gratuita il limite è 4 richieste al minuto: se compare "rate limit" aspetta un minuto. Se hai già riavviato lo stack con la nuova versione, per un uso reale metti la tua `SECRETS_ENCRYPTION_KEY` in `backend/.env` (vedi `.env.example`).

**Knowledge Graph** (menu Knowledge Base → Graph): mostra gli attori a sinistra, le loro campagne al centro e gli indicatori visti in ciascuna campagna a destra. Clicca un nodo per evidenziare le sue connessioni e leggerle nel pannello. Per dire che un indicatore è stato visto in una campagna, seleziona la campagna, scegli l'indicatore e premi **Connect** (**Unlink** per toglierlo). Compaiono solo gli indicatori già collegati a una campagna. L'import/export STIX porta con sé anche questi collegamenti.

**Punteggi (scoring v3):** un asset con tante vulnerabilità medie non diventa più automaticamente critico: il risultato più alto conta intero, il secondo la metà, il terzo un quarto e così via. Una vulnerabilità nel catalogo KEV (sfruttata in attacchi reali) porta l'asset ad almeno "medium" anche se è interno e poco importante. I punteggi già calcolati cambiano al prossimo ricalcolo.

**Cosa aspettarsi dalle pagine:** dal passo 2 tutte le pagine del frontend parlano con il backend. Molte restano vuote finché non arrivano dati: Exposure e Analysis finché non registri software con un CPE colpito da una CVE scaricata, Actors, Campaigns, Observables e Dark Web perché nessun collector li riempie ancora. Scores si riempie dopo `POST .../scores/compute` (lo può fare anche `analyst`).

## 6. Spegnere

```powershell
cd "C:\Users\lucab\OneDrive\Desktop\claude progetti\piattaforma cti"
powershell -ExecutionPolicy Bypass -File .\ferma-sentinel.ps1             # conserva i dati
powershell -ExecutionPolicy Bypass -File .\ferma-sentinel.ps1 -Cancella   # cancella anche il database
```

Poi chiudi la finestra di PowerShell del frontend (o premi Ctrl+C dentro).

## 7. Problemi comuni

| Sintomo | Cosa fare |
|---|---|
| Lo script dice "Docker non risponde" | Apri Docker Desktop e aspetta che la balena smetta di lampeggiare |
| "l'esecuzione di script è disabilitata nel sistema" | Usa il comando con `-ExecutionPolicy Bypass` come scritto sopra |
| Il login dà errore o pagina bianca | Keycloak ci mette fino a un minuto a partire. Aspetta e ricarica la pagina |
| Una porta è già occupata (5432, 6379, 8000, 8080, 5173) | Chiudi il programma che la usa (spesso un altro Postgres o un vecchio stack di Sentinel ancora acceso) |
| `migrate` è "Exited" con un numero diverso da 0 | `docker compose logs migrate` per vedere l'errore; di solito basta `docker compose up -d` una seconda volta |
| Voglio ripartire da zero | `.\ferma-sentinel.ps1 -Cancella`, poi di nuovo `.\avvia-sentinel.ps1` |
| Vedere cosa succede | Da `backend`: `docker compose logs -f api` oppure `docker compose logs -f worker` |

## Novità del passo 12

- **Scores → Explain**: spiega perché un asset ha quel punteggio (fattori di contesto e contributo di ogni vulnerabilità).
- **Dark Web**: due schede, Findings e Leaks. Si inseriscono a mano (bottone Add); le email dei leak vengono salvate solo come hash.
- **Reports**: più numeri, la classifica degli asset a rischio, **Download CSV** e **Print / PDF**.

Dettagli tecnici: `docs/AVVIO.md`. Stato del progetto: `docs/STATO-PROGETTO.md`.
