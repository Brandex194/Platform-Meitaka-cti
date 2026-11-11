> **Documento storico.** Si riferisce al vecchio codice di Sentinel AI (cartella `Desktop\File piattaforma per mediaminer`), sostituito dal rebuild iniziato il 23/10/2026. Conservato così com'era per riferimento; lo stato attuale è in `docs/STATO-PROGETTO.md`.

---

# Audit "tutto il progetto" — 2026-09-22

Richiesta: risolvere le mancanze rilevabili su backend + frontend + infra + demo. Ambito confermato dall'utente: tutto il progetto.

## Fix applicati e verificati

### Demo (`demo/SENTINEL_AI_v10.html`)
1. **CVE-2022-47966 → CVE-2022-42475.** L'entry (FortiOS SSL-VPN pre-auth RCE, sfruttata da BlackCat/ALPHV+LockBit, fix 7.0.9/6.4.11) era etichettata con l'ID sbagliato: CVE-2022-47966 è in realtà una RCE Zoho ManageEngine, non Fortinet. Verificato via Fortinet PSIRT FG-IR-22-398, CISA KEV ("Medusa"), FIRST.org EPSS live (99%).
2. **CVE-2014-6271 → CVE-2018-8273.** L'entry (SQL Server 2017 RTM) usava l'ID di Shellshock (bash) con una descrizione generica non riconducibile a nessuna CVE reale. Sostituita con CVE-2018-8273 (buffer overflow RCE reale in SQL Server 2017 RTM, fix KB4293803/agosto 2018), che mantiene la correlazione con gli asset "SQL Server 2017 RTM" di TechSupply/MediTalia/Assicura Vita. Verificato via KB4293803, NVD/Tenable (CVSS 9.8), FIRST.org EPSS live (29%).
3. Stesso ID vecchio corretto anche nel tag CVE di un post dark-web (ALPHV/BlackCat) che referenziava la CVE Fortinet.
4. **Exposure Operations scollegato da CUSTOMERS** — `EXP_PRESETS` era una copia statica e non sincronizzata dello stack software dei 4 clienti storici (mancavano EnergIS Power e Assicura Vita). Rimosso: `ExpModule.loadPreset()` ora legge lo stack direttamente da `CUSTOMERS`, unica fonte dati condivisa con Quick Report/Dashboard/Campagne. Aggiunti i pulsanti preset per i 2 clienti mancanti.
5. **`openCVEDetail()` era codice morto** — implementato (drawer CVE con actor, attack path, client impattati, remediation) ma non agganciato a nessun elemento cliccabile. Collegato in 4 punti dell'app live: card finding di Exposure Operations, dettaglio finding di Customer Risk Detail, badge Top CVE nella riga "Customers at Risk" del dashboard, finding correlati nel dettaglio Case.
6. **Dead code minore**: rimossa una `function renderCasesPanel` duplicata (la prima definizione era shadowata/mai eseguita; teneva solo il wrapper di compat esplicitamente commentato come tale).

Verifica: `node --check` sul JS estratto, bilanciamento `<div>` invariato rispetto all'originale, smoke test Playwright end-to-end (click reali su preset EnergIS Power/TechSupply, apertura drawer CVE per entrambe le CVE corrette, pannello Cases con filtro).

### Backend
Rieseguita la suite completa dopo aver riallineato la copia locale (mancava `app/reports/` — la feature Quick Report di una consegna precedente): **251/251 pytest, `ruff check .` pulito, `bandit -r app` pulito (0 issue su 7320 righe)**.

### Frontend
- **`frontend/.env.test` mancante** — confermato: `npm test` falliva a caricare `src/auth/userManager.test.ts` per `VITE_OIDC_AUTHORITY` assente. Il `.gitignore` esclude `.env.*` ma fa un'eccezione esplicita per `!frontend/.env.test`, quindi va versionato, non trattato come override locale. Creato con solo le 3 variabili OIDC richieste (non `VITE_API_BASE_URL`: due test di `runtimeConfig.test.ts` assumono esplicitamente, nei loro stessi commenti, che quella chiave resti assente da `.env.test`). Consegnato via `Claude outputs/env-fixed.test` + script (vedi sotto) perché la scrittura diretta di file `.env*` sul device è bloccata.
- Con `.env.test` a posto e le dipendenze reali del device (package.json ha già `vitest ^5.0.0`, non `^2.1.9` come in una copia locale non aggiornata usata per un primo giro di test): **24/24 vitest, `npm run lint` pulito (1 solo warning innocuo pre-esistente su React Compiler/TanStack Table), `tsc --noEmit` pulito, `npm run build` OK, `npm audit` → 0 vulnerabilità**.
- Nota minore non bloccante: bundle di build singolo da ~1MB (305KB gzip) — code-splitting da valutare in futuro, non prioritario ora.

## Consegnato all'utente
- `demo/SENTINEL_AI_v10.html` aggiornato scritto direttamente sul device (tutti i fix sopra).
- `setup-repo-v2.ps1` (sostituisce `setup-repo.ps1`, mai eseguito e con path ormai in parte inesistenti): sposta i workflow CI in `.github/workflows/` (tuttora vuota), sposta `.env.test` corretto in `frontend/`, archivia (non cancella) `demo/SENTINEL_AI_v9.html` e i doppioni in `Claude outputs/`+`github/`, aggiunge `.claude/settings.local.json` al `.gitignore`, poi `git init` + primo commit. **Va eseguito dall'utente** — questa sessione non ha `device_bash` né accesso "computer use" (rifiutato in precedenza), quindi nessun comando shell/git può essere lanciato direttamente sulla sua macchina.

## Aperto — decisione dell'utente, non presa autonomamente
- **`iac/` vs `infra/`**: entrambe contengono kubernetes+terraform sovrapposti. Da chiarire quale sia quella corrente prima del primo commit, altrimenti la duplicazione finisce versionata.
- **`docker/`, `prompts/`, `provaDemo/`, `domande per migliorie.txt`, `prompt.txt`, `run_demo.sh`**: non hanno l'aria di scarti ovvi (sembrano note di lavoro/materiale di supporto), quindi non li ho spostati né esclusi — da rivedere se devono entrare nel repo così come sono.
- `.claude/` (dir) e `.demo/` risultano già gestiti correttamente (quest'ultima è già in `.gitignore`; per `.claude/` ho aggiunto solo `settings.local.json`, per convenzione, allo script v2).
