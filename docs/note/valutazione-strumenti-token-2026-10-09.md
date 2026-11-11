> **Aggiornamento 9 novembre 2026.** Cosa è cambiato da quando è stata scritta questa nota:
> - Graphify è installato e in uso: `graphify-out/` nella cartella del rebuild contiene un grafo costruito il 03/11/2026 (793 nodi). Nella radice non c'è un `.graphifyignore`; oggi il repo non contiene `.env` né dati di clienti, ma va aggiunto prima di introdurre seed o fixture reali.
> - Il rebuild è un repository git (branch `feature/phase1-backend`), quindi `graphify hook install` ora funziona.
> - I percorsi sotto che puntano a `File piattaforma (vecchio prototipo)` vanno letti come `claude progetti\piattaforma cti`.
> - La cartella del rebuild non ha ancora `.claude/skills/`: gli skill di progetto proposti più sotto non sono stati creati. Lo skill di scoring andrebbe scritto solo dopo aver deciso quali formule valgono (vedi `docs/STATO-PROGETTO.md`).
> - Per il lavoro del rebuild è stato usato il flusso superpowers (spec, piani, registro in `.superpowers/sdd/`).

---

# Ridurre i token in Claude Code: ponytail, OmniRoute, graphify, agent skills

Valutazione del 2026-10-09 per il lavoro su Sentinel AI. Fonti lette: README dei repository su GitHub, docs ufficiali Claude Code, due benchmark indipendenti. I numeri "dichiarati" vengono dagli autori; quelli "misurati" da terzi. Non ho installato né eseguito nessuno dei quattro strumenti.

## In sintesi

| Strumento | Cosa taglia | Risparmio realistico | Rischio dati | Raccomandazione |
|---|---|---|---|---|
| Graphify | Input (lettura del repo) | Alto su repo medi/grandi, ~0 su repo piccoli | Basso (codice parsato in locale) | **Sì, provalo per primo** |
| Agent skills | Input (regole riletti ogni volta) | Moderato | Nessuno | **Sì, 2-3 skill mirati** |
| Ponytail | Output (codice scritto) | ~10% di costo misurato da terzi | Nessuno (solo un prompt) | **Sì, a costo zero, ma aspettati poco** |
| OmniRoute | Costo, non qualità | Alto in €, a scapito di qualità e riservatezza | **Alto** | **No per Sentinel AI** |

Il costo principale in una sessione Claude Code è l'input, non l'output: in un'analisi su 171 sessioni l'output dei tool (letture file, grep, log) era il 67,5% del contesto ([dev.to](https://dev.to/jaypokale/caveman-vs-ponytail-vs-chisle-i-benchmarked-the-claude-code-token-saving-plugins-on-20-tasks-bg8)). Per questo graphify e gli skill rendono più di ponytail.

## Graphify

- Repo: [Graphify-Labs/graphify](https://github.com/Graphify-Labs/graphify), Apache-2.0/MIT, ~125k stelle, molto attivo.
- Come funziona: costruisce un knowledge graph del repo. Il **codice** è parsato in locale con tree-sitter, zero chiamate LLM. **Documenti, PDF e immagini** vengono invece mandati al modello per estrarre i concetti. Un hook in Claude Code intercetta Read/Glob/grep e spinge Claude a interrogare il grafo invece di aprire i file (`--strict` blocca la prima lettura raw).
- Risparmio: il README attuale non dichiara una cifra sui token, pubblica benchmark di accuratezza (copertura fatti chiave 82% contro 70,8% di grep/read). Una guida di terzi riporta 71,5x meno token per query su un corpus di 52 file e circa 1x su 6 file ([claudelog](https://claudelog.com/claude-code-mcps/graphify)). Sentinel AI (backend + frontend + infra) è nella fascia dove conviene.
- Installazione: `uv tool install graphifyy` (sì, due "y"), `graphify install --project`, poi `/graphify .` in Claude Code. Per tenerlo aggiornato: `graphify hook install` (rebuild a ogni commit) o `--watch`.
- Attenzione: escludi dal grafo `.env`, dump di dati tenant e fixture con dati reali, perché i documenti non-codice vanno al modello. Il repo oggi non ha `.git`, quindi l'hook su commit non funziona finché non lo inizializzi.

## Agent skills

- Docs ufficiali: [code.claude.com/docs/en/skills](https://code.claude.com/docs/en/skills).
- Come funzionano: in ogni turno resta in contesto solo nome + descrizione di ogni skill. Il corpo di `SKILL.md` si carica solo quando serve, e i file di supporto solo se lo skill li richiama.
- Due dettagli che contano: una volta caricato, il corpo **resta in contesto** per il resto della sessione, quindi va tenuto corto (le docs dicono sotto 500 righe). E ogni skill installato costa la sua descrizione in **ogni** turno: installare decine di plugin di skill peggiora il consumo invece di migliorarlo. `/skill-doctor` mostra quanto costa ciascuno.
- Per Sentinel AI: sposta in `.claude/skills/` le regole che oggi Claude rilegge da `Architettura.md` e `.copilot-instructions.md`. Tre skill bastano: formule di scoring e ScoreRule, comandi di qualità (pytest/ruff/bandit/npm), isolamento multi-tenant.

## Ponytail

- Repo: [DietrichGebert/ponytail](https://github.com/DietrichGebert/ponytail), MIT, ~158k stelle.
- Cos'è: un singolo prompt che fa scrivere meno codice a Claude. Prima di scrivere si chiede se il codice serve, se esiste già, se basta la libreria standard o una riga. Dichiara di non tagliare validazione, error handling e sicurezza.
- Risparmio dichiarato: −45% token, −26% costo, −53% codice (benchmark degli autori, 39 task).
- Risparmio misurato da terzi:
  - JetBrains, 80 task: costo mediano **−10%**, peggio su 34 task su 80, qualità senza differenze rilevabili ([JetBrains](https://blog.jetbrains.com/ai/2026/07/ponytail-skill-claude-tested/)).
  - dev.to, 20 task: bolletta totale al 68% del baseline, ma su 8 task su 20 ha speso di più ([dev.to](https://dev.to/jaypokale/caveman-vs-ponytail-vs-chisle-i-benchmarked-the-claude-code-token-saving-plugins-on-20-tasks-bg8)).
- Installazione: come plugin (`/plugin marketplace add DietrichGebert/ponytail`, poi `/plugin install ponytail@ponytail`). Copiare solo `SKILL.md` nella cartella skills non funziona: JetBrains ha visto zero attivazioni in 10 sessioni.
- Nota: non combinarlo con "caveman", nel benchmark dev.to la coppia ha consumato più di uno solo.

## OmniRoute

- Repo: [diegosouzapw/OmniRoute](https://github.com/diegosouzapw/OmniRoute), MIT, ~74k stelle, molto attivo ma enorme (350+ provider, 10k commit).
- Cos'è: un gateway locale (`localhost:20128/v1`) che smista le richieste tra centinaia di provider, con fallback e "150+ free tier". Ha anche una pipeline di compressione (RTK + caveman) che dichiara 15–95% di token in meno, non verificata da terzi.
- Perché no per Sentinel AI:
  - Il guadagno vero è mandare le richieste a modelli più economici o gratuiti. Claude Code con un modello diverso da Claude lavora peggio, e un errore su scoring o isolamento tenant costa più dei token risparmiati.
  - Codice, prompt ed eventuali dati dei tenant finirebbero a provider terzi, spesso free tier che usano i dati per training. Per una piattaforma CTI venduta a clienti B2B è un problema contrattuale prima che tecnico.
  - Il progetto stesso marca 13 provider come "avoid" nel suo catalogo di rischio sui termini d'uso e offre "key pool" per condividere abbonamenti: è terreno da violazione dei ToS.
- Se ti serve solo la compressione, ottieni lo stesso effetto in modo più pulito con graphify + skill, senza far passare il traffico da un proxy.

## Dove la risposta preliminare era sbagliata o incompleta

- **Ponytail**: non era "sconosciuto". È un plugin di prompt che riduce il codice scritto, misurato da terzi intorno al −10% di costo.
- **OmniRoute**: non è solo un router, ha anche una compressione dei token. La conclusione resta però la stessa, il beneficio principale è spostare traffico su modelli economici, con il problema di riservatezza.
- **Graphify**: corretto nella sostanza. Precisazione: il codice non passa da nessun LLM, ci passano solo documenti, PDF e immagini.
- **Agent skills**: corretto. Va aggiunto che ogni skill installato costa la sua descrizione a ogni turno, quindi pochi e mirati.
- Confermato: tutto si installa nel Claude Code sul tuo PC, non nei thread di questo progetto.

## Ordine consigliato

1. Graphify sul repo Sentinel AI, con esclusione di `.env` e dati tenant.
2. Tre skill di progetto in `.claude/skills/`.
3. Ponytail come plugin, controllando con `/cost` se su due o tre giorni di lavoro cambia qualcosa.
4. OmniRoute: no.

## Installazione su Windows (Claude Code sul PC)

Comandi presi dai README ufficiali, non eseguiti da me.

### 1. Graphify

In PowerShell:

```powershell
winget install astral-sh.uv
uv tool install graphifyy
# se "graphify" non viene trovato: uv tool update-shell, poi apri un nuovo terminale
cd "C:\percorso-progetto\piattaforma cti"
```

Prima di costruire il grafo, crea `.graphifyignore` nella root del repo (sintassi `.gitignore`, `.gitignore` viene rispettato in automatico):

```
.env
.env.*
**/*.env
**/secrets/
**/fixtures/
**/seed*/
*.sql
*.dump
*.csv
*.xlsx
node_modules/
dist/
```

Adatta `fixtures/`, `seed*/`, `*.csv` alle cartelle reali dove ci sono dati di clienti. Poi:

```powershell
graphify install --project          # se non rileva Windows: graphify install --platform windows --project
```

In Claude Code: `/graphify .` (in PowerShell senza slash: `graphify .`). Infine, una volta costruito il grafo:

```powershell
graphify claude install             # fa consultare il grafo a Claude prima di leggere/cercare file
```

Aggiornamento: `graphify update .` dopo modifiche importanti. `graphify hook install` ricostruisce a ogni commit, ora che il rebuild è un repo git funziona.

### 2. Ponytail

Dentro Claude Code, due prompt separati:

```
/plugin marketplace add DietrichGebert/ponytail
/plugin install ponytail@ponytail
```

Riavvia la sessione. Va installato come plugin: copiare solo `SKILL.md` non lo attiva.

### 3. Agent skills di progetto

Un file per skill in `.claude/skills/<nome>/SKILL.md` nella root del repo:

```markdown
---
name: sentinel-scoring
description: Formule di risk scoring di Sentinel AI e regole ScoreRule. Usare quando si tocca scoring, pesi, soglie o risk engine.
---

S_base(i) = f_severity*0.5 + f_confidence*0.3 + f_recency*0.2
... (resto delle formule da Architettura.md §5)
Ogni modifica a pesi/soglie passa da ScoreRule versionata + audit log.
```

Proposta: `sentinel-scoring`, `sentinel-quality` (pytest, ruff, bandit, npm test/lint/typecheck/build), `sentinel-tenant-isolation` (RLS, filtro tenant su ogni query). Descrizioni brevi e specifiche, corpo sotto le 500 righe. Controlla il costo con `/skill-doctor`.
