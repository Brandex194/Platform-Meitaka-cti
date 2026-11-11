# Documenti storici

Documenti scritti per il vecchio codice di Sentinel AI (cartella `Desktop\File piattaforma per mediaminer`, non modificata). Ognuno ha in testa una nota che dice cosa vale ancora. Lo stato attuale è in [`../STATO-PROGETTO.md`](../STATO-PROGETTO.md).

| File | Cos'era | Vale ancora? |
|---|---|---|
| `2026-09-22-audit-vecchio-codice.md` | Audit completo di backend, frontend, infra e demo | No, riguarda codice sostituito |
| `2026-10-09-revisione-vecchio-codice.md` | Revisione con test eseguiti e problemi in ordine di impatto | Solo come checklist (realm demo in prod, dashboard) |
| `2026-10-23-reverse-engineering-vecchio-codice.md` | Analisi dal codice da cui è nato il rebuild | I 10 difetti sono ricontrollati in `STATO-PROGETTO.md` |
| `vecchio-README.md` | README del vecchio repo | Sostituito da `README.md` |
| `vecchio-IMPLEMENTATION_PLAN.md` | Workstream WS1–WS7 e stato al 23/09 | Sostituito da `IMPLEMENTATION_PLAN.md` |
| `vecchio-AUTH.md` | Auth con realm demo a 5 utenti | Sostituito da `docs/AUTH.md` |
| `vecchio-DEPLOY-azure-aws.md` | Deploy Terraform AKS/EKS + Helm e hardening | Infrastruttura non presente nel rebuild; utile come checklist di hardening |
| `vecchio-RUNBOOK.md` | Operazioni su ambiente deployato | Non applicabile finché non c'è un deploy |
| `vecchio-Avvio.md` | Guida all'avvio con docker compose | Sostituita da `docs/AVVIO.md` |
| `input-design/prompt.txt` | Prompt di design della demo (stile enterprise, struttura pagine) | Sì, come requisito di UI |
| `input-design/domande per migliorie.txt` | Suggerimenti UX sulla demo (densità, gerarchia, focus mode) | Sì, come requisito di UI |

Le note sugli strumenti per ridurre i token sono in `../note/`, aggiornate al 09/11/2026.
