> **Documento storico.** Si riferisce al vecchio codice di Sentinel AI (cartella `Desktop\File piattaforma (vecchio prototipo)`), sostituito dal rebuild iniziato il 23/10/2026. Sostituito da `docs/AUTH.md`. Conservato così com'era per riferimento; lo stato attuale è in `docs/STATO-PROGETTO.md`.

---

# Autenticazione e RBAC — guida rapida (Blocco 8 + Blocco 9)

Sentinel AI usa OIDC/OAuth2 reale (Architettura §6.1 punto 4) per
autenticare ogni chiamata API e ogni sessione frontend. Non esiste alcun
percorso "senza login": ogni endpoint tranne `/health` richiede un JWT
RS256 valido, verificato dal backend contro le JWKS del provider OIDC
configurato.

## Provider OIDC in sviluppo: Keycloak

`docker-compose.yml` include un container Keycloak (`quay.io/keycloak/keycloak:25.0.6`,
modalità `start-dev`) che importa automaticamente, all'avvio, il realm
definito in `docker/keycloak/realm-export.json`:

- **Realm**: `sentinel-ai`
- **Client SPA pubblico**: `sentinel-frontend` — Authorization Code + PKCE
  (S256), nessun client secret (client pubblico, come richiesto per
  un'app browser). Redirect URI: `http://localhost:5173/auth/callback`.
- **Ruoli realm**: `super_admin`, `tenant_admin`, `analyst`, `viewer`,
  `api_user` — esattamente i 5 ruoli di Architettura §3.1, mappati 1:1 su
  `app/auth/roles.py` nel backend.
- **Claim custom `tenant_id`**: mappato da un attributo utente Keycloak
  con lo stesso nome, tramite un protocol mapper dedicato sul client —
  necessario perché non è un claim OIDC standard.
- **Audience**: un mapper `oidc-audience-mapper` aggiunge `"sentinel-ai"`
  all'`aud` dell'access token, per farlo corrispondere al default di
  `OIDC_AUDIENCE` nel backend (Keycloak non lo fa di default).

Il backend verifica l'`iss` del token contro `OIDC_ISSUER_URL`
(`http://localhost:8081/realms/sentinel-ai`, l'URL pubblicato che il
browser vede) mentre recupera le JWKS tramite `OIDC_JWKS_URL` sulla rete
Docker interna (`http://keycloak:8080/...`) — due percorsi di rete diversi
per lo stesso provider, intenzionale (vedi commento in `docker-compose.yml`
sopra `x-oidc-env`).

## Utenti demo (SOLO sviluppo — non usare in produzione)

Tutti con password `SentinelDemo!2026`, tutti collegati al tenant fisso
seedato da `app/db/seed.py` (`Sentinel Demo Tenant`,
id `11111111-1111-4111-8111-111111111111`) tranne il super admin, che per
definizione non è legato a un singolo tenant:

| Username | Ruolo | Per testare |
|---|---|---|
| `super.admin` | `super_admin` | Accesso cross-tenant, `/tenants`, switch tenant |
| `tenant.admin` | `tenant_admin` | Gestione asset/config del tenant demo |
| `analyst` | `analyst` | Scoring, analisi IoC, dark web |
| `viewer` | `viewer` | Sola lettura — verifica che i pulsanti di scrittura siano nascosti/bloccati |
| `api.user` | `api_user` | Ceiling di rate limiting più alto, uso programmatico |

Questi utenti/password sono pubblici in questo repository di sviluppo per
scelta — **rigenerare completamente il realm** (nuove password, nessun
utente demo, `directAccessGrantsEnabled: false`) prima di qualunque
deploy raggiungibile da Internet. Questo è tracciato come attività del
Blocco 12 (hardening di sicurezza finale).

## Avvio locale

```bash
docker compose up -d postgres redis keycloak
docker compose up migrate         # applica migrazioni + seed (tenant demo incluso)
docker compose up -d api worker beat frontend
```

Poi apri `http://localhost:5173`, clicca "Accedi" e usa una delle
credenziali sopra. Il primo avvio di Keycloak in modalità dev può
richiedere 20-30 secondi prima che l'healthcheck diventi verde (compilazione
JIT/Quarkus); `api` aspetta che Keycloak sia sano prima di partire.

## Cosa NON è stato verificato end-to-end in questo ambiente

Il backend/JWT/RBAC/rate-limit/audit-log (Blocco 8) sono stati verificati
per davvero contro un vero server JWKS locale e Postgres/Redis reali. Il
flusso di login OIDC/PKCE del frontend (Blocco 9) è stato verificato con un
browser reale (Playwright/Chromium) contro un provider OIDC "shape-identico"
a Keycloak (stessa forma di issuer, stesso claim `tenant_id`, stesso
`realm_access.roles`) fatto girare localmente — questo ambiente sandbox non
ha un daemon Docker disponibile, quindi il container Keycloak reale sopra
descritto non è mai stato avviato qui. La sintassi di `docker-compose.yml`
e la validità JSON di `realm-export.json` sono state verificate
staticamente. **Prima del primo utilizzo reale, esegui il flusso di login
una volta con Keycloak vero** (comandi sopra) per confermare che tutto
combaci esattamente come nel provider di test.
