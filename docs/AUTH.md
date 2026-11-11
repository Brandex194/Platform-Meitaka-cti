# Autenticazione, ruoli e isolamento tenant

Descrive il codice del rebuild al 9 novembre 2026 (`backend/app/auth/`, `backend/app/api/v1/deps.py`, `backend/app/db/session.py`, `frontend/src/auth/`). Sostituisce il vecchio `docs/AUTH.md`, che parlava del realm demo con 5 utenti e password condivisa: quel realm non esiste nel rebuild.

## Flusso

1. Il frontend fa login su Keycloak con Authorization Code + PKCE (`oidc-client-ts`), client `VITE_KEYCLOAK_CLIENT_ID` (oggi `sentinel-ai`), sessione in `sessionStorage`, rinnovo silenzioso attivo.
2. Ogni chiamata API porta `Authorization: Bearer <access_token>`.
3. Il backend verifica il JWT con le chiavi pubbliche del realm (JWKS da `{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs`): firma RS256, issuer del realm, audience uguale a `KEYCLOAK_CLIENT_ID`. Token assente o non valido: `401 UNAUTHORIZED`.
4. Non esiste una tabella utenti locale: ruoli e tenant arrivano solo dal token.

## Claim usati

| Claim | Uso |
|---|---|
| `sub` | identità dell'utente |
| `tenant_id` | tenant dell'utente; deve coincidere con il `{tenant_id}` del path |
| `roles` oppure `realm_access.roles` | ruoli RBAC |

Keycloak non emette `tenant_id` né `roles` di primo livello da solo: servono mapper nel client (attributo utente `tenant_id` → claim, ruoli realm → `roles`) e un audience mapper perché `aud` contenga il client del backend. Il realm di sviluppo `backend/keycloak/realm-dev.json` (aggiunto il 09/11/2026) li configura tutti sul client `sentinel-ai`, dichiara `tenant_id` nel profilo utente e contiene 5 utenti di prova (vedi `docs/AVVIO.md`). Per l'uso dentro Docker il backend scarica le chiavi da `KEYCLOAK_INTERNAL_URL` (es. `http://keycloak:8080`) ma continua a verificare l'issuer pubblico `KEYCLOAK_URL`.

## Ruoli

`super_admin`, `tenant_admin`, `analyst`, `viewer`, `api_user`. Permessi delle rotte (aggiornati al passo 2 del 09/11/2026):

| Azione | super_admin | tenant_admin | analyst | viewer | api_user |
|---|---|---|---|---|---|
| Leggere assets, scores, exposure match del proprio tenant | sì | sì | sì | sì | sì |
| Creare asset, cambiarne esposizione e impatto, aggiungere o togliere software | sì | sì | no | no | sì |
| Creare, modificare, cancellare casi; creare identità | sì | sì | sì | no | no |
| Creare, modificare, cancellare threat actor e campagne del proprio tenant; creare e cancellare IOC | sì | sì | sì | no | no |
| Risolvere / segnare falso positivo un exposure match | sì | sì | sì | no | no |
| Ricalcolare gli score (`POST .../scores/compute`) | sì | sì | sì | no | no |
| Creare o modificare una `ScoreRule` | sì | no | no | no | no |
| Accedere ai dati di un altro tenant | sì | no | no | no | no |

Un ruolo mancante restituisce `403 FORBIDDEN`. Tutti i ruoli leggono dashboard, casi, identità, eventi di correlazione, IOC, osservazioni, report, threat actor e campagne. `super_admin`, `tenant_admin` e `analyst` creano, modificano e cancellano i threat actor, le campagne e gli IOC del proprio tenant (`/tenants/{id}/threat-actors`, `/campaigns`, `/indicators`); le voci comuni (`tenant_id` NULL) non si cambiano da una sessione di tenant. Le rotte di gestione dei tenant previste dalla spec non esistono ancora.

## Isolamento tenant

Tre livelli, tutti attivi:

1. **Controllo token/path** — `get_scoped_db` rifiuta con `403 FORBIDDEN` ("Tenant mismatch") se il `tenant_id` del token non coincide con quello del path. Solo `super_admin` è esente.
2. **RLS Postgres** — la sessione imposta `app.current_tenant_id` con `set_config(..., true)` (parametrizzato, valido solo per la transazione). Le policy `tenant_isolation` su 13 tabelle filtrano per quella variabile. L'API si collega come `sentinel_app`, ruolo senza superuser e senza BYPASSRLS.
3. **Filtro esplicito** — le query delle rotte filtrano comunque per `tenant_id`.

Eccezione voluta (migrazione 0005): su `score_rules` le regole globali (`tenant_id` NULL) si leggono anche da una sessione di tenant, ma non si possono scrivere (`WITH CHECK` senza il ramo NULL).

Worker e collector usano `bypass_session()`, che imposta `app.bypass_tenant_scope=on` per elaborare tutti i tenant; le policy controllano prima quel flag (migrazione 0004).

Eccezioni: `GET /api/v1/threat-actors` e `GET /api/v1/campaigns` non hanno il tenant nel path (catalogo comune). Usano `get_db` e `decode_token`; le campagne con un `tenant_id` diverso da quello del token sono escluse nel codice, perché `campaigns` non ha RLS. Anche `indicators` non ha RLS: la rotta mostra solo IOC globali e del proprio tenant con un filtro esplicito. Dalla migrazione `0007` anche `threat_actors` ha `tenant_id` (NULL = catalogo comune), senza RLS e con lo stesso filtro esplicito: la lista mostra gli attori comuni e quelli del proprio tenant, mai quelli di altri tenant.

## Formato degli errori

```json
{"error": {"code": "FORBIDDEN", "message": "Insufficient permissions", "detail": {}}}
```

Codici in uso: `UNAUTHORIZED` (401), `FORBIDDEN` (403), `NOT_FOUND` (404), `VALIDATION_ERROR` (422), `RATE_LIMIT_EXCEEDED` (429, previsto ma non ancora attivo).

## Audit

Ogni `POST`, `PATCH`, `DELETE` andato a buon fine scrive una riga in `audit_logs` (middleware, solo su Postgres). La creazione e la modifica di una `ScoreRule` scrivono anche una riga dedicata con la versione. Al contrario del vecchio codice, `audit_logs` **non** è protetta da un trigger append-only: oggi un ruolo con DELETE sulla tabella può cancellare righe.

## Cosa manca

- Realm di produzione senza utenti né password nel repo (fase 3).
- Rate limit per tenant: la funzione `check_rate_limit` (100 richieste/60 s per tenant su Redis) esiste ma nessuna rotta la chiama.
- Verifica end-to-end: fatta il 09/11/2026 con Keycloak 25 vero e token per 3 ruoli (vedi `docs/STATO-PROGETTO.md`). Il 09/11 (passo 2) fatto anche il login dal browser con `tenant.admin`. I test automatici sostituiscono ancora la verifica del token con un override.


## Casi: note e timeline (passo 7)

`case_notes` e `case_events` hanno RLS forzata come le altre tabelle per tenant. Lettura: ogni ruolo del tenant. Scrittura di note e cambi di stato: `analyst`, `tenant_admin`, `super_admin`. Cancellare una nota: l'autore (confronto con `sub` del token) oppure `tenant_admin`/`super_admin`; altrimenti 403. Un caso di un altro tenant risponde 403 dal controllo sul tenant del path, e 404 se l'id non esiste nel proprio.


## Chiavi API, audit e tenant (passo 8)

- **Chiavi API**: header `X-API-Key: mk_...`. `decode_token` prova prima il Bearer; se non c'è, cerca la chiave (hash SHA-256) con una sessione che salta la RLS, perché il tenant si conosce solo dopo. Una chiave valida produce un payload con `roles: ["api_user"]` e il `tenant_id` della chiave, quindi `get_scoped_db` la blocca sugli altri tenant come un token normale. Scaduta o revocata = 401. `last_used_at` si aggiorna a ogni uso. `api_keys` ha RLS forzata come le altre tabelle per tenant.
- **Gestione chiavi e audit log**: `tenant_admin` e `super_admin`; l'`api_user` non può gestire chiavi.
- **Tenant** (`/api/v1/admin/tenants`): solo `super_admin`, con sessione che salta la RLS (`get_admin_db`) perché `tenants` ha RLS sull'id.
- **Audit**: il middleware scrive utente (claim `sub` del Bearer, letto solo dopo che la rotta ha accettato la richiesta), IP del client, esito, e `{"via": "api_key"}` se la richiesta usava una chiave. Dietro un proxy l'IP è quello del proxy finché non si configurano gli header inoltrati.

## STIX (passo 9)

`GET /tenants/{t}/stix/export` e `POST /tenants/{t}/stix/import`: `analyst`, `tenant_admin`, `super_admin`, `api_user`; il viewer riceve 403. Le tabelle `indicators`, `threat_actors` e `campaigns` non hanno RLS: export e import filtrano a mano per tenant (comune + proprio), e ciò che si importa è sempre del tenant del path.


## Chiavi di servizi esterni (passo 10)

`integration_keys` (RLS forzata): una riga per tenant e servizio con la chiave **cifrata** (Fernet, master key `SECRETS_ENCRYPTION_KEY`, nessun ripiego). Impostare, sostituire, cancellare e elencare: `tenant_admin` e `super_admin`. Nessuna rotta restituisce la chiave; il corpo della richiesta di salvataggio è letto come dizionario libero perché un errore di validazione standard ripeterebbe il valore inviato, e l'audit log registra solo il percorso. Usare la chiave (Enrich) è permesso a `analyst`, `tenant_admin`, `super_admin`: il backend la decifra per la singola chiamata e non la restituisce. `indicator_enrichments` (RLS forzata) tiene solo i numeri del verdetto.


## Knowledge Graph (passo 11)

`campaign_indicators` ha RLS forzata come le altre tabelle per tenant. `GET /tenants/{t}/graph`: tutti i ruoli del tenant. Collegare e scollegare (`POST`/`DELETE /tenants/{t}/campaigns/{id}/indicators`): `analyst`, `tenant_admin`, `super_admin`. Attori, campagne e indicatori non hanno RLS: grafo e collegamenti filtrano a mano (righe comuni con `tenant_id` NULL più quelle del proprio tenant) e rifiutano con 404 ciò che il tenant non vede.


## Spiegazione score, Dark Web, Quick Report (passo 12)

`GET /tenants/{t}/assets/{id}/score-explanation` e `GET /tenants/{t}/reports/quick`: tutti i ruoli del tenant. Dark Web: lettura a tutti i ruoli (`/observations?event_type=darkweb`, `GET /darkweb/leaks`); `POST/PATCH/DELETE` su `/darkweb/findings` e `/darkweb/leaks` per `analyst`, `tenant_admin`, `super_admin`. `observations` e `leaks` hanno RLS; in più le route filtrano per tenant e per `event_type`, quindi non si può toccare un'observation di altro tipo da questi endpoint. L'email di un leak non viene mai salvata in chiaro né restituita.
