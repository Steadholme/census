# Census — people directory, profiles & groups

Census is the authoritative people directory of the Steadholme estate. It layers an editable
profile / group / membership store over the real identities **Keystone** owns: it READS the shared
`holdfast` database's `users` table (subject + email only — **never** the password hash) to
enumerate who exists, and owns the editable layer in its own `census` database.

It is **internal-only**, served behind a Sluice `auth=sso` route at the subdomain root
`people.w33d.xyz`. It runs no login of its own — it trusts the gateway-injected
`X-Auth-Subject` / `X-Auth-Email` / `X-Auth-Scope` headers, strips any inbound copies, and keys a
profile edit to the verified subject.

## Endpoints

| Method | Path                          | Auth        | Purpose |
|--------|-------------------------------|-------------|---------|
| GET    | `/healthz`                    | none        | Liveness probe (container HEALTHCHECK). |
| GET    | `/`                           | sso         | Directory: every Keystone identity joined to its profile, keyword filter, groups panel. |
| GET    | `/u/{sub}`                    | sso         | A person page — profile + group memberships (owner gets the inline edit form). |
| POST   | `/api/profile`                | sso, CSRF   | Edit **my own** profile (subject from `X-Auth-Subject`). |
| GET    | `/groups`                     | sso         | Groups directory + create form + per-group membership management. |
| POST   | `/api/groups`                 | sso, CSRF   | Create a group (unique name). |
| POST   | `/api/groups/{id}/members`    | sso, CSRF   | Add or remove a member (`action=add\|remove`). |
| GET    | `/api/people`                 | sso         | JSON people feed (`{sub, email, display_name, title}`) for other services. |

State-changing POSTs are double-submit CSRF protected (`__Host-csrf` cookie + hidden field). The bio
is rendered as **sanitized** Markdown (raw HTML escaped to text, link/image URLs scheme-allowlisted);
the avatar URL is allowlisted to `http`/`https`/relative before it is used as an `<img src>`.

## Audit

Notable changes are emitted to Watchtower via a **non-blocking** bounded-queue emitter
(`source=census`): `census.profile.update` (a profile edit) and `census.group.change` (a group
create / membership add / remove). A slow or down Watchtower never blocks, slows, or fails a request.

## Configuration

| Env var                 | Default            | Purpose |
|-------------------------|--------------------|---------|
| `BIND_ADDR`             | `0.0.0.0:9130`     | Listen address. |
| `CENSUS_STORE`          | `memory`           | `memory` (zero-config) or `postgres`. |
| `DATABASE_URL`          | —                  | Required when `CENSUS_STORE=postgres` (the `census` DB). |
| `KEYSTONE_DATABASE_URL` | —                  | Read-only DSN to the shared `holdfast` DB (Keystone `users`). Unset = no enumerated identities (the signed-in viewer is still always visible). |
| `AUDIT_ENABLED`         | `false`            | Enable the Watchtower audit emitter. |
| `WATCHTOWER_URL`        | `http://watchtower:8500` | Watchtower base URL (plain HTTP, in-network). |
| `AUDIT_INGEST_TOKEN`    | —                  | Bearer token for Watchtower ingest. |

The service **boots zero-config**: with no environment set it uses the in-memory store + an empty
directory, so the signed-in viewer can always see and edit their own profile.

## Data model (own `census` DB — portable standard SQL)

```text
profiles(sub TEXT PK, display_name TEXT NOT NULL DEFAULT '', title TEXT NOT NULL DEFAULT '',
         bio TEXT NOT NULL DEFAULT '', avatar_url TEXT NOT NULL DEFAULT '', updated_at BIGINT)
groups(id TEXT PK, name TEXT UNIQUE NOT NULL, description TEXT NOT NULL DEFAULT '', created_at BIGINT)
memberships(group_id TEXT NOT NULL, sub TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'member',
            joined_at BIGINT, PRIMARY KEY(group_id, sub))
```

Runtime sqlx queries only (no compile-time macros, no database needed to build), standard SQL only
(no JSONB / arrays / SERIAL / extensions), so the same statements run unchanged on FusionDB over
pgwire. `migrate()` runs `CREATE TABLE IF NOT EXISTS` on startup.

## Build & test

```bash
CARGO_BUILD_JOBS=2 cargo check --all-targets
cargo test                 # in-memory flow + unit tests (no database)
TEST_DATABASE_URL=postgres://… cargo test --test pg_store -- --nocapture   # PG integration
```

## Frontend (v2, 2026-09-08)

The directory follows the shared Steadholme v2 system implemented from the Figma
file `ZyDrJFbfBmd7YiingQ671q` (Census, sky accent). The stylesheet served at
`/assets/census-20260908.css` is `crates/odyssey`'s canonical layer concatenated
with this repo's `static/service.css`; bump the date in `src/handlers/mod.rs`
(`APP_CSS_PATH`) and in `tests/census_flow.rs` together when the CSS changes, so
the immutable cache entry is invalidated. No page carries an inline `<style>`.

Every page renders through `shell(TEMPLATE, active, theme, email)`, which fills
`{{THEME_ATTR}}`, `{{COLOR_SCHEME}}`, `{{CSS_PATH}}`, `{{FOOTER}}` and
`{{APPBAR}}` — in that order, so the one caller-supplied chrome value (the
signed-in email) is substituted last and can never be re-scanned as a template
instruction. The theme comes from the `__Secure-theme` cookie via
`odyssey::resolve_theme`.

The cross-writer DOM contract in `tests/dom_contract.rs` is load-bearing and
unchanged: the roll keeps `roll`/`roll__row`/`roll__index`, provenance keeps
`prov prov--*` and `prov-note`, the legend keeps its `aria-label` and the
sentence "Unmarked rows are enumerated by the identity source.", groups keep
`members`/`member`/`member__via`/`readonly-note`, and outage/overflow keep
`alert--down banner` and `bound`/`bound__mark`.

Two deliberate changes came from the design. The directory gained a five-tile
stat strip (people, groups, departments, provisional marks, newest workforce
observation) and per-row group chips. The groups grid became a browse surface:
a card carries the name, counts, description and a member facepile, and every
membership edit — add, remove, link a child group — now lives only on the group
page the card links to, instead of being duplicated on both.

Selects reset `appearance` and draw their own caret. Odyssey paints a chevron
via `background-image`, and a `background` shorthand here resets its
`background-repeat`, which tiles the arrow under `:root[data-theme="dark"]`.
