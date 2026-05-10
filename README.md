# kite-mcp-oauth

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-oauth.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-oauth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

OAuth 2.0 + JWT session + dynamic client registration + Google SSO +
admin MFA TOTP for the algo2go ecosystem. Bundles authorize/token/
callback/registration handlers, RequireAuth middleware with token-
expiry detection, JWT issuance/verification, persistent ClientStore
(AES-256-GCM encrypted client_secrets), Google SSO callback flow,
and admin MFA TOTP enrolment + verification.

Used by [`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
for MCP client OAuth, dashboard SSO, admin RBAC gating, and
session lifecycle management.

## Why a separate module?

OAuth 2.0 + JWT + dynamic client registration is a substantial
authentication surface (~16K LOC). Hosting as a module:

- Centralizes the authentication contract across consumers
- Lets OAuth flow + JWT signature + ClientStore version
  independently of business logic
- Pairs cleanly with `algo2go/kite-mcp-templates` (callback HTML)
  and `algo2go/kite-mcp-users` (admin store + MFA backend) for
  the full identity stack

## Stability promise

**v0.x — unstable.** Type signatures and OAuth flow specifics may
evolve as MCP-Remote spec patterns mature. Pin `v0.1.0` deliberately.
v1.0 ships only after the public API (handlers, middleware, JWT
config, ClientStore methods) is reviewed for stability and at least
one external consumer ships against it.

## Install

```bash
go get github.com/algo2go/kite-mcp-oauth@v0.1.0
```

## Public API (selected)

### Handlers
- `NewHandler(...)` — composes the full OAuth handler set
- Authorize / Token / Callback / Registration HTTP handlers
- Browser login + admin MFA enrolment routes

### Middleware
- `RequireAuth(...)` — gates routes with JWT + token-expiry detection
- Returns 401 for unauthenticated AND expired Kite tokens (forces
  seamless re-auth via mcp-remote)

### JWT
- `JWTConfig` — config struct (24h MCP bearer, 7d dashboard cookie)
- `IssueJWT(email) string` / `VerifyJWT(token) (Session, error)`

### ClientStore
- `ClientStore` — persistent OAuth client_id → encrypted client_secret
  registry (AES-256-GCM via HKDF from OAUTH_JWT_SECRET)
- `RegisterClient(...)` / `LookupClient(client_id) (Client, error)`

### Google SSO
- Google SSO callback flow with userinfo + admin role injection

### Admin MFA
- TOTP enrolment + verification (admin-only per kc/users role gate)

## Dependencies

- `github.com/algo2go/kite-mcp-templates` v0.1.0 — callback HTML
- `github.com/algo2go/kite-mcp-users` v0.1.0 — admin store + MFA backend
- `github.com/algo2go/kite-mcp-alerts` v0.1.0 (indirect via users)
- `github.com/algo2go/kite-mcp-broker, kite-mcp-domain, kite-mcp-isttz,
  kite-mcp-logger, kite-mcp-money` (indirect via deeper transitive)
- `github.com/golang-jwt/jwt/v5` — JWT signing
- `golang.org/x/oauth2` — Google SSO flow
- `golang.org/x/crypto` — HKDF + AES-GCM
- `github.com/zerodha/gokiteconnect/v4` — Kite token validation
- `modernc.org/sqlite` — ClientStore backend

All algo2go deps are published modules; no upstream `replace`
directives needed.

## Reference consumer

[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
— consumed by 100+ files including app/, kc/audit, kc/billing,
kc/ops, kc/papertrading, kc/riskguard, mcp/admin, mcp/middleware,
plugins/rolegate, plugins/telegramnotify.

## License

MIT — see [LICENSE](LICENSE).

## Authors

Original design: [Sundeepg98](https://github.com/Sundeepg98) (Zerodha
Tech). Multi-module promotion (2026-05-10): algo2go contributors.
