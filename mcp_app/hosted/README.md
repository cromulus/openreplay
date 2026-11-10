# Hosted OpenReplay MCP

The Dokploy Compose file runs the upstream MCP app behind a Streamable HTTP gateway at `https://replay.nmc-atelier.com/mcp`. The gateway provides OAuth discovery, dynamic client registration, PKCE, explicit browser consent, token rotation and revocation. Sign in to OpenReplay in the same browser before approving the connector.

Only read tools are exposed. The arbitrary API proxy and tools that change the backend or authentication are excluded. Each MCP session starts a separate upstream stdio process with an isolated temporary configuration. OAuth grants retain the approving user's existing OpenReplay permissions. The backend URL is fixed by `OPENREPLAY_URL`.

The gateway verifies the OpenReplay JWT against `/api/projects` before issuing a grant, refreshing a grant, or opening a session. It never takes a password. The consent page uses the existing same-origin `UserStore.jwt` session, after the user clicks Approve. This supports the installed v1.27 API without upgrading the application or adding the newer `/api/v1/mcp/auth-status` endpoint.

Access tokens last at most one hour; rotating refresh tokens expire with the original OpenReplay session or after 24 hours, whichever comes first. Reconnect and approve again after expiry. Grants and client registrations survive restarts in the `mcpdata` volume, encrypted with a separate owner-only key in that volume. Back up the entire volume together; do not commit its contents.

## Build and verify

From the repository root:

```sh
corepack yarn --cwd player install --frozen-lockfile
corepack yarn --cwd mcp_app install --frozen-lockfile
corepack yarn --cwd mcp_app build
node --test mcp_app/hosted/gateway.test.mjs
docker compose --env-file /secure/path/dokploy.env -f scripts/docker-compose/dokploy.docker-compose.yml config --quiet
```

The upstream typecheck wrapper excludes pre-existing player errors; it does not establish that the entire player package typechecks.

To deploy MCP independently of database migrations and the existing application services, use the existing Dokploy project name and environment, build only `mcp-openreplay`, then `up -d --no-deps mcp-openreplay`. Validate nginx with `nginx -t` before reloading the existing container. Never run the full Compose stack just to update MCP.

Public checks: `/mcp-health` returns 200; unauthenticated `/mcp` returns 401 with a resource metadata challenge; `/.well-known/oauth-protected-resource/mcp` and `/.well-known/oauth-authorization-server` advertise the connector. These checks establish availability, not authenticated data access. Verify a real OAuth login, MCP initialization, tools listing and a read-only `list_projects` call before declaring client readiness.

Rollback: restore the previous nginx configuration and reload it, then stop only the MCP service. Retain the state volume and previous image. Existing OpenReplay services and data volumes do not need to change.
