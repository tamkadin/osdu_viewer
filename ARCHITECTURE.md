# OSDU Web Console Architecture

## 1. Purpose

This web console combines two OSDU workflows in one Flask application:

- **OSDU Data Catalog**: browse domains, entity kinds, records, and record details.
- **OSDU Access Governance**: inspect OSDU access governance data such as groups, members, legal tags, ACL policies, and record access decisions.

The application is designed as a lightweight operational UI. It does not replace Keycloak, OSDU Entitlements, Legal, Search, or Storage. Those services remain the source of truth.

## 2. Runtime Architecture

```text
Browser
  |
  | HTML + JS fetch
  v
Flask app
  |-- app.py
  |-- config.py
  |-- token_manager.py
  |-- access_control.py
  |-- domains.py
  |
  | Authorization: Bearer <token>
  | data-partition-id: <partition>
  v
OSDU Core Services
  |-- Search API
  |-- Storage API
  |-- Entitlements API
  |-- Legal API
  |-- Partition API
  |
  v
Keycloak token endpoint
```

## 3. Main Modules

### `app.py`

Main Flask entry point.

Responsibilities:

- Defines HTML routes.
- Defines JSON API routes.
- Initializes and rebuilds `TokenManager`.
- Gates data APIs when no valid token is available.
- Keeps the old Data Viewer search/detail/delete logic intact.
- Wires Access Control APIs to `AccessControlService`.

### `config.py`

Environment configuration layer.

Responsibilities:

- Loads `.env`.
- Reads deploy-time environment variables.
- Supports runtime overrides from the Auth popup without writing secrets to disk.
- Provides masked config summaries for UI.
- Keeps Koyeb/CI/CD deploy compatible by avoiding code-level environment hard-coding.

### `token_manager.py`

OSDU token manager.

Responsibilities:

- Supports `client_credentials`.
- Supports `password` grant for delegated user access.
- Supports optional refresh token.
- Caches token in memory and `.token_cache`.
- Avoids reusing token cache across different grant/client/user contexts.

### `access_control.py`

Read-only OSDU access-control facade.

Responsibilities:

- Lists partitions.
- Lists Entitlements groups.
- Lists group members.
- Lists Legal Tags.
- Reads record ACL from Storage.
- Explains access decisions by matching user groups against `acl.viewers` and `acl.owners`.

### `domains.py`

Domain/entity registry for Data Viewer.

Responsibilities:

- Defines supported OSDU domains.
- Defines entity names, kinds, descriptions, and display fields.

## 4. UI Architecture

The UI uses a full-screen operational layout.

```text
Top navigation
  |-- OSDU Data Catalog
  |-- OSDU Access Governance
  |-- Token status
  |-- Auth button

Auth modal
  |-- Service account mode
  |-- User login mode
  |-- Advanced environment override

Data Catalog shell
  |-- Left domain sidebar
  |-- Main browse/search/record workspace

Access Governance shell
  |-- Left admin sidebar
  |-- Dashboard
  |-- Users
  |-- Partitions
  |-- Groups
  |-- Legal Tags
  |-- ACL Policies
  |-- Access Checker
  |-- Audit Logs
```

### Auth Modal

Auth is a popup gate, not a permanent tab.

Service account mode:

- Uses configured `OSDU_CLIENT_ID`.
- Uses configured `OSDU_CLIENT_SECRET`.
- User does not need to type client credentials.

User login mode:

- Uses configured client.
- User enters username/email and password.
- Requires Keycloak Direct Access Grants to be enabled for the client.

Advanced settings are hidden by default:

- OSDU base URL.
- Partition.
- Token endpoint.

These values normally come from `.env` or deploy environment variables.

## 5. Configuration

Local runtime uses `.env`.

Important variables:

```env
OSDU_BASE_URL=https://osdu.example.com
OSDU_PARTITION_ID=osdu
OSDU_DATA_PARTITION_ID=osdu

OSDU_AUTH_URL=https://keycloak.example.com/realms/osdu/protocol/openid-connect/token
OSDU_TOKEN_ENDPOINT=https://keycloak.example.com/realms/osdu/protocol/openid-connect/token

OSDU_TOKEN_GRANT_TYPE=client_credentials
OSDU_CLIENT_ID=datafier
OSDU_CLIENT_SECRET=...
```

For deployment, set the same variables in Koyeb or CI/CD environment settings.

Do not put production secrets in `.env.example`.

## 6. Request Flow

### Data Viewer Search

```text
User opens Data Viewer
  -> chooses domain/entity kind
  -> browser calls /api/records/{domain}/{entity}
  -> Flask resolves OSDU kind from domains.py
  -> TokenManager returns access token
  -> Flask calls OSDU Search API
  -> browser renders records
```

### Record Detail

```text
User opens record
  -> browser calls /api/record/{record_id}
  -> Flask attempts Storage API strategies
  -> fallback search retrieval if needed
  -> browser renders JSON/table/tree view
```

### Access Governance Groups

```text
User opens Groups section
  -> browser calls /api/access-control/groups
  -> AccessControlService calls OSDU Entitlements
  -> browser renders group table
```

### Access Checker

```text
User enters record id and user/group context
  -> browser calls /api/access-control/check
  -> Flask reads record from Storage
  -> Flask compares user groups with acl.viewers and acl.owners
  -> browser displays allow/deny explanation
```

## 7. Data Ownership

OSDU source of truth:

- Partitions.
- Entitlements groups.
- Group members.
- Legal Tags.
- Storage records.
- Record ACLs.

Local/browser-only workspace:

- Users section local registry.
- ACL policy templates.
- Audit logs.

These local sections are UI workspaces for BA/admin workflows and do not mutate OSDU unless explicit backend API support is added later.

## 8. Security Notes

- Access tokens are retrieved server-side.
- Client secret should come from environment variables.
- `.env.example` must not contain real secrets.
- User password grant requires Keycloak Direct Access Grants.
- For production web login, Authorization Code + PKCE is preferred over password grant.
- Token status is shown globally in the top navigation.

## 9. Deployment Model

Simple deployment:

```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

Koyeb deployment:

1. Push source to GitHub.
2. Configure build/run command.
3. Set all OSDU variables in Koyeb Environment Variables.
4. Keep `FLASK_DEBUG=False`.
5. Set `OSDU_VERIFY_SSL=True` for valid HTTPS certificates.

## 10. Extension Points

Possible future improvements:

- Persist Users, ACL Policies, and Audit Logs in PostgreSQL.
- Add create/update/delete APIs for Entitlements groups and members.
- Add Keycloak Admin API user sync.
- Add Legal Tag create/update workflows.
- Replace password grant with Authorization Code + PKCE.
- Add role-based protection for admin actions.

## 11. Non-Goals

Current application does not:

- Replace Keycloak user management.
- Replace OSDU Entitlements administration fully.
- Persist local admin workspace data server-side.
- Implement production SSO.
- Automatically create OSDU groups, legal tags, or partitions at startup.
