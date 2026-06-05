# OSDU Web Console

Flask operational UI for two OSDU workflows:

- **OSDU Data Catalog**: browse configured OSDU domains and entity kinds, search records, open record detail, view governance metadata, export/download JSON/CSV, and soft-delete records when the active token has permission.
- **OSDU Access Governance**: review Entitlements groups and members, Legal Tags, partitions, local ACL policy workspace, local audit logs, and record access explanations.

OSDU Core Services, Keycloak, Entitlements, Legal, Search, and Storage remain the source of truth. This app is only an operational console.

## Auth Flow

When no valid token is available, the app redirects every protected HTML route to **Connect to OSDU**.

Supported modes:

- **Service Account**: uses configured `OSDU_CLIENT_ID` and `OSDU_CLIENT_SECRET` from environment or `.env`. The client secret is never shown or entered in the UI.
- **User Login**: uses password grant with username/email and password. The password is used only for the runtime token request and is not written to disk.

Advanced settings are collapsed by default:

- OSDU base URL
- Partition
- Token endpoint
- Keycloak admin base URL and realm, used only when syncing users from external IAM
- SSL verify

After a token is ready, the user lands on the home dashboard with cards for Data Catalog and Access Governance. The global top bar shows token status, auth mode, identity, partition, and **Switch**.

## Environment

Create `.env` from `.env.example` and set deployment-specific values.

```env
OSDU_BASE_URL=https://osdu.example.com
OSDU_PARTITION_ID=osdu
OSDU_TOKEN_ENDPOINT=https://keycloak.example.com/realms/osdu/protocol/openid-connect/token
OSDU_CLIENT_ID=datafier
OSDU_CLIENT_SECRET=...
OSDU_VERIFY_SSL=True
```

Service account:

```env
OSDU_TOKEN_GRANT_TYPE=client_credentials
```

User login:

```env
OSDU_TOKEN_GRANT_TYPE=password
OSDU_USERNAME=user@example.com
OSDU_PASSWORD=...
OSDU_TOKEN_SCOPE=openid profile email
```

For Keycloak password grant, the client must allow Direct Access Grants.

## Run

```bash
pip install -r requirements.txt
python app.py
```

Open:

```text
http://localhost:5000
```

## Koyeb Deployment

Use **Buildpack** deployment. No Dockerfile or Procfile is required.

Recommended Koyeb settings:

- Builder: `Buildpack`
- Build command: leave empty
- Run command: `gunicorn -w 2 -b 0.0.0.0:$PORT app:app`
- Work directory: set to `osdu_view` when deploying this full repository; leave empty only if `osdu_view` is the repository root.
- Health check port: use Koyeb's exposed service port/`$PORT`

Set these variables in Koyeb **Environment Variables**. You can use your real local `.env` values as reference, but do not commit `.env`.

```env
FLASK_ENV=production
FLASK_DEBUG=False
OSDU_BASE_HOST=osdu.example.com
OSDU_BASE_URL=http://osdu.example.com
OSDU_PARTITION_ID=osdu
OSDU_TOKEN_ENDPOINT=http://keycloak.example.com/realms/osdu/protocol/openid-connect/token
OSDU_TOKEN_HOST=keycloak.example.com
OSDU_TOKEN_GRANT_TYPE=client_credentials
OSDU_CLIENT_ID=...
OSDU_CLIENT_SECRET=...
OSDU_VERIFY_SSL=False
OSDU_ENTITLEMENTS_BASE_PATH=/api/entitlements/v2
OSDU_LEGAL_BASE_PATH=/api/legal/v1
OSDU_PARTITION_BASE_PATH=/api/partition/v1
OSDU_STORAGE_BASE_PATH=/api/storage/v2
```

Optional variables:

```env
OSDU_BASE_HOST=
OSDU_TOKEN_HOST=
OSDU_AUTH_BASE_URL=
OSDU_AUTH_REALM=
OSDU_GROUP_SCAN_LIMIT=5000
OSDU_TIMEOUT_SECONDS=30
WEB_CONCURRENCY=2
```

## Main Routes

- `GET /`
- `GET /home`
- `GET /connect`
- `GET /auth`
- `GET /data-catalog`
- `GET /catalog`
- `GET /domain/{domain}`
- `GET /records/{domain}/{entity}`
- `GET /record/{record_id}`
- `GET /governance`
- `GET /access-governance`
- `GET /access-control`
- `GET /governance/groups`
- `GET /governance/legal-tags`
- `GET /governance/access-checker`
- `GET /api/config`
- `GET /api/auth/status`
- `POST /api/auth/connect`
- `POST /api/auth/token`
- `GET /api/records/{domain}/{entity}`
- `GET /api/record/{record_id}`
- `POST /api/delete-record/{record_id}`
- `POST /api/bulk-delete-records`
- `GET /api/access-control/groups`
- `GET /api/access-control/groups/{group_email}/members`
- `GET /api/access-control/users`
- `GET /api/access-control/users/{user_email}/groups`
- `GET /api/access-control/legal-tags`
- `POST /api/access-control/legal-tags`
- `DELETE /api/access-control/legal-tags/{legal_tag_name}`
- `POST /api/access-control/check`

## Inspect User Group Membership

Access Governance > Users can inspect a specific user's OSDU Entitlements membership.

- Enter an email manually and click **Load groups**.
- If Keycloak Admin user listing is configured, click **Sync from Keycloak** first, then use **View Groups** on a user row.
- The source of truth is OSDU Entitlements group membership, not the local browser registry.
- If Keycloak Admin API is unavailable, user listing may be empty, but manual email inspection still works.
- The active token needs enough Entitlements permission to list groups and group members.
- If Entitlements returns 403, the UI shows: `Current token cannot inspect user group membership.`
- From Groups > group detail, use **View user groups** on a member row to open Users and inspect that member.

## Access Governance - Entitlements Administration

Access Governance uses OSDU Entitlements as the source of truth for authorization groups and membership. Keycloak is only used for authentication and token issuance.

- Groups page can list OSDU Entitlements groups, create a group, open group detail, view members, and add a member.
- Users page can inspect a user email and show which OSDU Entitlements groups that user belongs to.
- Users page can add the inspected user to a group by entering the full Entitlements group name.
- Group types are inferred from group name prefixes: `data.` => DATA, `users.` => USER, `service.` => SERVICE, otherwise UNKNOWN.
- Creating groups and adding members require an active token with Entitlements admin permission.
- If the active token lacks permission, mutation APIs return 403 and the UI shows a clear Entitlements permission error.
- The app does not create Keycloak users, does not use Keycloak Groups for OSDU authorization, and does not create default groups on startup.

## Notes

- Do not commit production secrets.
- `.env.example` contains placeholders only; set real values through local `.env`, Koyeb, or CI/CD secret variables.
- `.token_cache` is keyed by token endpoint, grant type, client id, and username to avoid reusing a token across auth contexts.
- Access Checker is read-only and explains local ACL/legal matching. OPA and full service permission evaluation are not performed by the local checker.
