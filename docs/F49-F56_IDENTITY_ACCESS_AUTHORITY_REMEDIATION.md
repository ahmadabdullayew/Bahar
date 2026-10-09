# F49–F56 — Independent HTTP Identity, Tenant Scope and Human Authority

**Cumulative baseline:** F08–F48. **Version:** F08–F56. **Status:** implemented and locally tested, awaiting real-provider and PostgreSQL integration qualification.

## Security architecture

Production HTTP requests use independently verified OpenID Connect **API access tokens** (asymmetric RS256 or ES256). Verified `iss`, `sub`, `aud`, `azp` (or `client_id`), `iat`, `nbf`, `exp` and signature establish identity, not authorization. Token lifetimes exceeding 900 seconds are rejected. Signing keys are retrieved only from a configured HTTPS JWKS endpoint on the issuer origin, with a five-minute JWKS-set cache. No HMAC-signed or `alg=none` tokens are accepted. The API audience is required to differ from the public SPA client identifier, preventing accidental use of ID tokens as API credentials.

`auth_actor_memberships(issuer,subject)` resolves active principals to active organization memberships through a read-only, restricted PostgreSQL SECURITY DEFINER function. The API takes `X-Bahar-Tenant` only as a requested selector and checks that it is actually one of those memberships. Role claims in JWTs, request JSON fields, and the environment's bootstrap service principal **never grant authority**. Facility-only grants are not promoted to tenant-wide grants.

A separate `PostgresBaharStore` and `TenantContext(organization_id,principal_id)` is created for each authenticated HTTP request using a shared connection pool, with PostgreSQL `SET LOCAL`-style transaction-scoped RLS context. The server never mutates a shared global user context. The existing service principal is retained only for explicit administration/bootstrap and cannot authenticate browser callers. Role membership and validity are checked again on each request. Privileged DB methods independently check membership at transaction time.

## Endpoint policy

| Route/action | Required role | Fresh external MFA? |
| --- | --- | --- |
| `/api/auth/tenants`, `/api/auth/me` | Valid external identity; selected tenant for `/me` | No |
| `/api/dashboard`, `/api/records/*`, `/api/assessments/*` | At least one tenant-wide read role (auditor, analyst, reviewer, regulatory approver, release authority, incident manager, tenant admin) | No |
| `/api/assess`, `/api/assess/governed`, `/api/ai/audit`, `/api/ai/compare` | analyst | No |
| `/api/documents` | analyst | No |
| Evidence source/assertion/review/correction/coverage writes | reviewer (including source intake requiring qualified custody) | No |
| Governed operational writes | Exact route → operational action → DB role; analyst or reviewer | No |
| `/api/reviews/assign` | tenant_administrator | Yes |
| `/api/reviews/decision` | reviewer; current independent assignee | Yes |
| `/api/reviews/regulatory-decision` | regulatory_approver; independent of reviewer | Yes |
| `/api/releases` | release_authority and all production release prerequisites | Yes |
| `/api/operational/preview` | Public diagnostic, with claim limits | No |
| `/api/demo/*`, `/api/ai/lookup`, `/api/ai/identity`, `/api/health` | Public and non-authoritative | No |

The earlier `/api/operational/records` endpoint remains a local SQLite diagnostic and is **not** available as a production write route; its access is not misleadingly granted by the new policy. Routes not on the explicit write policy cannot be invoked as writes. Sensitive GET routes require authentication. The Content Security Policy permits cross-origin browser token exchange only to the trusted configured HTTPS issuer origin. The response from `/api/auth/me` contains real roles and permitted write routes so the UI can disable unavailable actions; these display controls do not replace server enforcement. For security simplicity **facility-scoped roles are read-only metadata in this release** and cannot authorize an organization-wide operation. Genuine facility-scoped RBAC needs facility-to-record authorization and its own test suite.

## Qualified review workflow

`/api/reviewers` exposes only currently appointed tenant-wide reviewers to the tenant administrator, for selection through the assignment form. `/api/reviews/assign` appoints a valid, active, tenant-wide reviewer who must be distinct from the assessment author and assigning administrator. The assessment author is recovered from the tenant's append-only audit stream. The assignment is immutable per assessment in the current build; assignment turnover needs a separately governed replacement procedure rather than silent editing. `/api/reviews/decision` accepts `accepted_for_review`, `rejected`, or `needs_changes`, preserving the assessed input digest and actor. A reviewer cannot provide positive acceptance unless `technical_readiness=ready_for_review`.

`/api/reviews/regulatory-decision` requires a current positive reviewer decision, a different regulatory approver, and an explicit decision/reason. It **does not** certify label compliance or authorize product release. `/api/releases` derives actor and role from the verified HTTP context, not the request. It additionally requires current, digest-matching, correctly ordered reviewer and regulatory decisions and **three distinct people** across review, regulatory approval, and release authority; the previous production evidence, source-custody, release-scope, freshness, and change-continuity gates still apply. A browser cannot convert a demo assessment into a release. All decisions and role checks are performed inside tenant-scoped PostgreSQL transactions, with audit events.

**Limitation:** This release records assignment, review, regulatory approval and release requests. It does not implement a full e-signature standard, emergency access, recertification workflow, organizational onboarding interface, delegation/leave cover, or user administration. Roles and principal records are provisioned by a separate administrator, never via untrusted browser input.

## Identity-provider setup

1. Deploy a trusted provider such as Keycloak or a corporate OpenID Connect IdP, with a **public SPA** configured for Authorization Code + **PKCE S256**, no implicit flow, strict registered HTTPS redirect URI, and appropriate CORS for its token endpoint. Configure access tokens with the **API audience** `bahar-api` AND the authorized-client claim `azp=bahar-spa-public` (or `client_id` equal to your SPA client). An ID token for the SPA, or an API token issued to a different client, is insufficient.
2. Configure issuer, JWKS, authorize, token, client ID, audience, redirect URI, and approved MFA ACR values in `.env` as documented in `.env.example`. Production start **fails closed** if these settings are missing or if URLs do not satisfy HTTPS/origin checks. The bundled server binds only to loopback by default. The Compose deployment explicitly permits private-container 0.0.0.0 binding while mapping its exposed host port to 127.0.0.1. A correctly configured public HTTPS reverse proxy is mandatory for browser SSO; never publish that internal HTTP port directly.
3. Enable provider-enforced MFA and include `auth_time` and trustworthy `amr` or `acr` claims in signed API access tokens. For privileged operations, the API validates verified MFA and recent authentication (default 300 seconds). A button requesting `prompt=login&max_age=0` does not itself guarantee MFA; provider policy must enforce it.
4. Apply Alembic revision `0004_oidc_actor_lookup`, under a trusted DB migration administrator. Provision matching `principals(issuer,subject)` and `memberships(organization_id,principal_id,role_name)` with a separate audited administrator procedure. Do not reuse the local bootstrap fixture as a real person.
5. Load the browser over HTTPS. Click **Sign in with organization SSO**, select an authorized organization, and execute only the enabled actions. Tokens remain in volatile JS memory, not cookies or localStorage. Only the short-lived PKCE verifier/state are stored in sessionStorage; reload requires fresh login. Sign out erases the local token, **but is not global IdP logout or immediate token revocation**.
6. Run the security acceptance suite with a real OIDC provider, at least two actual PostgreSQL tenants, distinct analyst/reviewer/regulatory/release identities, and invalid/expired/revoked identities. Verify RLS, changed memberships, DB transaction failures, review sequence, reauthentication/MFA, and zero data leakage across tenants.

## What has and has not been proven

**Locally tested:** signature and claims rejection; incorrect audience/issuer, forged role claims, unassigned tenant, facility roles, token lifetime, expired access token, required fresh MFA, role-specific operation blocking, and request-scoped tenant/principal binding. Existing pre-F49 tests remain passing.

**Not independently validated:** live IdP deployment and JWKS key rotation/revocation behavior; IdP CORS/PKCE configuration; real MFA provider policy; full PostgreSQL migration and two-tenant RLS integration; performance under simultaneous memberships; full UI browser automation against live SSO; operator onboarding; security penetration test. No such evidence is claimed. The existing five PostgreSQL integration tests are still skipped in the absence of `BAHAR_TEST_DATABASE_URL`.

**Production safety rule:** The mere presence of this authentication component must not lift the domain/regulatory restrictions, F01–F07 unresolved assessment defects, or missing evidence qualification. Successful login conveys identity, never truth or release authority.
