# F49–F56 Verification Report

**Build:** Cumulative F08–F56 source package. The code modifications do not mutate the earlier F08–F48 source archive.

| ID | Implemented correction | Verification disposition |
|---|---|---|
| F49 | Strict OIDC access-token authentication for production HTTP | Cryptographic positive and negative unit tests pass; live IdP pending |
| F50 | Request-specific actor/tenant context; no fallback to environment principal | Unit tests confirm request context; PostgreSQL end-to-end pending |
| F51 | Release identity and role are derived server-side from verified actor; body role/actor rejected | Tampering test passes; release database integration pending |
| F52 | Tenant selected only from valid memberships; RLS bound per request; facility grants not elevated | Cross-tenant selection unit tests pass; actual two-tenant PostgreSQL test pending |
| F53 | Role-restricted browser UI, tenant-scoped reviewer directory, independent reviewer assignment, reviewer/regulatory decision, release request | Browser syntax/verification passes; full SSO E2E and DB review integration pending |
| F54 | No service-principal HTTP authority; production OIDC required at startup; private-container/loopback binding | Startup configuration and request denial tests pass |
| F55 | Trusted external OIDC PKCE; expiring API JWTs; local logout; privilege-specific fresh MFA | Signature/audience/issuer/client/MFA/timing tests pass; actual provider configuration pending |
| F56 | Deny-by-default HTTP action/role matrix and PostgreSQL role verification | Exact-path matrix and privilege-escalation tests pass; facility-specific RBAC intentionally not implemented |

**Tests (current environment):** `136 passed, 5 skipped` using `PYTHONPATH=src pytest -q`.
Five integration tests are skipped because `BAHAR_TEST_DATABASE_URL` is missing. JavaScript syntax validation (`node --check`) and the existing offline responsive frontend verifier pass.

**Security limitations:** External provider account provisioning, actual second-tenant DB RLS coverage, database migration execution, full review and release transactions against PostgreSQL, provider JWKS rollover and revocation exercises, administrator onboarding, cross-domain browser OAuth CORS behavior, full penetration testing, and recovery procedures have **not** been independently verified. JWT logout is local-only; provider access tokens remain usable until their short expiry unless the issuer revokes credentials independently. These are qualification blockers, not accomplished test results.

**Claim boundary:** This patch provides conditional software identity and authorization enforcement; it does not establish food-safety, domain, legal, or manufacturing regulatory compliance, or resolve the earlier F01–F07 defects.
