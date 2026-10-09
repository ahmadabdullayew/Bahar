# Bahar frontend implementation and verification — 2026-10-09

## What this revision changes

This revision follows the supplied frontend weakness audit and the original Bahar application design. The existing dark-green / warm-neutral color system, card layout, typography families, domain navigation names, and source-data model remain intact. The FoodChain ID “Targets!” article was used as a reference for responsive content hierarchy and menu clarity; its proprietary branding, text, and page layout have not been copied.

### Implemented

1. Addressable hash navigation with current-page semantics; mobile menu button, expanded-state semantics, and keyboard-focused headings.
2. WCAG-targeted text contrast adjustments, skip navigation, visible keyboard focus, reduced-motion support, labeled rules input, and persistent contextual failures.
3. Responsive rendering verified in a mocked Chromium browser at 320, 390, 768, 1024, and 1440 CSS pixels.
4. All nine dashboard counters rendered, rather than truncating the ninth.
5. A side-by-side comparison of the user-submitted formulation and label text, with bounded candidate-span highlighting and explicit limits on its evidentiary status.
6. Assessment summaries distinguishing execution state, technical readiness, reported findings, coverage, and knowledge limitations. JSON remains available in an expandable diagnostic view. Findings explain their scope and lack of automatic legal authority.
7. Rules-workbench results summarized similarly instead of being available solely as JSON.
8. Structured human-editable fields generated from existing JSON templates, including object groups, boolean/number/date controls and live suggestions for organization-scoped foreign-key references. Advanced JSON remains optional. This is an ergonomic improvement, **not** an independently validated domain-specific form-schema system.
9. Navigable, searchable server-side record pages, with bounded organization-scoped queries, next/previous controls and record-details expansion. The server enforces a maximum page size.
10. Distinct states for record commit and post-commit list refresh. A refresh failure cannot silently turn a committed write into an unqualified "submission failed" notice.
11. Latest-attempt assessment result handling: failed runs are not represented as successful current results. Historical output is visibly marked historical.
12. Request timeouts, latest-lookup sequencing, busy states, non-transient error banners, and independent dashboard/health handling.
13. Document ingestion feedback distinguishes stored artifact acceptance from successful extraction, failed extraction, or unsupported extraction. Optional supplier, valid-date, and applicable-lot metadata can now be provided at ingestion. An 18 MiB browser-side size guard prevents known base64 / 25 MiB JSON-body limit mismatches. **Binary streaming and resumable uploads are not implemented.**
14. Explicit JSON-scoped report export for completed assessment results. It is **not** a regulatory or release certificate.
15. A no-storage unsaved-form unload warning; no sensitive source data is automatically placed in localStorage or sessionStorage.
16. Browser regression test harness and source-level bounded-pagination tests.

### Known remaining scope

The code does **not** establish a complete regulated production frontend. The following still require authoritative backend workflows and independent qualification before production use:

- Authenticated real-user roles, effective multi-tenant identity in HTTP requests, permission-aware actions, and review/approval UI.
- A source-document retrieval/viewing API and a governed reviewable viewer for PDF/OCR/artwork with evidence-region overlays.
- Server-governed evidence adjudication, legally approved rule packages, and fully traceable artifact-to-claim-to-finding relationships.
- Domain-specific typed forms that enforce all required business invariants, including full nested relational entities, draft lifecycle and transaction consequences.
- Binary chunked/resumable ingestion, cancellation of server-side tasks, and upload-progress telemetry.
- Live PostgreSQL integration, accessible assistive-technology user tests, multi-browser testing, localization, large-dataset load tests, and real-data benchmark validation.
- Previously reported assessment-engine trust-boundary findings (F-01 through F-06). This frontend revision does not purport to fix backend decision logic.

## Verification

Run from project root:

```bash
PYTHONPATH=src python -m pytest -q
python scripts/verify_frontend.py
node --check web/app.js
python -m compileall -q src
```

Browser verification uses isolated mock APIs and Chromium. It is independent of PostgreSQL and therefore **does not establish integrated deployment behavior**. Screenshots under `artifacts/` are mocked-workflow captures.

At the time of this packaging, `53` unit tests passed; the `5` PostgreSQL integration tests were skipped because the required database environment variable was not configured. The browser-script checks passed at all five viewport widths listed above. Running `docker compose up` and repeating integration verification remains necessary in an actual deployment environment.

## Reference material

- FoodChain ID, *Tackling Food Labeling Challenges with a Friendly Helper: “Targets!”*, 2025: https://www.foodchainid.com/resources/tackling-food-labelling-challenges-with-targets/
- W3C Web Accessibility Initiative, Menu Structure: https://www.w3.org/WAI/tutorials/menus/structure/
- W3C WCAG 2.2: https://www.w3.org/TR/WCAG22/
- OWASP, Cross Site Scripting Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- ISO 9241-110:2020, interaction principles (standard listing).

No website content or logos from FoodChain ID are distributed in this application.
