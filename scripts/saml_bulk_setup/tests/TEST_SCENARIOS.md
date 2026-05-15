# Test scenarios — `arize_saml_bulk_setup.py`

Checklist to walk before pushing changes. Sections **1–8** map 1:1 to a test file under `tests/`; section **9** lists scenarios that require a live Arize account and stay manual.

> **Automated coverage**: scenarios marked ✅ are covered by `tests/` — run `pip install -r tests/requirements.txt && pytest tests/` from this directory. The rest require a live Arize test account.

> Conventions used below
> - "Test account" = a non-production Arize account you can mutate freely.
> - "Clean account" = a test account with **no SAML IdP** configured yet.
> - "Configured account" = a test account with an existing SAML IdP and at least one mapping.
> - "Custom-role account" = a test account that already has at least one custom RBAC role defined (e.g. `Project Reviewer`).

---

## 1. CSV parsing — [`tests/test_csv_io.py`](./tests/test_csv_io.py)

Edge cases around how `load_csv` handles bad input. No API calls; pure file I/O.

| # | ✅ | Setup | Command | Expected |
|---|---|---|---|---|
| 1.1 | ✅ | No file at the given path | `python arize_saml_bulk_setup.py --csv ./does_not_exist.csv --dry-run` | stderr: `ERROR: CSV file not found: ./does_not_exist.csv`; exit 1 |
| 1.2 | ✅ | Empty file (`touch empty.csv`) | `... --csv ./empty.csv --dry-run` | stderr: `ERROR: CSV file is empty.`; exit 1 |
| 1.3 | ✅ | CSV missing a required column | `... --csv ./missing_col.csv --dry-run` | stderr lists the missing column; exit 1 |
| 1.4 | ✅ | CSV with whitespace-only rows between data rows | `... --dry-run` | Blank rows skipped silently; only real rows appear in results CSV |

---

## 2. Row validation — [`tests/test_validation.py`](./tests/test_validation.py)

`_validate_row` and `_classify_space_role` from `runner.py`. Pure helpers, no I/O.

| # | ✅ | Setup | Command | Expected |
|---|---|---|---|---|
| 2.1 | ✅ | Row with any required field blank (`space`, `organization`, etc.) | `... --dry-run` | That row: `status=error`, message lists the missing field |
| 2.2 | ✅ | Row with `arize_org_role` outside {admin, member, viewer, annotator} | `... --dry-run` | That row: `status=error`, message references valid roles |
| 2.3 | ✅ | Row with `arize_org_role=admin` and a non-empty `arize_space_role` | `... --dry-run` | That row: `status=error`, message explains admin shouldn't have a space role |
| 2.4 | ✅ | Row with builtin `arize_space_role` (admin/member/viewer/annotator, any case) | `... --dry-run` | Classified as legacy `spaceRolesMap` role; viewer translated to `readOnly` |
| 2.5 | ✅ | Row with blank `arize_space_role` | `... --dry-run` | Classified as inherited (both space_role + space_rbac_role_id empty) |
| 2.6 | ✅ | Row with non-builtin `arize_space_role` (e.g. `Project Reviewer`) | `... --dry-run` | Classified as custom RBAC; deferred to `RolesCache` for relay-ID resolution |

---

## 3. CLI parsing & env vars — [`tests/test_cli.py`](./tests/test_cli.py)

`build_parser()` + `resolve_api_key()`. No runner construction.

| # | ✅ | Setup | Command | Expected |
|---|---|---|---|---|
| 3.1 | ✅ | No env, no flag | `unset ARIZE_API_KEY ARIZE_DEVELOPER_KEY; python arize_saml_bulk_setup.py --csv ./x.csv` | stderr: `ERROR: No API key provided...`; exit 1 |
| 3.2 | ✅ | `ARIZE_API_KEY` env set | `export ARIZE_API_KEY=valid_key; python ...` | Key resolved from env |
| 3.3 | ✅ | `ARIZE_DEVELOPER_KEY` env set (legacy name) | `export ARIZE_DEVELOPER_KEY=valid_key; python ...` | Key resolved from env |
| 3.4 | ✅ | Both `--saml-metadata-url` and `--saml-metadata-xml` | `... --saml-metadata-url u --saml-metadata-xml x ...` | `main()` rejects with mutex error |
| 3.5 | ✅ | `--output custom.csv` | `... --output ./custom_results.csv ...` | Results land in `./custom_results.csv`, not the default |

---

## 4. Retry / rate-limit — [`tests/test_retry.py`](./tests/test_retry.py)

`with_retry()` behaviour on transient vs permanent errors.

| # | ✅ | Setup | Command | Expected |
|---|---|---|---|---|
| 4.1 | ✅ | Function raises `429 Too Many Requests` once, then succeeds | run | Log contains `Rate limit hit for '<op>' (attempt 1/5). Retrying in 1.0s…`; call returns the success value |
| 4.2 | ✅ | Function raises 429 on every attempt | run | After `MAX_RETRIES` attempts, the 429 is raised to the caller |
| 4.3 | ✅ | Function raises a non-rate-limit error (e.g. `ValueError`) | run | No retries; error surfaces immediately |

---

## 5. Custom RBAC roles (RolesCache) — [`tests/test_roles.py`](./tests/test_roles.py)

`RolesCache.resolve_custom_space_role()` against a mocked `/v2/roles` endpoint.

| # | ✅ | Setup | Command | Expected |
|---|---|---|---|---|
| 5.1 | ✅ | Valid custom role name; cache empty on first call | `... --csv custom.csv` | Row: `created`; in Arize UI, the mapping appears under `spaceRbacRolesMap` with the correct role |
| 5.2 | ✅ | Custom role name in different case (e.g. `project reviewer`) | `... --csv case.csv` | Resolved case-insensitively to the right relay ID |
| 5.3 | ✅ | Custom role name misspelled (`Project Reveiwer`) | `... --csv typo.csv` | Row: `error`, message includes the list of available roles |
| 5.4 | ✅ | Caller supplies a relay role ID (`Um9sZTo…`) directly | run | Validated against the cache, passed through unchanged |
| 5.5 | ✅ | `/v2/roles` returns 429 once, then 200 | run | Retry fires (regression — used to be silently broken) |

---

## 6. Preflight conflict resolution — [`tests/test_preflight.py`](./tests/test_preflight.py)

`resolve_role_type_conflicts()`. Arize allows only one role type (standard OR custom) per space.

| # | ✅ | Setup | Command | Expected |
|---|---|---|---|---|
| 6.1 | ✅ | CSV with two rows for the same space: one builtin, one custom | Real run | Both rows: `status=error`, message mentions both row numbers and tells user to pick one role type; no API write; exit 1 |
| 6.2 | ✅ | IdP already has space `S` under `spaceRolesMap`; CSV asks for a custom role on `S` | `... --csv migrate.csv` | New row: `created`; old `S→admin` entry stripped from `spaceRolesMap`. Other spaces on the same mapping unchanged. |
| 6.3 | ✅ | Reverse: IdP has `spaceRbacRolesMap` entry for `S`; CSV asks for builtin on `S` | `... --csv migrate.csv` | Migration works the other direction |
| 6.4 | ✅ | CSV has one row exactly matching an existing entry for space `S` (`already_exists`) plus a second row asking for the **other** role type on `S` | `... --csv tricky.csv` | Preflight detects the contradiction via `_exact_match_uses`; both contributing rows fail; the optimistic `mappings_existed` counter is rolled back |

---

## 7. SAML IdP service — [`tests/test_saml.py`](./tests/test_saml.py)

`SamlIdpService.ensure_loaded()` and `flush()` against a stubbed GraphQL executor.

| # | ✅ | Setup | Command | Expected |
|---|---|---|---|---|
| 7.1 | ✅ | Clean account; no `--email-domains`, no metadata | `python arize_saml_bulk_setup.py --csv ./saml_mappings.csv` | First row to reach the SAML step: `error`, message tells user to provide `--email-domains` and `--saml-metadata-url`/`--saml-metadata-xml`; exit 1 |
| 7.2 | ✅ | Clean account; `--email-domains` provided but no metadata | run | `error`: "No SAML IdP found and no metadata supplied" |
| 7.3 | ✅ | Clean account; `--email-domains` + `--saml-metadata-url` | run | `createSAMLIdP` called with the URL + all collected mappings in one call; logs include `Creating SAMLIdP…` |
| 7.4 | ✅ | Same as 7.3 but with `--saml-metadata-xml '<xml>...'` | run | `createSAMLIdP` called with `metadataXml`; custom-role rows route to `spaceRbacRolesMap`, not `spaceRolesMap` |
| 7.5 | ✅ | Configured account with `enforceSaml=false`; run with `--enforce-saml` | `... --csv minimal.csv --enforce-saml` | After update, `enforceSaml=true` |
| 7.6 | ✅ | Same shape for `--sync-user-roles`, `--sign-authn` | as above | Flag flips to true |
| 7.7 | ✅ | Configured account with `enforceSaml=true`; run **without** `--enforce-saml` | `... --csv minimal.csv` | `enforceSaml` still `true` (preserved, not clobbered to false) |

---

## 8. Runner orchestration — [`tests/test_runner.py`](./tests/test_runner.py)

End-to-end `BulkSetupRunner.run()` with mocked `ArizeClient` and a stubbed SAML executor.

| # | ✅ | Setup | Command | Expected |
|---|---|---|---|---|
| 8.1 | ✅ | Configured account, dry-run, multiple CSV rows | `... --csv ./template.csv --dry-run --verbose` | All rows: `status=dry_run`; no `createSAMLIdP`/`updateSAMLIdP` calls issued |
| 8.2 | ✅ | Dry-run with one cached org + one new org | `... --dry-run` | Counters: `orgs_existed=1`, `orgs_created=1`; same shape for spaces |
| 8.3 | ✅ | `--verbose` toggles logger level | `... --verbose` | Logger at DEBUG instead of INFO |
| 8.4 | ✅ | `updateSAMLIdP` returns an error response | run | All previously `created` rows flip to `error` with message `SAML update failed: …`; exit 1 |
| 8.5 | ✅ | Flush failure on a batch that includes a pre-flush validation error | run | Pre-flush error message preserved (not overwritten by the flush-failure rollback) |
| 8.6 | ✅ | No SAML IdP on the account AND no `--email-domains` / metadata args | run | Single ERROR log line ("No SAML IdP found…") — not per row. Exactly one `getSAMLIdP` API call, not one per row. Every row in the results CSV carries the same actionable error. |
| 8.7 | ✅ | `getSAMLIdP` raises a non-RuntimeError (e.g. transport/auth error) during pre-flight | run | Distinct error message `Could not load SAML configuration from Arize: <reason>` — separate from the "IdP doesn't exist" path. Single log line, every row marked error. |
| 8.8 | ✅ | `POST /v2/organizations` returns a persistent server error (e.g. 500). Multiple CSV rows reference the same org name. | run | First row: original error message. Subsequent rows referencing the same org: `Earlier attempt to create organization '<name>' failed: <original>` — no repeated API call. Same shape applies to `POST /v2/spaces`. |
| 8.9 | ✅ | A row hits an unexpected error during processing | run at INFO (default) vs `--verbose` | INFO: single-line `ERROR Row N failed: <message>` with no traceback. `--verbose`: same message **plus** the Python traceback for debugging. |

---

## 9. Manual-only scenarios (live test account required)

These exercise live backend state — mocking them would just test the mocks. Walk through each one when the corresponding code area changed.

| # | Setup | Command | Expected |
|---|---|---|---|
| 9.1 | Configured account, run a fresh CSV, then re-run it without changes | `python arize_saml_bulk_setup.py --csv ./saml_mappings.csv` (twice) | First run: each row `created` or `already_exists`. Second run: every row `already_exists`; summary shows 0 created; exit 0 |
| 9.2 | After 9.1, add one new row to the same CSV and re-run | `... --csv ./saml_mappings.csv` | Only the new row: `created`; others: `already_exists` |
| 9.3 | Custom-role account: CSV row with a valid custom role, run twice | `... --csv custom.csv` (twice) | Second run: `already_exists` (exercises the live `mapping_exists` check against `spaceRbacRolesMap`) |
| 9.4 | Test EU account | `... --arize-url https://app.arize-eu.com --csv ./eu.csv` | Toolkit + REST calls hit the EU host (verify via network capture). `GET /v2/roles` still targets `https://api.arize.com` — this URL is intentionally not parameterized; flag if a customer hits this |

---

## Exit codes (covered implicitly above, listed for reference)

- All rows `created` / `already_exists` / `dry_run` → exit **0**
- Any row `error` → exit **1**

---

## Quick reference — minimal valid CSV

```csv
organization,space,arize_org_role,arize_space_role,saml_attribute_name,saml_attribute_value
Test Org,Test Space,member,,groups,arize-test-group
```

Use this for scenarios 7.5–7.7 and 8.4 where only one mapping is needed.
