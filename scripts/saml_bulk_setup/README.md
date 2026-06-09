# Bulk SAML setup for Arize

Use this tool to provision your Arize account from a single CSV file. It supports two modes:

- **SAML group mapping** (default) — create organizations and spaces, and set up SAML group-to-role rules so users automatically receive the right access when they log in via SSO.
- **SAML + private project assignment** (`--project-assign`) — everything above, plus: create restricted (private) projects and assign specific users to them by email address. Use this when you need fine-grained project-level access control that SAML groups alone cannot provide.

It is safe to **run more than once**: rows that are already configured are skipped.

**Source:** [arize-ai/ax-automation-scripts](https://github.com/Arize-ai/ax-automation-scripts) on GitHub.

---

## Two modes of operation

This tool can be used in two distinct ways. Choose the one that matches your needs.

### Mode 1 — SAML group mapping (default)

Sets up **SAML group → org/space role** rules so users automatically receive the right access in Arize when they log in via SSO. This is the standard setup for most teams.

**What it does:**
- Creates organizations and spaces if they don't exist.
- Registers SAML group-to-role mappings on your IdP configuration.
- Users gain access automatically on their next SSO login—no manual user management needed.

**Run it with:**
```bash
python arize_saml_bulk_setup.py --csv ./saml_mappings.csv
```

### Mode 2 — SAML + private project assignment (`--project-assign`)

Extends Mode 1 with **project-level access control**: creates restricted (private) projects and assigns specific users to them by email address.

**Why you need explicit emails for projects:** Arize does not support SAML group-to-project mapping. Project access requires an explicit role binding per user. This mode bridges that gap by:

1. Running the normal SAML mapping phase (Mode 1).
2. Creating and restricting the specified projects (making them private).
3. Assigning the listed emails to each project with the given project role.

**What "restricted" means:** A restricted project is invisible to space members who do not have an explicit project-level role binding. Even space admins see it; regular space members do not, unless they are in the `project_emails` list.

**User pre-registration:** If a listed email doesn't yet have an Arize account, the tool creates one automatically with SSO-only access (`invite_mode=none`). No invitation email is sent. The user logs in via SAML as normal on their first visit.

**Run it with:**
```bash
python arize_saml_bulk_setup.py --csv ./saml_mappings_with_projects.csv --project-assign
```

> **Important:** The `project` and `project_emails` columns in the CSV are **only read when `--project-assign` is passed**. Without the flag, those columns are ignored even if they are present in the file.

---

## Is this for you?

This is for **account administrators**, **IT / identity teams**, and **platform owners** who:

- Use **SAML SSO** with Arize (or plan to), and  
- Want to align **IdP groups** (for example Okta or Azure AD groups) with **roles in Arize**, across **many orgs and spaces**, from a single file.

You do **not** need SAML already turned on in the Arize app. If your account does not have SAML configured yet, this script can **register your identity provider** and apply your mappings in **one run**, as long as you provide **metadata** and **email domains** (see [Run the tool](#run-the-tool)).

**How Arize models SAML:** SAML is tied to your **Arize account**. Typically there is **one identity provider (IdP) per account**. This tool creates or updates that IdP and the group-to-role rules you define in the CSV.

---

## Before you start

| You need | Notes |
| --- | --- |
| **Python 3.11 or newer** | [python.org](https://www.python.org/downloads/) |
| An **Arize API key** with rights to manage organizations, spaces, and SAML | Create and manage keys in [Arize API keys](https://arize.com/docs/ax/security-and-settings/api-keys#api-keys). If something is denied, ask your Arize admin to confirm the key’s permissions. |
| A completed **CSV** | Use the [template](#csv-file-format) below as a starting point. |
| (First-time SAML only) Your IdP **metadata URL** or **metadata XML**, and **email domains** your users sign in with | Your identity team can provide these. |

---

## Install

1. Clone or download this repository (or copy the entire `saml_bulk_setup` folder—script, package, and `requirements.txt`—into a folder on your machine).
2. Open a terminal in the `saml_bulk_setup` folder and run:

```bash
pip install -r requirements.txt
```

### Running the test suite (optional)

If you're modifying the script and want to verify it still works, install the test dependencies and run `pytest` against the `tests/` directory:

```bash
pip install -r tests/requirements.txt
pytest tests/
```

The unit tests cover CSV parsing, validation, retry logic, custom role lookup, the preflight conflict resolver, the SAML IdP service, the runner orchestration, and CLI parsing—no Arize account or network access required. Scenarios that need a live account are marked in [`TEST_SCENARIOS.md`](./TEST_SCENARIOS.md).

---

## CSV file format

Start from the sample file: [`saml_mappings_template.csv`](./saml_mappings_template.csv).

Each **row** is one rule. There are two types of rows depending on your use case.

### SAML-only rows (Mode 1)

“When a user’s SAML attribute matches this value, grant them these roles in this org and space.”

| Column | What to put | Required |
| --- | --- | --- |
| `organization` | Name of the Arize **organization** (created if it does not exist). | Yes |
| `space` | Name of the **space** inside that organization (created if it does not exist). | Yes |
| `arize_org_role` | Role **in the organization**: `admin`, `member`, `viewer`, or `annotator`. | Yes |
| `arize_space_role` | Role **in the space**: one of the four standard roles above, the name of a **custom RBAC role** defined on your account, or **empty**—see [Org and space roles](#org-and-space-roles). | No (depends on rule) |
| `saml_attribute_name` | SAML attribute that carries group membership (often `groups`, `roles` or a custom claim). Must match what your IdP sends. | Yes |
| `saml_attribute_value` | The group or claim **value** that should match (for example `arize-ml-team`). | Yes |
| `project` | Leave **blank** for SAML-only rows. | — |
| `project_emails` | Leave **blank** for SAML-only rows. | — |

### Project rows (Mode 2 — `--project-assign` only)

“Create this project in the space, make it private, and give these specific users access.”

Project rows work differently from SAML-only rows in one important way: **`arize_space_role` is re-interpreted as the project-level role**, which will only allow to operate over that specific project in the space.

| Column | What to put | Required |
| --- | --- | --- |
| `organization` | Same as SAML-only rows. | Yes |
| `space` | Same as SAML-only rows. | Yes |
| `arize_org_role` | Same as SAML-only rows. Also used as the account role when auto-creating users that don’t exist yet. | Yes |
| `arize_space_role` | **Must be one of:** `project_admin`, `project_editor`, or `project_viewer`. This is the role each listed email receives on the project — it is **not** used as a SAML space role for this row. | Yes |
| `saml_attribute_name` | Same as SAML-only rows. The SAML mapping for this group is still applied (inheriting the org role with no explicit space role override). | Yes |
| `saml_attribute_value` | Same as SAML-only rows. | Yes |
| `project` | Name of the Arize project to create/restrict inside the space. | Yes |
| `project_emails` | Comma-separated email addresses to assign to the project. Each user gets the role in `arize_space_role`. Users not yet in Arize are created automatically (SSO-only, no invite email). | Yes |

> **Note on dual-phase rows:** When `project` is set, the tool still processes the SAML group mapping (the group gets the org-level role configured, with no space-role override). The project assignment is a separate, additional action: the `project_emails` users are the only ones who can access the restricted project, regardless of what SAML group they belong to.

### Org and space roles

- **`arize_org_role`** is the user’s access at the **organization** level.
- **`arize_space_role`** is optional. It sets the user’s role **in the space** on that row. If you leave it **blank**, Arize aligns the space role with the org role (for users who are not org admins).
- If **`arize_org_role` is `admin`**, that user has full access across the org; leave **`arize_space_role` empty** on that row.

`viewer` in the file is accepted; Arize stores it as read-only access.

### Custom RBAC roles

`arize_space_role` also accepts the **name of any custom RBAC role** defined on your Arize account (in addition to the four standard roles above). Custom role names are matched **case-insensitively**.

```csv
organization,space,arize_org_role,arize_space_role,saml_attribute_name,saml_attribute_value
Subsidiary Inc,NLP Research,member,Project Reviewer,groups,arize-nlp-leads
```

A few things to know:

- The custom role must already exist on your Arize account before you run. Create it in the Arize UI first; this script does not create arbitrary custom roles.  
  **Exception:** the four auto-promoted equivalents of legacy roles (`Space Admin`, `Space Member`, `Space Read-Only`, `Space Annotator`) are created automatically by the tool when needed — see [Conflict handling](#conflict-handling).
- **One role type per space**: Arize requires that a space uses either standard roles OR a custom role across all its SAML mappings — not both. If your CSV (or an existing IdP mapping) introduces that mix, the tool **automatically resolves it** by promoting the standard role entries to custom RBAC equivalents that mirror the same permissions. See [Conflict handling](#conflict-handling) for details.
- If the role name in the CSV doesn't match anything on your account, the row fails with a list of available roles in `error_message`.

### Example — SAML-only (Mode 1)

```csv
organization,space,arize_org_role,arize_space_role,saml_attribute_name,saml_attribute_value,project,project_emails
Acme Corp,ML Platform,admin,,groups,arize-admins,,
Acme Corp,ML Platform,member,admin,groups,arize-ml-engineers,,
Acme Corp,Fraud Detection,member,,groups,arize-fraud-team,,
Subsidiary Inc,NLP Research,member,Project Reviewer,groups,arize-nlp-leads,,
```

The `project` and `project_emails` columns can be left blank (or omitted entirely) for SAML-only rows.

### Example — SAML + private project assignment (Mode 2)

Assume alice and bob are in `arize-ml-engineers` **only** — not in `arize-risk-leads`. Dave is also in `arize-ml-engineers`. Carol is in `arize-risk-viewers` only.

```csv
organization,space,arize_org_role,arize_space_role,saml_attribute_name,saml_attribute_value,project,project_emails
Acme Corp,ML Platform,member,admin,groups,arize-ml-engineers,,
Acme Corp,ML Platform,member,project_admin,groups,arize-risk-leads,Credit Risk,"alice@acme.com,bob@acme.com"
Acme Corp,ML Platform,member,project_viewer,groups,arize-risk-viewers,Credit Risk,carol@acme.com
Subsidiary Inc,NLP Research,member,member,groups,arize-nlp-engineers,Chatbot QA,"lead@subsidiary.com,eng@subsidiary.com"
```

What each user experiences:

| User  | Space role (from SAML)                  | `Credit Risk` project                          |
|-------|-----------------------------------------|------------------------------------------------|
| alice | Space admin (`arize-ml-engineers`)      | Project admin — via `project_emails` binding   |
| bob   | Space admin (`arize-ml-engineers`)      | Project admin — via `project_emails` binding   |
| dave  | Space admin (`arize-ml-engineers`)      | **Blocked** — not listed in `project_emails`   |
| carol | `project_viewer` (`arize-risk-viewers`) | Can view — via `project_emails` binding        |

Two scenarios illustrated:

- **Space admin ≠ restricted project access (dave).** Dave is a space admin but cannot see `Credit Risk` because the project is restricted and he has no explicit binding. Restriction gates access regardless of space role.
- **Space admins who also need project access must be listed in `project_emails` (alice, bob).** Their `admin` space role comes from the `arize-ml-engineers` SAML row. The `project_emails` field grants them an explicit project-level binding on top of that — the two are at different resource levels and do not conflict.

> Each user has exactly one space role. Alice and bob are **not** in `arize-risk-leads`, so the `project_admin` SAML mapping on that row does not apply to them — they keep `admin` from `arize-ml-engineers`.
>
> The `arize-nlp-engineers` row uses `arize_space_role=member` for both purposes at once: the SAML mapping assigns `member` space role to all group members, and `lead@`/`eng@` additionally receive an explicit project binding to `Chatbot QA`. For the project binding, `member` is automatically resolved to the `Space Member` custom RBAC role (created on demand if it doesn't exist yet).

**Project-only rows** — if the SAML mapping for a space already exists and you only want to create a project and assign users, leave `arize_org_role`, `saml_attribute_name`, and `saml_attribute_value` blank. The SAML phase is skipped entirely; only the project creation and user assignment run:

```csv
Acme Corp,ML Platform,,project_viewer,,,Insurance Risk,carol@acme.com
```

`arize_space_role` is still required (it defines the project-level role for the binding).

Run with:
```bash
python arize_saml_bulk_setup.py --csv ./saml_mappings.csv --project-assign
```

---

## API key (authentication)

Your API key is **never** written to the results file or echoed in normal output.

Provide the key in one of these ways:

1. **`--api-key`** on the command line  
2. Environment variable **`ARIZE_API_KEY`**  
3. Environment variable **`ARIZE_DEVELOPER_KEY`** (same purpose; supported for compatibility)

Example:

```bash
export ARIZE_API_KEY='your-key-here'
```

---

## Run the tool

We recommend a **`--dry-run`** first: it shows what would happen **without** changing anything in Arize.

```bash
python arize_saml_bulk_setup.py --csv ./saml_mappings.csv --dry-run
```

When you are ready to apply changes, remove `--dry-run`.

### First time setting up SAML on this Arize account

If SAML is **not** configured yet, run with your **email domains** (the domains users use to sign in) and **IdP metadata** so the tool can register your identity provider and apply all rows from your CSV:

```bash
python arize_saml_bulk_setup.py \
  --csv ./saml_mappings.csv \
  --email-domains 'yourcompany.com' \
  --saml-metadata-url 'https://your-idp.example.com/metadata'
```

- Use **`--saml-metadata-xml`** instead of **`--saml-metadata-url`** if you paste metadata as text.  
- Do **not** pass both URL and XML.

### SAML already configured

If you (or your team) already set up SAML in Arize, you usually only need the CSV:

```bash
python arize_saml_bulk_setup.py --csv ./saml_mappings.csv
```

The tool adds or updates **group-to-role mappings** on your existing SAML setup.

### Other useful options

| Option | What it does |
| --- | --- |
| `--project-assign` | Enable [Mode 2](#mode-2--saml--private-project-assignment---project-assign): read the `project` and `project_emails` columns and run the project creation/restriction/assignment phase. Without this flag those columns are ignored. |
| `--verbose` | More detailed messages per row (helpful when debugging). |
| `--output PATH` | Where to write the results file (default: `saml_setup_results.csv`). |
| `--arize-url URL` | Use a non-default Arize URL if your company uses a dedicated host (default is `https://app.arize.com`). |

### SAML configuration flags

These flags control account-wide SAML settings. They apply both when creating a new IdP and when updating an existing one. Each flag is **opt-in**: omitting it preserves whatever your IdP already has, so a routine mapping update won't silently flip configuration. Passing the flag turns the setting on; this script does not turn settings off—use the Arize UI for that.

| Option | What it does |
| --- | --- |
| `--enforce-saml` | Require SAML sign-in for users in the configured email domains. |
| `--sync-user-roles` | On each sign-in, re-apply the roles dictated by the user's SAML group claims (instead of letting roles drift via the UI). |
| `--sign-authn` | Sign outbound SAML AuthN requests sent to your IdP. |

---

## What happens when you run

For each row, the tool runs two phases (or just the first, depending on flags):

**Phase 1 — SAML (always runs):**
1. Finds or creates the **organization** and **space** by name.
2. Adds **SAML group-to-role mappings** that are not already present.

**Phase 2 — Projects (only when `--project-assign` is passed and `project` is non-empty):**
3. Finds or creates the **project** inside the space.
4. Marks the project as **restricted** (private): only users with an explicit project-level role binding can see it.
5. For each email in `project_emails`:
   - Looks up the user in Arize. If the user doesn't exist yet, creates them with SSO-only access (no email invite).
   - Assigns the user to the project with the role from `arize_space_role` (`project_admin`, `project_editor`, or `project_viewer`).

After all rows are processed, the tool writes a **results file** and prints a short **summary** in the terminal.

If the service is busy, the tool **retries** automatically when it hits rate limits. If one row fails, **other rows still run**; failed rows are listed in the results file.

### Conflict handling

Arize requires that a space uses **either standard roles OR a custom RBAC role** across all its SAML mappings — not both. Whenever the tool detects a mixed-role conflict for a space, it **automatically resolves it** before writing to Arize rather than failing the run:

- **Auto-promotion**: all standard-role uses on the conflicted space are promoted to custom RBAC equivalents with matching permissions. The tool creates these roles on your account on demand if they don't exist yet:

  | Standard role | Auto-created custom role |
  | --- | --- |
  | `admin` | `Space Admin` |
  | `member` | `Space Member` |
  | `viewer` | `Space Read-Only` |
  | `annotator` | `Space Annotator` |

- **Two conflict shapes** are both handled automatically:
  - *CSV-internal*: two rows in the same run use a standard and a custom role on the same space. The standard-role row is swapped to the equivalent custom role; both rows succeed.
  - *CSV vs. existing IdP*: a row touches a space that already has the other role type on the IdP. The existing legacy entries for that space are promoted to custom; the row continues normally with a `note` in the results file.

- **Fallback to error**: if the auto-promotion itself fails (for example, `POST /v2/roles` is denied), the affected rows fail with a clear error message explaining which rows conflict and asking you to edit the CSV to use one role type for that space.

Rows that were previously `already_exists` and got their underlying mapping promoted show status `already_exists` with a note — they are not re-created.

### Re-running the tool

Running the tool again on the same CSV is **safe**: rows already in place are reported as `already_exists` and not duplicated. Changing the role type for an existing space across runs is treated as a migration on the next run, as described above.

---

## Results and success

### Results file

By default the tool creates **`saml_setup_results.csv`** next to your command (or the path you pass with `--output`). It contains your original columns plus:

- **`status`** — whether that row was applied (`created`), already in place (`already_exists`), failed (`error`), or only simulated (`dry_run` if you used `--dry-run`).  
- **`error_message`** — short reason when a row failed.

### Exit code

- **`0`** — every row succeeded.  
- **`1`** — at least one row failed (see the results file).

### Example summary (terminal)

**Mode 1 — SAML only:**
```
──────────────────────────────────────────────────
Summary
──────────────────────────────────────────────────
  Organizations : 1 created, 2 already existed
  Spaces        : 3 created, 5 already existed
  SAML mappings : 4 created, 2 already existed
  Errors        : 0
──────────────────────────────────────────────────
```

**Mode 2 — SAML + project assignment:**
```
──────────────────────────────────────────────────
Summary
──────────────────────────────────────────────────
  Organizations : 1 created, 2 already existed
  Spaces        : 3 created, 5 already existed
  SAML mappings : 4 created, 2 already existed
  Projects      : 2 created, 1 already existed
  Users created : 3 (for project assignment)
  Proj access   : 5 granted, 1 already had access
  Errors        : 0
──────────────────────────────────────────────────
```

If some rows fail, the summary tells you how many failed and points you to the results CSV.

---

## Troubleshooting

| What you see | What to try |
| --- | --- |
| **Permission denied / forbidden** | Confirm your API key can manage organizations, spaces, and SAML. You may need an account-level administrator to create or rotate the key. |
| **Invalid role** | For **`arize_org_role`**, use only `admin`, `member`, `viewer`, or `annotator`. For org **admin** rows, leave **`arize_space_role`** empty. **`arize_space_role`** also accepts custom RBAC role names defined on your account—see [Custom RBAC roles](#custom-rbac-roles). |
| **Custom role not found** | The role name in **`arize_space_role`** doesn't match any role on your account. The error message lists every available role (case-insensitive). Confirm the role exists in the Arize UI and that the spelling matches. |
| **Space role conflict (auto-promotion failed)** | The tool tried to promote a standard role to its custom equivalent on a space but the role-creation API call failed (e.g. permission denied). The error message lists the conflicting row numbers. You can either fix the CSV to use a single role type for that space, or confirm that your API key has permission to create custom roles (`POST /v2/roles`). |
| **Errors creating SAML / “no IdP”** | For a **new** SAML setup, include **`--email-domains`** and **`--saml-metadata-url`** or **`--saml-metadata-xml`**. Alternatively, complete SAML setup once in the Arize **Settings** UI, then run again with only **`--csv`**. |
| **Too many requests / slow** | The tool retries automatically. If it keeps failing, wait and run again with a smaller CSV or off-peak hours. |
| **Users do not get the expected access** | Check that **`saml_attribute_name`** and **`saml_attribute_value`** exactly match what your IdP sends (including spelling and case, per your IdP’s behavior). Review failed rows in **`saml_setup_results.csv`**. |
| **Invalid `arize_space_role` on a project row** | When `project` is set, `arize_space_role` must be exactly one of `project_admin`, `project_editor`, or `project_viewer` (case-insensitive). Standard space roles (`admin`, `member`, `viewer`, `annotator`) and other custom roles are not accepted on project rows. |
| **`project_emails` is required** | Every row that has a `project` value must also have at least one email in `project_emails`. If the column is empty for that row, the row fails with an error. |
| **Project access not working after a user logs in** | Only users listed in `project_emails` can access a restricted project. If someone needs access, add their email to that row and re-run the script. Re-runs are safe—existing assignments are not duplicated. |
| **User was auto-created but can’t log in** | Auto-created users have SSO-only access (no password). They must sign in via SAML SSO. Ensure your SAML configuration covers their email domain. |

---

## Need help?

- **Arize documentation:** [arize.com/docs](https://arize.com/docs)  
- **API keys:** [API keys](https://arize.com/docs/ax/security-and-settings/api-keys#api-keys)  

If something still fails after checking the table above, contact **your Arize account team** or **Arize Support** with the **error messages** from your results file (redact secrets).
