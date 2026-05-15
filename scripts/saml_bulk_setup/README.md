# Bulk SAML setup for Arize

Use this tool to **create or update** your Arize **organizations**, **spaces**, and **SAML group-to-role mappings** from a spreadsheet (CSV)—so your teams can onboard to Arize without clicking through each mapping in the UI.

It is safe to **run more than once**: rows that are already configured are skipped.

**Source:** [arize-ai/ax-automation-scripts](https://github.com/Arize-ai/ax-automation-scripts) on GitHub.

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

Each **row** is one rule: “When a user’s SAML attribute matches this value, grant them these roles in this org and space.”

| Column | What to put | Required |
| --- | --- | --- |
| `organization` | Name of the Arize **organization** (created if it does not exist). | Yes |
| `space` | Name of the **space** inside that organization (created if it does not exist). | Yes |
| `arize_org_role` | Role **in the organization**: `admin`, `member`, `viewer`, or `annotator`. | Yes |
| `arize_space_role` | Role **in the space**: one of the four standard roles above, the name of a **custom RBAC role** defined on your account, or **empty**—see [Org and space roles](#org-and-space-roles). | No (depends on rule) |
| `saml_attribute_name` | SAML attribute that carries group membership (often `groups` or a custom claim). Must match what your IdP sends. | Yes |
| `saml_attribute_value` | The group or claim **value** that should match (for example `arize-ml-team`). | Yes |

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

- The custom role must already exist on your Arize account. Create it in the Arize UI first; this script does not create roles.
- **One role type per space**: Arize allows a space to use either standard roles OR a custom role across all SAML mappings—not both. If your CSV mixes them for the same space, the affected rows fail (see [Conflict handling](#conflict-handling)).
- If the role name in the CSV doesn't match anything on your account, the row fails with a list of available roles in `error_message`.

### Example

```csv
organization,space,arize_org_role,arize_space_role,saml_attribute_name,saml_attribute_value
Acme Corp,ML Platform,admin,,groups,arize-admins
Acme Corp,ML Platform,member,admin,groups,arize-ml-engineers
Acme Corp,Fraud Detection,member,,groups,arize-fraud-team
Subsidiary Inc,NLP Research,member,Project Reviewer,groups,arize-nlp-leads
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

For each row, the tool:

1. Finds or creates the **organization** and **space** by name.  
2. Adds **SAML mappings** that are not already present (same rules are not duplicated).  
3. Writes a **results file** and prints a short **summary** in the terminal.

If the service is busy, the tool **retries** automatically when it hits rate limits. If one row fails, **other rows still run**; failed rows are listed in the results file.

### Conflict handling

Arize allows a space to use **either standard roles OR a custom RBAC role** across all its SAML mappings—not both. The tool checks for this before writing any changes:

- **Inside your CSV**: if two rows ask for a standard role and a custom role on the same space, **both rows fail** with an error pointing to the offending row numbers. Fix the CSV so the space uses one role type, then re-run.
- **CSV vs. existing IdP**: if your CSV asks for a custom role on a space that currently uses a standard role (or vice versa), the tool treats this as a **migration**—the old entry for that space is removed and the new one is applied. Other mappings on the IdP are preserved.

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

If some rows fail, the summary tells you how many failed and points you to the results CSV.

---

## Troubleshooting

| What you see | What to try |
| --- | --- |
| **Permission denied / forbidden** | Confirm your API key can manage organizations, spaces, and SAML. You may need an account-level administrator to create or rotate the key. |
| **Invalid role** | For **`arize_org_role`**, use only `admin`, `member`, `viewer`, or `annotator`. For org **admin** rows, leave **`arize_space_role`** empty. **`arize_space_role`** also accepts custom RBAC role names defined on your account—see [Custom RBAC roles](#custom-rbac-roles). |
| **Custom role not found** | The role name in **`arize_space_role`** doesn't match any role on your account. The error message lists every available role (case-insensitive). Confirm the role exists in the Arize UI and that the spelling matches. |
| **Space role conflict** | Two CSV rows asked for both a standard role and a custom role on the same space, which Arize doesn't allow. The error message lists the offending row numbers—edit them to use a single role type for that space. |
| **Errors creating SAML / “no IdP”** | For a **new** SAML setup, include **`--email-domains`** and **`--saml-metadata-url`** or **`--saml-metadata-xml`**. Alternatively, complete SAML setup once in the Arize **Settings** UI, then run again with only **`--csv`**. |
| **Too many requests / slow** | The tool retries automatically. If it keeps failing, wait and run again with a smaller CSV or off-peak hours. |
| **Users do not get the expected access** | Check that **`saml_attribute_name`** and **`saml_attribute_value`** exactly match what your IdP sends (including spelling and case, per your IdP’s behavior). Review failed rows in **`saml_setup_results.csv`**. |

---

## Need help?

- **Arize documentation:** [arize.com/docs](https://arize.com/docs)  
- **API keys:** [API keys](https://arize.com/docs/ax/security-and-settings/api-keys#api-keys)  

If something still fails after checking the table above, contact **your Arize account team** or **Arize Support** with the **error messages** from your results file (redact secrets).
