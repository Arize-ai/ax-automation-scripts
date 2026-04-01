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

1. Clone or download this repository (or copy `arize_saml_bulk_setup.py` and `requirements.txt` into a folder on your machine).
2. Open a terminal in the `saml_bulk_setup` folder and run:

```bash
pip install -r requirements.txt
```

---

## CSV file format

Start from the sample file: [`saml_mappings_template.csv`](./saml_mappings_template.csv).

Each **row** is one rule: “When a user’s SAML attribute matches this value, grant them these roles in this org and space.”

| Column | What to put | Required |
| --- | --- | --- |
| `organization` | Name of the Arize **organization** (created if it does not exist). | Yes |
| `space` | Name of the **space** inside that organization (created if it does not exist). | Yes |
| `arize_org_role` | Role **in the organization**: `admin`, `member`, `viewer`, or `annotator`. | Yes |
| `arize_space_role` | Role **in the space**, or leave **empty**—see [Org and space roles](#org-and-space-roles). | No (depends on rule) |
| `saml_attribute_name` | SAML attribute that carries group membership (often `groups` or a custom claim). Must match what your IdP sends. | Yes |
| `saml_attribute_value` | The group or claim **value** that should match (for example `arize-ml-team`). | Yes |

### Org and space roles

- **`arize_org_role`** is the user’s access at the **organization** level.
- **`arize_space_role`** is optional. It sets the user’s role **in the space** on that row. If you leave it **blank**, Arize can align the space role with the org role (for users who are not org admins).
- If **`arize_org_role` is `admin`**, that user has full access across the org; leave **`arize_space_role` empty** on that row.

`viewer` in the file is accepted; Arize stores it as read-only access.

### Example

```csv
organization,space,arize_org_role,arize_space_role,saml_attribute_name,saml_attribute_value
Acme Corp,ML Platform,admin,,groups,arize-admins
Acme Corp,ML Platform,member,admin,groups,arize-ml-engineers
Acme Corp,Fraud Detection,member,,groups,arize-fraud-team
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

---

## What happens when you run

For each row, the tool:

1. Finds or creates the **organization** and **space** by name.  
2. Adds **SAML mappings** that are not already present (same rules are not duplicated).  
3. Writes a **results file** and prints a short **summary** in the terminal.

If the service is busy, the tool **retries** automatically when it hits rate limits. If one row fails, **other rows still run**; failed rows are listed in the results file.

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
| **Invalid role** | Use only `admin`, `member`, `viewer`, or `annotator` for roles. For org **admin** rows, leave **`arize_space_role`** empty. |
| **Errors creating SAML / “no IdP”** | For a **new** SAML setup, include **`--email-domains`** and **`--saml-metadata-url`** or **`--saml-metadata-xml`**. Alternatively, complete SAML setup once in the Arize **Settings** UI, then run again with only **`--csv`**. |
| **Too many requests / slow** | The tool retries automatically. If it keeps failing, wait and run again with a smaller CSV or off-peak hours. |
| **Users do not get the expected access** | Check that **`saml_attribute_name`** and **`saml_attribute_value`** exactly match what your IdP sends (including spelling and case, per your IdP’s behavior). Review failed rows in **`saml_setup_results.csv`**. |

---

## Need help?

- **Arize documentation:** [arize.com/docs](https://arize.com/docs)  
- **API keys:** [API keys](https://arize.com/docs/ax/security-and-settings/api-keys#api-keys)  

If something still fails after checking the table above, contact **your Arize account team** or **Arize Support** with the **error messages** from your results file (redact secrets).
