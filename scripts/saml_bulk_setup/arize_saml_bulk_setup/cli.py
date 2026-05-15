"""Command-line entry point."""

from __future__ import annotations

import argparse
import os
import sys

from .config import ARIZE_APP_URL
from .csv_io import load_csv, write_results_csv
from .runner import BulkSetupRunner
from .summary import print_summary


def build_parser() -> argparse.ArgumentParser:
    """Construct the argparse parser. Exposed for testing."""
    parser = argparse.ArgumentParser(
        prog="arize_saml_bulk_setup.py",
        description=(
            "Bulk provision Arize organizations, spaces, and SAML group "
            "role mappings from a CSV file."
        ),
    )
    parser.add_argument(
        "--csv", required=True, metavar="CSV", help="Path to input CSV file"
    )
    parser.add_argument(
        "--api-key",
        metavar="API_KEY",
        help="Arize API key (or set ARIZE_API_KEY / ARIZE_DEVELOPER_KEY env var)",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Preview actions without API calls"
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Enable per-row debug logging"
    )
    parser.add_argument(
        "--output",
        default="saml_setup_results.csv",
        metavar="OUTPUT",
        help="Path for results CSV (default: saml_setup_results.csv)",
    )
    parser.add_argument(
        "--arize-url",
        default=ARIZE_APP_URL,
        metavar="URL",
        help=f"Arize app base URL (default: {ARIZE_APP_URL})",
    )

    saml_group = parser.add_argument_group(
        "SAML IdP creation (only needed if no IdP is configured yet)"
    )
    saml_group.add_argument(
        "--saml-metadata-url",
        metavar="URL",
        help="URL to fetch SAML IdP metadata from (mutually exclusive with --saml-metadata-xml)",
    )
    saml_group.add_argument(
        "--saml-metadata-xml",
        metavar="XML",
        help="Raw SAML IdP metadata XML string (mutually exclusive with --saml-metadata-url)",
    )
    saml_group.add_argument(
        "--email-domains",
        metavar="DOMAINS",
        help="Comma-separated email domains for the IdP (e.g. acme.com,subsidiary.com)",
    )
    saml_group.add_argument(
        "--enforce-saml",
        action="store_true",
        default=None,
        help="Enable SAML enforcement on create, or turn it on for an existing IdP update",
    )
    saml_group.add_argument(
        "--sync-user-roles",
        action="store_true",
        default=None,
        help="Enable sync user roles on create, or turn it on for an existing IdP update",
    )
    saml_group.add_argument(
        "--sign-authn",
        action="store_true",
        default=None,
        help="Enable signed authn requests on create, or turn it on for an existing IdP update",
    )
    return parser


def resolve_api_key(cli_key: str | None) -> str:
    """Resolve the API key from the CLI flag or env vars; exit 1 if none found.

    Precedence: `--api-key` flag → `ARIZE_API_KEY` → `ARIZE_DEVELOPER_KEY` (legacy).
    """
    key = (
        cli_key
        or os.environ.get("ARIZE_API_KEY")
        or os.environ.get("ARIZE_DEVELOPER_KEY")
    )
    if not key:
        print(
            "ERROR: No API key provided. Use --api-key or set ARIZE_API_KEY.",
            file=sys.stderr,
        )
        sys.exit(1)
    return key


def main() -> None:
    """Parse args, run the bulk setup, write the results CSV, exit accordingly."""
    parser = build_parser()
    args = parser.parse_args()

    if args.saml_metadata_url and args.saml_metadata_xml:
        parser.error(
            "--saml-metadata-url and --saml-metadata-xml are mutually exclusive."
        )

    api_key = resolve_api_key(args.api_key)
    rows = load_csv(args.csv)

    if args.dry_run:
        print("DRY RUN — no changes will be made.\n")

    email_domains = (
        [d.strip() for d in args.email_domains.split(",") if d.strip()]
        if args.email_domains
        else None
    )

    runner = BulkSetupRunner(
        api_key=api_key,
        dry_run=args.dry_run,
        verbose=args.verbose,
        arize_app_url=args.arize_url,
        saml_metadata_url=args.saml_metadata_url,
        saml_metadata_xml=args.saml_metadata_xml,
        email_domains=email_domains,
        enforce_saml=args.enforce_saml,
        sync_user_roles=args.sync_user_roles,
        sign_authn=args.sign_authn,
    )

    results = runner.run(rows)

    write_results_csv(results, args.output)
    print_summary(runner, results, args.output)

    sys.exit(1 if any(r.status == "error" for r in results) else 0)
