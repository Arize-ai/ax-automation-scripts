"""CSV input parsing and results output."""

from __future__ import annotations

import csv
import os
import sys

from .config import OUTPUT_COLUMNS, REQUIRED_COLUMNS
from .models import RowResult


def load_csv(path: str) -> list[dict[str, str]]:
    """Load and validate the input CSV.

    Exits the process with code 1 on any structural problem (missing file,
    empty file, missing required column, or no data rows) — the CLI's contract
    is that bad input fails fast before any API call.

    Whitespace-only rows are skipped silently.
    """
    if not os.path.isfile(path):
        print(f"ERROR: CSV file not found: {path}", file=sys.stderr)
        sys.exit(1)
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            print("ERROR: CSV file is empty.", file=sys.stderr)
            sys.exit(1)
        missing = REQUIRED_COLUMNS - set(reader.fieldnames)
        if missing:
            print(
                f"ERROR: CSV is missing required columns: {', '.join(sorted(missing))}",
                file=sys.stderr,
            )
            sys.exit(1)
        rows = [row for row in reader if any(v and v.strip() for v in row.values())]
    if not rows:
        print("ERROR: CSV file has no data rows.", file=sys.stderr)
        sys.exit(1)
    return rows


def write_results_csv(results: list[RowResult], output_path: str) -> None:
    """Write one CSV row per RowResult to `output_path`, columns per OUTPUT_COLUMNS."""
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=OUTPUT_COLUMNS)
        writer.writeheader()
        for r in results:
            writer.writerow(
                {
                    "organization": r.organization,
                    "space": r.space,
                    "arize_org_role": r.arize_org_role,
                    "arize_space_role": r.arize_space_role,
                    "saml_attribute_name": r.saml_attribute_name,
                    "saml_attribute_value": r.saml_attribute_value,
                    "status": r.status,
                    "error_message": r.error_message,
                }
            )
