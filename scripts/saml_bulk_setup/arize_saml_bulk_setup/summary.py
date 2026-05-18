"""Final terminal summary block."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .models import RowResult

if TYPE_CHECKING:
    from .runner import BulkSetupRunner


def print_summary(
    runner: "BulkSetupRunner", results: list[RowResult], output_path: str
) -> None:
    """Print the org/space/mapping counters and error count to stdout.

    `output_path` is referenced in the error guidance so the operator knows
    where to look up failed rows.
    """
    errors = [r for r in results if r.status == "error"]
    print()
    print("─" * 50)
    print("Summary")
    print("─" * 50)
    print(
        f"  Organizations : {runner.orgs_created} created, {runner.orgs_existed} already existed"
    )
    print(
        f"  Spaces        : {runner.spaces_created} created, {runner.spaces_existed} already existed"
    )
    print(
        f"  SAML mappings : {runner.mappings_created} created, {runner.mappings_existed} already existed"
    )
    if runner.legacy_auto_conversions:
        print(
            f"  Auto-converts : {runner.legacy_auto_conversions} legacy role(s) "
            "converted to custom equivalents for cross-mapping compatibility"
        )
    if errors:
        print(f"  Errors        : {len(errors)} row(s) failed — review {output_path}")
    else:
        print("  Errors        : 0")
    print("─" * 50)
    if errors:
        print(f"\n{len(errors)} row(s) failed. See '{output_path}' for details.")
