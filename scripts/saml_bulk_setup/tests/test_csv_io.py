"""CSV parsing — covers TEST_SCENARIOS.md section 1 (scenarios 1.1–1.4)."""

from __future__ import annotations

import pytest

from arize_saml_bulk_setup.csv_io import load_csv, write_results_csv
from arize_saml_bulk_setup.models import RowResult


def test_missing_file_exits_with_error(capsys: pytest.CaptureFixture[str]) -> None:
    """1.1: load_csv on a non-existent path exits 1 with a clear error."""
    with pytest.raises(SystemExit) as exc:
        load_csv("/tmp/__definitely_not_a_real_csv__.csv")
    assert exc.value.code == 1
    assert "CSV file not found" in capsys.readouterr().err


def test_empty_file_exits_with_error(
    tmp_path, capsys: pytest.CaptureFixture[str]
) -> None:
    """1.2: an empty file exits 1."""
    empty = tmp_path / "empty.csv"
    empty.write_text("")
    with pytest.raises(SystemExit) as exc:
        load_csv(str(empty))
    assert exc.value.code == 1
    assert "CSV file is empty" in capsys.readouterr().err


def test_missing_required_column_exits(
    fixtures_dir, capsys: pytest.CaptureFixture[str]
) -> None:
    """1.3: CSV missing a required column lists the missing column."""
    with pytest.raises(SystemExit) as exc:
        load_csv(str(fixtures_dir / "missing_required_column.csv"))
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "missing required columns" in err
    assert "saml_attribute_value" in err


def test_whitespace_only_rows_are_skipped(fixtures_dir) -> None:
    """1.4: whitespace-only rows don't appear in the loaded result."""
    rows = load_csv(str(fixtures_dir / "whitespace_rows.csv"))
    assert len(rows) == 2
    assert rows[0]["space"] == "ML Platform"
    assert rows[1]["space"] == "Fraud Detection"


def test_header_only_csv_exits(tmp_path, capsys: pytest.CaptureFixture[str]) -> None:
    """A file with only a header row (no data) exits 1."""
    header_only = tmp_path / "header_only.csv"
    header_only.write_text(
        "organization,space,arize_org_role,arize_space_role,"
        "saml_attribute_name,saml_attribute_value\n"
    )
    with pytest.raises(SystemExit) as exc:
        load_csv(str(header_only))
    assert exc.value.code == 1
    assert "no data rows" in capsys.readouterr().err


def test_write_results_csv_roundtrip(tmp_path) -> None:
    """write_results_csv emits all OUTPUT_COLUMNS in order, including status."""
    results = [
        RowResult(
            row_number=1,
            organization="Acme",
            space="S",
            arize_org_role="member",
            arize_space_role="admin",
            saml_attribute_name="groups",
            saml_attribute_value="g1",
            status="created",
            error_message="",
        ),
        RowResult(
            row_number=2,
            organization="Acme",
            space="S",
            arize_org_role="owner",
            arize_space_role="",
            saml_attribute_name="groups",
            saml_attribute_value="g2",
            status="error",
            error_message="Invalid arize_org_role 'owner'.",
        ),
    ]
    out = tmp_path / "results.csv"
    write_results_csv(results, str(out))
    text = out.read_text()
    lines = text.strip().split("\n")
    assert lines[0].startswith("organization,space,arize_org_role")
    assert "created," in lines[1]
    assert "error," in lines[2]
    assert "Invalid arize_org_role" in lines[2]
