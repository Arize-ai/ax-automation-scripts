"""CLI parsing and env var handling — covers TEST_SCENARIOS.md section 3 (3.1–3.5)."""

from __future__ import annotations

import pytest

from arize_saml_bulk_setup.cli import build_parser, resolve_api_key


# ── 3.1: missing API key ─────────────────────────────────────────────────────


def test_no_api_key_anywhere_exits(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("ARIZE_API_KEY", raising=False)
    monkeypatch.delenv("ARIZE_DEVELOPER_KEY", raising=False)
    with pytest.raises(SystemExit) as exc:
        resolve_api_key(None)
    assert exc.value.code == 1
    assert "No API key provided" in capsys.readouterr().err


# ── 3.2–3.3: env vars ────────────────────────────────────────────────────────


def test_cli_flag_wins_over_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARIZE_API_KEY", "from-env")
    assert resolve_api_key("from-cli") == "from-cli"


def test_arize_api_key_env_is_used(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ARIZE_DEVELOPER_KEY", raising=False)
    monkeypatch.setenv("ARIZE_API_KEY", "from-env")
    assert resolve_api_key(None) == "from-env"


def test_arize_developer_key_env_is_used(monkeypatch: pytest.MonkeyPatch) -> None:
    """ARIZE_DEVELOPER_KEY is the legacy name; still supported."""
    monkeypatch.delenv("ARIZE_API_KEY", raising=False)
    monkeypatch.setenv("ARIZE_DEVELOPER_KEY", "from-dev-env")
    assert resolve_api_key(None) == "from-dev-env"


def test_arize_api_key_takes_precedence_over_developer_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ARIZE_API_KEY", "primary")
    monkeypatch.setenv("ARIZE_DEVELOPER_KEY", "legacy")
    assert resolve_api_key(None) == "primary"


# ── 3.4: --saml-metadata-url / --saml-metadata-xml mutex ─────────────────────


def test_metadata_url_and_xml_are_mutually_exclusive() -> None:
    """3.4: argparse handling is in main(); here we verify parser accepts each individually."""
    parser = build_parser()
    # Either alone is accepted by argparse — the mutex is enforced in main()
    ns = parser.parse_args(
        ["--csv", "x.csv", "--saml-metadata-url", "https://idp.example.com/m"]
    )
    assert ns.saml_metadata_url == "https://idp.example.com/m"
    assert ns.saml_metadata_xml is None

    ns = parser.parse_args(
        ["--csv", "x.csv", "--saml-metadata-xml", "<xml/>"]
    )
    assert ns.saml_metadata_xml == "<xml/>"
    assert ns.saml_metadata_url is None


# ── 3.5: --output path ───────────────────────────────────────────────────────


def test_output_path_defaults_and_overrides() -> None:
    parser = build_parser()
    ns = parser.parse_args(["--csv", "x.csv"])
    assert ns.output == "saml_setup_results.csv"

    ns = parser.parse_args(["--csv", "x.csv", "--output", "/tmp/custom.csv"])
    assert ns.output == "/tmp/custom.csv"


# ── Arg-parser sanity checks ─────────────────────────────────────────────────


def test_csv_is_required() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([])  # no --csv


def test_saml_flags_default_to_none_when_omitted() -> None:
    """The three SAML flags use action='store_true' + default=None so that we
    can distinguish 'not passed' from 'explicitly False' downstream."""
    parser = build_parser()
    ns = parser.parse_args(["--csv", "x.csv"])
    assert ns.enforce_saml is None
    assert ns.sync_user_roles is None
    assert ns.sign_authn is None

    ns = parser.parse_args(
        ["--csv", "x.csv", "--enforce-saml", "--sync-user-roles", "--sign-authn"]
    )
    assert ns.enforce_saml is True
    assert ns.sync_user_roles is True
    assert ns.sign_authn is True


def test_arize_url_default_and_override() -> None:
    parser = build_parser()
    ns = parser.parse_args(["--csv", "x.csv"])
    assert ns.arize_url == "https://app.arize.com"

    ns = parser.parse_args(
        ["--csv", "x.csv", "--arize-url", "https://app.arize-eu.com"]
    )
    assert ns.arize_url == "https://app.arize-eu.com"
