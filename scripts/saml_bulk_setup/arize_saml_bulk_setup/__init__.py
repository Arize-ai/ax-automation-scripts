"""Bulk provision Arize organizations, spaces, and SAML group role mappings.

Entry points:
    python arize_saml_bulk_setup.py ...    # via the shim
    python -m arize_saml_bulk_setup ...    # via __main__

Programmatic users should import from the relevant submodule directly
(e.g. `from arize_saml_bulk_setup.runner import BulkSetupRunner`); the
package root does not re-export anything so that importing
`arize_saml_bulk_setup.models` doesn't pull in arize_toolkit / gql / requests.
"""
