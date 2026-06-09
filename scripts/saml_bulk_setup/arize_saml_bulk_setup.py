#!/usr/bin/env python3
"""
Usage:
    python arize_saml_bulk_setup.py --csv ./saml_mappings.csv [--api-key KEY]
                                     [--dry-run] [--verbose] [--output results.csv]

Dependencies:
    pip install -r requirements.txt
"""

from arize_saml_bulk_setup.cli import main

if __name__ == "__main__":
    main()
