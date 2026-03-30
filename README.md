# ax-automation-scripts

A collection of scripts and utilities maintained by the Arize team to help enterprises automate key administrative and operational workflows in [Arize AX](https://arize.com/docs/ax/).

## Overview

Managing Arize AX across many teams, spaces, organizations, and integrations involves workflows that can be tedious to execute manually through the UI. This repository provides automation scripts so that IT administrators, DevOps engineers, and platform teams can programmatically manage their Arize account easily.

Scripts in this repository are designed to be:

- **Standalone** — minimal dependencies, easy to run in any environment
- **Idempotent** — safe to re-run; existing state is preserved and not duplicated
- **Observable** — structured logging, dry-run modes, and results output so you always know what changed
- **Documented** — each script includes its own usage guide and examples


## Repository Structure

```
arize-automation-scripts/
├── README.md
├── LICENSE
└── scripts/
    └── ...
```

Each script lives in the `scripts/` directory with its own focused README. New scripts will be added over time as common automation needs are identified.


## Authentication

Most scripts in this repository authenticate against the Arize Admin API using an API key. You can provide your key in one of two ways:

1. **CLI flag:** `--api-key <your-key>`
2. **Environment variable:** `export ARIZE_API_KEY=<your-key>`

Your API key is never written to logs or output files. See the [Arize API key documentation](https://arize.com/docs/ax/security-and-settings/api-keys#api-keys) for details on generating and scoping keys.


## Contributing

This repository is maintained by the Arize AI team. If you encounter a bug or have a suggestion for a new automation script, please open a GitHub issue with the following information:

- A description of the workflow you want to automate
- The manual steps currently required
- Any relevant context (scale, frequency, environment)

Internal contributors should follow standard Arize engineering practices and open a pull request against `main`.


## License
MIT