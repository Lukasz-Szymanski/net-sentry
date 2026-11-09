# Contributing to NetSentry

Thank you for your interest in contributing to **NetSentry**.

## Getting Started

1. Fork the repository on GitHub.
2. Clone your fork locally:
   ```bash
   git clone https://github.com/Lukasz-Szymanski/net-sentry.git
   cd net-sentry
   ```
3. Create a virtual environment and install in editable mode with development dependencies:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```
4. Run the test suite:
   ```bash
   pytest -v
   ```

## Development Workflow

1. Create a feature branch (`git checkout -b feat/your-feature`).
2. Make your changes and add tests where applicable.
3. Verify that all tests pass (`pytest -v`).
4. Commit using Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`).
5. Push to your fork and open a Pull Request.

## Security Vulnerability Reporting

If you discover a security vulnerability in NetSentry, please report it privately via GitHub Security Advisories rather than opening a public issue.
