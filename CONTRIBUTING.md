# Contributing to NetSentry 🛡️

Thank you for your interest in contributing to **NetSentry**! NetSentry is an open-source network sentinel and threat monitor for Linux.

---

## Getting Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
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

---

## Development Workflow

1. Create a descriptive feature branch:
   ```bash
   git checkout -b feature/threat-rule-dns
   ```
2. Make your improvements or fixes.
3. Ensure all tests pass:
   ```bash
   pytest -v
   ```
4. Commit your changes following **Conventional Commits**:
   - `feat:` new feature or rule
   - `fix:` bug fix
   - `docs:` documentation updates
   - `test:` test improvements
   - `refactor:` code refactoring
5. Push to your fork and submit a Pull Request.

---

## Security Vulnerability Reporting

If you discover a security vulnerability within NetSentry itself, please report it privately by opening a Security Advisory or contacting the maintainers directly rather than opening a public issue.
