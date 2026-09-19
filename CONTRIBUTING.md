# Contributing to DockerWard

Thank you for your interest in improving **DockerWard**! We welcome contributions from the community to strengthen container runtime security audits and DevSecOps quality gates.

---

## Code of Conduct

We are committed to providing a welcoming, inclusive, and harassment-free environment for all contributors. Please maintain professional, constructive, and respectful interactions across all discussions and pull requests.

---

## Development Setup

### Prerequisites

- **Python**: 3.12 or higher
- **Docker Engine**: 24.0+ running with active UNIX socket (`/var/run/docker.sock`)
- **Git**

### Clone & Install

```bash
git clone https://github.com/h3n-x/DockerWard.git
cd DockerWard

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install editable package with development dependencies
pip install -e ".[dev]"
```

---

## Verification & Quality Gates

Before submitting a pull request, ensure all tests and linters pass cleanly:

### 1. Run Automated Test Suite
```bash
pytest tests/ -v --cov=dockerward --cov-report=term-missing
```

### 2. Linting & Formatting Check (Ruff)
```bash
ruff check .
ruff format --check .
```

### 3. Strict Type Checking (Mypy)
```bash
mypy dockerward/ tests/
```

---

## Pull Request Guidelines

1. **Branch Naming**:
   - `feat/<feature-name>` for new functionality or audit rules
   - `fix/<bug-name>` for bug fixes and patches
   - `docs/<doc-topic>` for documentation improvements
   - `test/<test-topic>` for test additions or coverage increases

2. **Commit Conventions**:
   Follow [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat: add CIS rule 5.31 for AppArmor profile verification`
   - `fix: handle missing memory limits in container inspect payload`
   - `docs: update SARIF export integration guide`
   - `test: add unit tests for cgroups v2 controller parsing`

3. **Submitting**:
   - Ensure all automated checks pass locally.
   - Open a PR against the `main` branch with a clear summary of changes and testing evidence.
