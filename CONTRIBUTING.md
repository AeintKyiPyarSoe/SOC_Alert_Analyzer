# Contributing to SOC Alert Analyzer

Thank you for your interest in contributing to **SOC Alert Analyzer**! We welcome contributions that strengthen detection accuracy, enhance security posture, improve test coverage, and improve user experience for cybersecurity analysts and students.

---

## 🛡️ Core Defensive Philosophy

This repository is strictly a **blue-team defensive cybersecurity tool**.
- **Accepted Contributions**: Detection heuristics, parser support, incident correlation logic, explainable risk calculations, MITRE ATT&CK mappings, defensive triage playbooks, and security hardening.
- **Prohibited Contributions**: Offensive exploit payloads, weaponization scripts, denial-of-service triggers, credential dumpers, or tools designed to evade detection.

---

## 🛠️ Development Setup

1. **Fork and Clone** the repository:
   ```bash
   git clone https://github.com/<your-username>/SOC_Alert_Analyzer.git
   cd SOC_Alert_Analyzer
   ```

2. **Create a Virtual Environment**:
   ```bash
   python3 -m venv venv
   # Linux / macOS:
   source venv/bin/activate
   # Windows PowerShell:
   .\venv\Scripts\Activate.ps1
   ```

3. **Install Dependencies**:
   ```bash
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. **Configure Environment Variables**:
   ```bash
   cp .env.example .env
   # On Windows: Copy-Item .env.example .env
   ```

---

## 🧪 Testing & Code Quality Standards

All pull requests must pass automated regression testing, syntax linting, and static security analysis before merging.

### 1. Run the Pytest Suite
Run the full test suite and ensure all tests pass:
```bash
python -m pytest -v
```

### 2. Run Syntax & Lint Checks
Verify that code conforms to PEP 8 standards with zero undefined names or syntax errors:
```bash
python -m flake8 app/ tests/ --count --select=E9,F63,F7,F82 --show-source --statistics
```

### 3. Run Static Security Analysis (Bandit)
Ensure no high-severity vulnerabilities are introduced:
```bash
python -m bandit -r app/ -ll -s B104,B105,B106,B107,B108,B311
```

### 4. Run Dependency Audit
Check that no vulnerable dependencies are introduced:
```bash
python -m pip_audit
```

---

## 📋 Pull Request Guidelines

1. **Branch Naming**: Use descriptive branch names:
   - `fix/description` for bug fixes.
   - `feat/description` for new features or detection rules.
   - `docs/description` for documentation improvements.
   - `test/description` for test additions.
2. **Write Unit Tests**: Every bug fix, detection heuristic, or API route modification must include corresponding pytest test cases in `tests/`.
3. **Preserve User Experience**:
   - Maintain the "Nicole's Security Lab" visual styling and tokens.
   - Do not break existing API contracts or standalone Windows executable packaging.
4. **Descriptive Commit Messages**: Follow conventional commits (e.g., `feat(detection): add parent-child heuristic for web shells`).
5. **No Hardcoded Secrets**: Ensure test files and configurations use generated or placeholder secrets.

---

## 📄 License

By contributing to SOC Alert Analyzer, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).
