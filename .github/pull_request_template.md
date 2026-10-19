## Description
Briefly describe the change and motivation (e.g. bug fix, security hardening, detection tuning).

## Type of Change
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] Security fix / defense hardening
- [ ] New detection rule / heuristic (blue team)
- [ ] New parser or log format support
- [ ] Documentation update
- [ ] Test addition or improvement

## Verification Checklist
- [ ] **Tests**: Added or updated regression tests in `tests/` covering new logic.
- [ ] **Pytest Suite**: Ran `python -m pytest` and all tests pass (0 failures).
- [ ] **Lint & Syntax**: Ran `flake8` with 0 syntax or undefined-name errors (`E9,F63,F7,F82`).
- [ ] **Security Scan**: Ran `bandit` AST scanner with 0 high/medium issues.
- [ ] **Dependency Audit**: Ran `pip_audit` with 0 unpatched vulnerabilities.
- [ ] **Preservation**: Verified that dashboard UI ("Nicole's Security Lab") and standalone Windows executable compatibility remain intact.
- [ ] **No Offensive Code**: Confirmed that changes contain no offensive payloads, exploitation tooling, or evasion code.
