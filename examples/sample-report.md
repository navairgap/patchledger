# PatchLedger Security Report

> **SYNTHETIC EXAMPLE DATA** — generated for illustration only. Not the result of a real scan.

- **Project:** example-project (synthetic)
- **Root:** `/home/dev/example-project`
- **Scan:** `bb509554abf5483baaa420279116dbab` (scan, 2026-11-11T12:00:00+00:00)
- **Git:** `0f1e2d3c4b5a` on `main`
- **Generated:** 2026-11-11T12:05:00+00:00
- **Overall status:** **FAIL (incomplete coverage)**

## Scanner coverage

| Tool | Status | Version | Note |
|------|--------|---------|------|
| semgrep | ran | 1.185.0 |  |
| bandit | ran | 1.9.4 |  |
| pip-audit | ran | 2.10.1 |  |
| gitleaks | unavailable | - | not installed on this machine |
| trivy | skipped | - | disabled in project configuration |

> ⚠️ **Incomplete coverage** — some tools did not run. Findings below are not a complete picture, and resolution claims are treated as unverified.

## Summary

| Severity | Count |
|----------|-------|
| critical | 0 |
| high | 4 |
| medium | 1 |
| low | 1 |
| info | 0 |
| unknown | 0 |
| **Total** | **6** |

## Comparison with scan `3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c` (2026-11-04T09:00:00+00:00)

- New: **1**
- Persistent: **4**
- Resolved candidates: **2** (verified fixed: **1**, inconclusive: **1**)
- Reintroduced: **0**
- Changed severity: **0**; changed evidence: **1**
- Note: Resolution of one finding was inconclusive: gitleaks did not run in the current scan.

## Findings

### 1. [HIGH] Vulnerable dependency: flask==0.12.4 (PYSEC-2023-62) — fixed in 2.2.5, 2.3.2

- **Scanner:** pip-audit — rule `PYSEC-2023-62`
- **Location:** `-`
- **Category:** dependency — confidence: unknown (scanner said: high)
- **Fingerprint:** `fp2:ff1f8e904c5964f6fbcc8a7f531344bd`
- **Evidence** (scanner-reported, secrets redacted):

```
flask==0.12.4
```
- **Remediation guidance** (advice, not evidence):

  > Why it matters: A dependency with a publicly known vulnerability is used.
  > Potential consequences: Attack techniques for published CVEs are widely available and often trivially applicable.
  > Recommended fix: Upgrade the package to at least the fixed version; review the advisory for breaking changes; verify the fix with a rescan.
  > Scanner-suggested fix: Upgrade flask to 2.3.2 or later

### 2. [HIGH] Possible SQL injection vector through string use.

- **Scanner:** bandit — rule `B608`
- **Location:** `app/db.py:133`
- **Category:** injection — confidence: unknown (scanner said: HIGH)
- **Fingerprint:** `fp2:a24c59e26cf07a8d38a0d1a9fa2f9b09`
- **Evidence** (scanner-reported, secrets redacted):

```
cursor.execute("SELECT * FROM users WHERE name='" + name + "'")
```
- **Remediation guidance** (advice, not evidence):

  > Why it matters: SQL built by string formatting mixes code and data. Attacker-controlled fragments can change query semantics.
  > Potential consequences: Data exfiltration, modification or destruction; in some stacks, full server compromise via stacked queries.
  > Recommended fix: Use parameterized queries or the ORM. Never interpolate values into SQL strings; if identifiers must be dynamic, validate them against an allowlist.
  > Secure pattern: cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
  > References: https://owasp.org/www-community/attacks/SQL_Injection

### 3. [HIGH] Detected subprocess with shell=True. Prefer a command list.

- **Scanner:** semgrep — rule `python.lang.security.audit.subprocess-shell-true`
- **Location:** `app/jobs.py:87`
- **Category:** injection — confidence: unknown (scanner said: ERROR)
- **Fingerprint:** `fp2:ca5e7d4632e0178190d87192beae15b5`
- **Evidence** (scanner-reported, secrets redacted):

```
subprocess.run(user_cmd, shell=True)
```
- **Remediation guidance** (advice, not evidence):

  > Why it matters: A subprocess is started through a shell. If any argument derives from user or environment input, shell metacharacters can turn it into arbitrary command execution.
  > Potential consequences: An attacker who controls part of the command string may execute arbitrary commands with the privileges of the application.
  > Recommended fix: Pass the command as an argument list and set shell=False. Validate or constrain any dynamic values. If a shell is truly required, avoid interpolating untrusted input and prefer shlex.quote on fixed parts.
  > Secure pattern: subprocess.run(["git", "status"], check=True, shell=False)
  > References: https://bandit.readthedocs.io/en/latest/plugins/b602_subprocess_popen_with_shell_equals_true.html; https://owasp.org/www-community/attacks/Command_Injection
  > Scanner-suggested fix: subprocess.run(shlex.split(user_cmd), shell=False)

### 4. [HIGH] AWS Access Key

- **Scanner:** gitleaks — rule `aws-access-token`
- **Location:** `config/settings.py:12`
- **Category:** secret — confidence: unknown (scanner said: high)
- **Fingerprint:** `fp2:67450e9849f0608c55aa0cf0776c2a0e`
- **Evidence** (scanner-reported, secrets redacted):

```
aws_key = "[redacted-token]EXAMP"
```
- **Remediation guidance** (advice, not evidence):

  > Why it matters: A credential matching a known service format was detected.
  > Potential consequences: A working credential in an attacker's hands allows direct access to the linked service under your identity.
  > Recommended fix: Revoke and rotate the credential immediately, remove it from the code and git history, and load it from a secret manager or environment at runtime. For git history remediation use the service's documented revocation flow first.
  > References: https://owasp.org/www-project-top-ten/2023/A07_2023-Identification_and_Authentication_Failures

### 5. [MEDIUM] Detected hardcoded password secret in variable.

- **Scanner:** semgrep — rule `python.lang.security.audit.hardcoded-password-string`
- **Location:** `app/jobs.py:41`
- **Category:** secret — confidence: unknown (scanner said: WARNING)
- **Fingerprint:** `fp2:0d6e0d57aa522c8579a2d04430e076b6`
- **Evidence** (scanner-reported, secrets redacted):

```
DB_PASS = "pla…ed" [redacted]
```
- **Remediation guidance** (advice, not evidence):

  > Why it matters: A credential appears to be embedded in source code. Anything committed to a repository must be treated as public.
  > Potential consequences: Anyone with repository access (or access to git history) obtains the credential; secret scanning on public platforms will flag it.
  > Recommended fix: Remove the literal, move the value to an environment variable or a secret manager, and rotate the credential — removing the code does not remove it from git history. Consider history rewriting only with a coordinated plan; rotation is the reliable fix.
  > Secure pattern: API_KEY = os.environ["API_KEY"]  # injected at runtime
  > References: https://owasp.org/www-project-top-ten/2023/A07_2023-Identification_and_Authentication_Failures

### 6. [LOW] Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.

- **Scanner:** bandit — rule `B101`
- **Location:** `app/validate.py:22`
- **Category:** sast — confidence: unknown (scanner said: LOW)
- **Fingerprint:** `fp2:80b35b6c0e4d19e541cc2cf737b5c454`
- **Evidence** (scanner-reported, secrets redacted):

```
assert token is not None
```
- **Remediation guidance** (advice, not evidence):

  > Why it matters: Static analysis flagged this code pattern as risky.
  > Potential consequences: Depends on the rule; review the scanner description and references for the specific risk.
  > Recommended fix: Review the flagged location, confirm whether the risk applies, and apply the scanner's suggested remediation.

---
_Generated by patchledger 0.1.0. Evidence is scanner-reported; remediation text is guidance from the local knowledge base._
