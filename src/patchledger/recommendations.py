"""Local remediation knowledge base.

Deterministic, offline guidance keyed by scanner rule identity and category.
This is ADVICE, kept strictly separate from evidence: the finding carries what
the scanner observed; this module only suggests what to do about it.

Everything here works with no network and no AI service.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Recommendation:
    """Remediation guidance for a class of findings."""

    category: str
    explanation: str
    consequences: str
    fix: str
    secure_pattern: str = ""
    references: tuple[str, ...] = ()


# ---------------------------------------------------------------- bandit ids
_BANDIT_CATEGORY: dict[str, str] = {
    "B101": "sast",
    "B102": "sast",
    "B103": "sast",
    "B104": "config",
    "B105": "secret",
    "B106": "secret",
    "B107": "secret",
    "B108": "config",
    "B110": "sast",
    "B112": "sast",
    "B301": "injection",
    "B303": "crypto",
    "B304": "crypto",
    "B305": "crypto",
    "B306": "sast",
    "B310": "sast",
    "B311": "crypto",
    "B312": "sast",
    "B313": "sast",
    "B314": "sast",
    "B315": "sast",
    "B316": "sast",
    "B317": "sast",
    "B318": "sast",
    "B319": "sast",
    "B320": "sast",
    "B323": "sast",
    "B324": "crypto",
    "B501": "crypto",
    "B502": "crypto",
    "B503": "crypto",
    "B504": "crypto",
    "B505": "crypto",
    "B506": "injection",
    "B601": "injection",
    "B602": "injection",
    "B603": "injection",
    "B604": "injection",
    "B605": "injection",
    "B606": "injection",
    "B607": "injection",
    "B608": "injection",
    "B610": "injection",
    "B611": "injection",
    "B701": "xss",
}


# ------------------------------------------------------------------- the KB
_KB: list[tuple[tuple[str, ...], Recommendation]] = [
    # ---- shell / command injection
    (
        ("subprocess-shell", "shell=true", "shell_equals_true",
         "b602", "b605", "start-process-with-a-shell"),
        Recommendation(
            category="injection",
            explanation="A subprocess is started through a shell. If any argument "
            "derives from user or environment input, shell metacharacters can turn "
            "it into arbitrary command execution.",
            consequences="An attacker who controls part of the command string may "
            "execute arbitrary commands with the privileges of the application.",
            fix="Pass the command as an argument list and set shell=False. Validate "
            "or constrain any dynamic values. If a shell is truly required, avoid "
            "interpolating untrusted input and prefer shlex.quote on fixed parts.",
            secure_pattern=(
                'subprocess.run(["git", "status"], check=True, shell=False)'
            ),
            references=(
                "https://bandit.readthedocs.io/en/latest/plugins/b602_subprocess_popen_with_shell_equals_true.html",
                "https://owasp.org/www-community/attacks/Command_Injection",
            ),
        ),
    ),
    (
        ("sql-injection", "b608", "raw-sql", "rawsql", "hardcoded-sql-strings"),
        Recommendation(
            category="injection",
            explanation="SQL built by string formatting mixes code and data. "
            "Attacker-controlled fragments can change query semantics.",
            consequences="Data exfiltration, modification or destruction; in some "
            "stacks, full server compromise via stacked queries.",
            fix="Use parameterized queries or the ORM. Never interpolate values "
            "into SQL strings; if identifiers must be dynamic, validate them "
            "against an allowlist.",
            secure_pattern=(
                'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
            ),
            references=("https://owasp.org/www-community/attacks/SQL_Injection",),
        ),
    ),
    (
        ("eval", "b307", "eval-user-input", "exec", "b102"),
        Recommendation(
            category="injection",
            explanation="Executing dynamically built Python code turns any input "
            "influence into code execution.",
            consequences="Arbitrary code execution with the privileges of the "
            "process.",
            fix="Refactor to avoid eval/exec. Parse data with ast.literal_eval or "
            "JSON when the input is data, not code.",
            secure_pattern=("value = json.loads(text)  # instead of eval(text)"),
            references=(),
        ),
    ),
    # ---- unsafe deserialization
    (
        ("yaml-load", "b506", "yaml-load-input", "unsafe-yaml"),
        Recommendation(
            category="injection",
            explanation="yaml.load without a safe loader can construct arbitrary "
            "Python objects from the YAML content.",
            consequences="Remote code execution when untrusted YAML is processed.",
            fix="Use yaml.safe_load (or safe_load_all). Only use full loaders for "
            "trusted, validated input.",
            secure_pattern=("data = yaml.safe_load(text)"),
            references=(),
        ),
    ),
    (
        ("pickle", "b301", "unsafe-pickle", "marshal", "shelve"),
        Recommendation(
            category="injection",
            explanation="Deserializing pickle/marshal data executes embedded "
            "bytecode and can reconstruct arbitrary objects.",
            consequences="Remote code execution when untrusted serialized data is "
            "unpacked.",
            fix="Exchange data with JSON or another data-only format; if pickle is "
            "unavoidable, restrict it to trusted, integrity-protected inputs.",
            references=(),
        ),
    ),
    # ---- secrets
    (
        ("hardcoded", "b105", "b106", "b107",
         "hardcoded-secret", "hardcoded-password", "generic-api-key"),
        Recommendation(
            category="secret",
            explanation="A credential appears to be embedded in source code. "
            "Anything committed to a repository must be treated as public.",
            consequences="Anyone with repository access (or access to git history) "
            "obtains the credential; secret scanning on public platforms will "
            "flag it.",
            fix="Remove the literal, move the value to an environment variable or "
            "a secret manager, and rotate the credential — removing the code does "
            "not remove it from git history. Consider history rewriting only with "
            "a coordinated plan; rotation is the reliable fix.",
            secure_pattern=('API_KEY = os.environ["API_KEY"]  # injected at runtime'),
            references=("https://owasp.org/www-project-top-ten/2023/A07_2023-Identification_and_Authentication_Failures",),
        ),
    ),
    (
        ("aws", "amazon", "s3", "slack", "github-token", "gcp", "azure", "private-key", "ssh"),
        Recommendation(
            category="secret",
            explanation="A credential matching a known service format was detected.",
            consequences="A working credential in an attacker's hands allows "
            "direct access to the linked service under your identity.",
            fix="Revoke and rotate the credential immediately, remove it from the "
            "code and git history, and load it from a secret manager or "
            "environment at runtime. For git history remediation use the service's "
            "documented revocation flow first.",
            references=("https://owasp.org/www-project-top-ten/2023/A07_2023-Identification_and_Authentication_Failures",),
        ),
    ),
    # ---- crypto
    (
        ("md5", "sha1", "b324", "weak-hash", "insecure-hash"),
        Recommendation(
            category="crypto",
            explanation="A hash function without collision or preimage resistance "
            "for security purposes is used.",
            consequences="Forged signatures, tampered data or cracked stored "
            "digests, depending on usage.",
            fix="Use SHA-256 or better for digests; for password storage use a "
            "dedicated password hashing scheme (argon2, bcrypt, scrypt).",
            secure_pattern=("digest = hashlib.sha256(data).hexdigest()"),
            references=(),
        ),
    ),
    (
        ("verify=false", "b501", "cert-validate", "certverify", "no-verify-ssl", "insecure-ssl"),
        Recommendation(
            category="crypto",
            explanation="TLS certificate verification is disabled, so connections "
            "silently accept any certificate.",
            consequences="Man-in-the-middle attackers can read and modify traffic "
            "that the code assumes is protected.",
            fix="Enable certificate verification; if a private CA is needed, pass "
            "its bundle via the verify parameter or system trust store.",
            secure_pattern=('requests.get(url, timeout=30)  # verify defaults to True'),
            references=(),
        ),
    ),
    (
        ("random", "b311", "insecure-random", "weak-random"),
        Recommendation(
            category="crypto",
            explanation="A non-cryptographic generator (random module) is used in "
            "a context that appears to need unpredictability.",
            consequences="Predictable tokens, keys or resets enable impersonation "
            "and guessing attacks.",
            fix="Use the secrets module for tokens, keys and any security-relevant "
            "randomness.",
            secure_pattern=('token = secrets.token_urlsafe(32)'),
            references=(),
        ),
    ),
    # ---- xss / templating
    (
        ("autoescape", "b701", "jinja2-autoescape"),
        Recommendation(
            category="xss",
            explanation="Template autoescaping is disabled, so variables are "
            "inserted into HTML without encoding.",
            consequences="Reflected or stored cross-site scripting against users "
            "of the application.",
            fix="Enable autoescape (select_autoescape) or render through a "
            "Template that escapes by default; mark explicit safe HTML sparingly.",
            secure_pattern=(
                "env = Environment(loader=..., autoescape=select_autoescape())"
            ),
            references=("https://owasp.org/www-community/attacks/xss/",),
        ),
    ),
    (
        ("xss", "cross-site", "dom-based"),
        Recommendation(
            category="xss",
            explanation="Untrusted data appears to reach an HTML/JS sink without "
            "encoding.",
            consequences="Script execution in victims' browsers: session theft, "
            "defacement, drive-by actions on their behalf.",
            fix="Encode output per context (HTML, attribute, URL, JS), use safe "
            "template engines with escaping on, and sanitize rich HTML with a "
            "vetted allowlist library.",
            references=("https://owasp.org/www-community/attacks/xss/",),
        ),
    ),
    # ---- config
    (
        ("debug=true", "b201", "flask-debug", "django-debug"),
        Recommendation(
            category="config",
            explanation="A framework debug mode is enabled in code that may run "
            "in production.",
            consequences="Debug panels expose internals and, in some frameworks, "
            "allow arbitrary code execution from error pages.",
            fix="Drive debug mode from configuration, never default it to True; "
            "run production behind a server config that disables debug features.",
            references=(),
        ),
    ),
    (
        ("bind-all-interfaces", "b104", "0.0.0.0", "bind"),  # noqa: S104 — rule keyword, not a bind
        Recommendation(
            category="config",
            explanation="A service binds to all network interfaces.",
            consequences="The service is reachable from networks it may not be "
            "intended for, bypassing perimeter assumptions.",
            fix="Bind explicitly to the required interface (localhost for local "
            "services) and expose externally only behind a controlled proxy.",
            references=(),
        ),
    ),
    (
        ("tmp", "b108", "hardcoded-tmp", "insecure-temporary"),
        Recommendation(
            category="config",
            explanation="A shared, world-writable temporary directory is used "
            "with a predictable file name.",
            consequences="Other local users can pre-create or swap the file, "
            "leading to data leaks or privilege issues.",
            fix="Create temporary files with tempfile (mkstemp) which uses "
            "randomized names and safe permissions.",
            secure_pattern=(
                "fd = tempfile.NamedTemporaryFile(prefix='app_', delete=False)"
            ),
            references=(),
        ),
    ),
    (
        ("cors", "allow-origin", "wildcard-origin", "access-control"),
        Recommendation(
            category="config",
            explanation="Cross-origin access appears to be granted with a "
            "wildcard (or reflected) origin, letting any website read the "
            "API's responses from a victim's browser.",
            consequences="Credential-bearing cross-site requests become "
            "readable by attacker-controlled origins; combined with cookies "
            "this enables data theft without XSS.",
            fix="Enumerate the origins that genuinely need access and "
            "configure them explicitly; never combine a wildcard origin with "
            "credential support. Reflect the Origin header only after "
            "validating it against an allowlist.",
            secure_pattern=(
                "CORSMiddleware(app, allow_origins=['https://app.example.com'], "
                "allow_credentials=True)"
            ),
            references=(),
        ),
    ),
    (
        ("ssl-version", "insecure-protocol", "b502", "b503", "b504",
         "tls-version", "weak-tls", "ssl-context"),
        Recommendation(
            category="crypto",
            explanation="A TLS protocol version or cipher policy from the "
            "pre-TLS-1.2 era is selected explicitly.",
            consequences="Downgrade and legacy-protocol attacks (POODLE, "
            "BEAST-era issues) become possible against the connection.",
            fix="Do not pin legacy versions: use the default TLS settings of "
            "a current standard library, or explicitly require TLS 1.2+ with "
            "a modern cipher suite.",
            secure_pattern=("ctx = ssl.create_default_context()  # TLS 1.2+ defaults"),
            references=(),
        ),
    ),
    (
        ("try-except-pass", "b110", "swallow", "except-pass"),
        Recommendation(
            category="sast",
            explanation="An exception handler silently discards the error "
            "(`except: pass`), hiding failures — including security-relevant "
            "ones like failed validation or authorization checks.",
            consequences="Attacker-triggered failures disappear: input "
            "validation, auth checks or integrity checks can be bypassed "
            "without any trace in logs.",
            fix="Handle the specific exception types expected and log or "
            "propagate everything else. If a failure is truly benign, say so "
            "in a comment and log it at debug level.",
            secure_pattern=(
                "except ValueError:\n    logger.warning('invalid payload', exc_info=True)"
            ),
            references=(),
        ),
    ),
    (
        ("b101", "assert-used", "assert-for-security"),
        Recommendation(
            category="sast",
            explanation="A Python assert statement is used where a check must "
            "always run. Asserts are stripped when Python runs with -O, so "
            "the check silently vanishes in optimized deployments.",
            consequences="Security validation (authentication, invariants, "
            "authorization assumptions) disappears in production builds.",
            fix="Replace assert with an explicit check that raises (and, for "
            "HTTP contexts, returns a proper error response).",
            secure_pattern=("if token is None:\n    raise PermissionError('missing token')"),
            references=(),
        ),
    ),
]


# ------------------------------------------------------- category fallbacks
_CATEGORY_FALLBACK: dict[str, Recommendation] = {
    "secret": Recommendation(
        category="secret",
        explanation="A credential-like value was detected in the source tree.",
        consequences="Leaked credentials grant direct access under your identity.",
        fix="Rotate the credential, remove the value from code and history, and "
        "inject it at runtime from an environment variable or secret manager.",
    ),
    "dependency": Recommendation(
        category="dependency",
        explanation="A dependency with a publicly known vulnerability is used.",
        consequences="Attack techniques for published CVEs are widely available "
        "and often trivially applicable.",
        fix="Upgrade the package to at least the fixed version; review the "
        "advisory for breaking changes; verify the fix with a rescan.",
    ),
    "injection": Recommendation(
        category="injection",
        explanation="Untrusted input appears to reach a code or query interpreter.",
        consequences="Attackers may execute commands or queries in your context.",
        fix="Separate code from data: parameterize, use safe APIs, validate "
        "against allowlists, and apply least privilege to the executing context.",
    ),
    "crypto": Recommendation(
        category="crypto",
        explanation="A cryptographic primitive is used in a way considered weak.",
        consequences="Protection intended by the design can be broken faster "
        "than expected.",
        fix="Use modern, vetted primitives (SHA-256+, AES-GCM, secrets module, "
        "established libraries) and keep TLS verification enabled.",
    ),
    "xss": Recommendation(
        category="xss",
        explanation="Untrusted data may reach browser-rendered output unencoded.",
        consequences="Cross-site scripting against your users.",
        fix="Encode per output context and prefer templates with autoescaping "
        "enabled.",
    ),
    "config": Recommendation(
        category="config",
        explanation="A configuration choice weakens the runtime security posture.",
        consequences="Exposure beyond intended boundaries or debug features in "
        "production.",
        fix="Prefer restrictive defaults; derive exposure from explicit "
        "configuration instead of code constants.",
    ),
    "sast": Recommendation(
        category="sast",
        explanation="Static analysis flagged this code pattern as risky.",
        consequences="Depends on the rule; review the scanner description and "
        "references for the specific risk.",
        fix="Review the flagged location, confirm whether the risk applies, and "
        "apply the scanner's suggested remediation.",
    ),
    "other": Recommendation(
        category="other",
        explanation="The scanner flagged this location.",
        consequences="Depends on the rule; see the scanner documentation.",
        fix="Review the finding and follow the references provided by the "
        "scanner.",
    ),
}


def classify_category(
    scanner: str, rule_id: str, metadata: dict, message: str = ""
) -> str:
    """Classify a finding into a remediation category (deterministic)."""
    scanner = scanner.lower()
    rule = rule_id.lower()
    text = f"{rule} {message.lower()}"

    if scanner == "gitleaks":
        return "secret"
    if scanner == "pip-audit" or scanner == "trivy":
        return "dependency"

    if scanner == "bandit":
        upper = rule_id.upper()
        if upper in _BANDIT_CATEGORY:
            return _BANDIT_CATEGORY[upper]
        if upper.startswith(("B6",)):
            return "injection"
        if upper.startswith(("B5",)):
            return "crypto"
        if upper.startswith(("B1", "B2", "B3", "B4", "B7")):
            return "sast"

    for keywords, rec in _KB:
        if any(k in rule for k in keywords):
            return rec.category

    if "secret" in text or "password" in text or "token" in text or "credential" in text:
        return "secret"
    if "injection" in text or "sql" in text or "command" in text:
        return "injection"
    if "crypto" in text or "hash" in text or "ssl" in text or "tls" in text:
        return "crypto"
    if "xss" in text or "script" in text:
        return "xss"
    if metadata.get("category") == "security":
        return "sast"
    return "other"


def get_recommendation(
    scanner: str, rule_id: str, metadata: dict, message: str = ""
) -> Recommendation:
    """Look up remediation guidance (rule-specific first, then category)."""
    category = classify_category(scanner, rule_id, metadata, message)
    rule = rule_id.lower()
    for keywords, rec in _KB:
        if category == rec.category and any(k in rule for k in keywords):
            return rec
    return _CATEGORY_FALLBACK[category]
