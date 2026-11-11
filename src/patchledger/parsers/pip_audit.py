"""pip-audit JSON parser (output of ``pip-audit --format json``)."""

from __future__ import annotations

from typing import Any

from patchledger.parsers.common import ParseResult, RawFinding


def parse_pip_audit(data: Any, scan_root: str | None = None) -> ParseResult:
    """Parse pip-audit JSON output into raw findings.

    Each vulnerable dependency becomes one finding per vulnerability, with
    ``package==version`` carried in the message so fingerprints change when a
    package is upgraded (that is what makes dependency fixes verifiable).
    """
    if isinstance(data, dict):
        data = data.get("dependencies")
    if not isinstance(data, list):
        raise ValueError("pip-audit report must be a JSON array of dependencies")

    findings: list[RawFinding] = []
    warnings: list[str] = []

    for idx, dep in enumerate(data):
        if not isinstance(dep, dict):
            warnings.append(f"dependencies[{idx}] is not an object; skipped")
            continue

        name = str(dep.get("name") or "").strip()
        version = str(dep.get("version") or "").strip()
        if not name:
            warnings.append(f"dependencies[{idx}] has no package name; skipped")
            continue

        vulns = dep.get("vulns")
        if not isinstance(vulns, list) or not vulns:
            continue  # clean dependency: nothing to record

        for v_idx, vuln in enumerate(vulns):
            if not isinstance(vuln, dict):
                warnings.append(f"dependencies[{idx}].vulns[{v_idx}] is not an object; skipped")
                continue

            vuln_id = str(vuln.get("id") or "").strip()
            if not vuln_id:
                warnings.append(
                    f"dependencies[{idx}].vulns[{v_idx}] has no vulnerability id; skipped"
                )
                continue

            aliases = vuln.get("aliases")
            alias_list = (
                [str(a) for a in aliases if isinstance(a, str)] if isinstance(aliases, list) else []
            )
            fix_versions = vuln.get("fix_versions")
            fix_list = (
                [str(v) for v in fix_versions if isinstance(v, str)]
                if isinstance(fix_versions, list)
                else []
            )

            description = str(vuln.get("description") or "")
            message = f"Vulnerable dependency: {name}=={version} ({vuln_id})"
            if fix_list:
                message += f" — fixed in {', '.join(fix_list)}"

            findings.append(
                RawFinding(
                    scanner="pip-audit",
                    rule_id=vuln_id,
                    message=message,
                    description=description,
                    file_path=None,  # dependency findings are not file findings
                    evidence=f"{name}=={version}",
                    severity_hint="high",  # explicit mapping happens in the normalizer
                    fix=f"Upgrade {name} to "
                    + (", ".join(fix_list) if fix_list else "a non-vulnerable version"),
                    references=alias_list,
                    metadata={
                        "package": name,
                        "installed_version": version,
                        "fix_versions": fix_list,
                        "aliases": alias_list,
                    },
                )
            )

    return ParseResult(scanner="pip-audit", findings=findings, warnings=warnings)
