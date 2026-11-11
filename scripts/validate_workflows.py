"""Validate GitHub Actions workflow YAML: parseable, well-formed, least-privilege."""

from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((REPO / ".github" / "workflows").glob("*.yml"))
REQUIRED_ACTION_PINS = ("@v",)  # every `uses:` must pin a version


def validate(path: Path) -> list[str]:
    problems: list[str] = []
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        return [f"{path.name}: top level is not a mapping"]
    if "name" not in doc:
        problems.append(f"{path.name}: missing 'name'")
    if "on" not in doc and True in doc:  # YAML 1.1 parses bare `on:` as True
        problems.append(f"{path.name}: 'on' parsed as boolean True — quote it")
    elif "on" not in doc:
        problems.append(f"{path.name}: missing 'on' trigger")
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        problems.append(f"{path.name}: missing or empty 'jobs'")
        return problems
    for job_name, job in jobs.items():
        if not isinstance(job, dict) or not job.get("steps"):
            problems.append(f"{path.name}:{job_name}: job has no steps")
            continue
        runs_on = job.get("runs-on")
        if not runs_on:
            problems.append(f"{path.name}:{job_name}: missing runs-on")
        for step in job["steps"]:
            if not isinstance(step, dict):
                problems.append(f"{path.name}:{job_name}: step is not a mapping")
                continue
            uses = step.get("uses")
            run = step.get("run")
            if not uses and not run:
                problems.append(f"{path.name}:{job_name}: step has neither uses nor run")
            if uses and not any(pin in str(uses) for pin in REQUIRED_ACTION_PINS):
                problems.append(f"{path.name}:{job_name}: action '{uses}' is not version-pinned")
    perms = doc.get("permissions")
    if perms is None:
        problems.append(f"{path.name}: missing top-level 'permissions' (least privilege)")
    return problems


def main() -> None:
    if not WORKFLOWS:
        raise SystemExit("no workflow files found")
    failures = 0
    for path in WORKFLOWS:
        problems = validate(path)
        status = "OK" if not problems else "PROBLEMS"
        print(f"{path.name}: {status}")
        for problem in problems:
            failures += 1
            print(f"  - {problem}")

    # The user-facing example workflow must also be valid YAML inside its fence.
    example = (REPO / "docs" / "example-workflow.md").read_text(encoding="utf-8")
    fence = example.split("```yaml")[1].split("```")[0]
    doc = yaml.safe_load(fence)
    if not (isinstance(doc, dict) and doc.get("jobs")):
        raise SystemExit("example workflow failed to parse or has no jobs")
    perms = doc.get("permissions")
    if perms != {"contents": "read"}:
        raise SystemExit(f"example workflow permissions wrong: {perms}")
    print(f"docs/example-workflow.md embedded YAML: OK (permissions={perms})")

    if failures:
        raise SystemExit(f"{failures} workflow problem(s) found")
    print("all workflows valid")


if __name__ == "__main__":
    main()
