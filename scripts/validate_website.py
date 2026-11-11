"""Validate website HTML: tag balance, anchor integrity, asset references."""

from html.parser import HTMLParser
from pathlib import Path

WEBSITE = Path(__file__).resolve().parent.parent / "website"
VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input",
        "link", "meta", "param", "source", "track", "wbr"}


class Checker(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.problems: list[str] = []
        self.anchors: set[str] = set()
        self.refs: set[str] = set()
        self.assets: set[str] = set()

    def handle_starttag(self, tag, attrs):
        if tag not in VOID:
            self.stack.append(tag)
        for key, value in attrs:
            if key == "id" and value:
                self.anchors.add(value)
            if key == "href" and value and value.startswith("#"):
                self.refs.add(value[1:])
            if key in ("src", "href") and value and not value.startswith(("#", "http", "data:")):
                self.assets.add(value)

    def handle_endtag(self, tag):
        if tag in VOID:
            return
        if not self.stack:
            self.problems.append(f"unexpected closing tag </{tag}>")
            return
        if self.stack[-1] == tag:
            self.stack.pop()
        else:
            self.problems.append(
                f"mismatched tag </{tag}>, open stack top is <{self.stack[-1]}>"
            )
            # attempt recovery
            if tag in self.stack:
                while self.stack and self.stack[-1] != tag:
                    self.stack.pop()
                if self.stack:
                    self.stack.pop()


def main() -> None:
    index = WEBSITE / "index.html"
    checker = Checker()
    checker.feed(index.read_text(encoding="utf-8"))
    checker.close()

    if checker.stack:
        checker.problems.append(f"unclosed tags at EOF: {checker.stack}")

    for ref in sorted(checker.refs):
        if ref and ref not in checker.anchors:
            checker.problems.append(f"broken internal anchor: #{ref}")

    for asset in sorted(checker.assets):
        if not (WEBSITE / asset).exists():
            checker.problems.append(f"missing asset: {asset}")

    # Every required section (mission list) must exist as an anchor target
    required = [
        "overview", "problem", "features", "how", "scanning", "normalization",
        "verification", "cli", "report", "architecture", "installation", "docs",
        "contributing", "roadmap", "license",
    ]
    for section in required:
        if section not in checker.anchors:
            checker.problems.append(f"missing required section: #{section}")

    if checker.problems:
        for problem in checker.problems:
            print("PROBLEM:", problem)
        raise SystemExit(1)
    print(f"website OK: {len(checker.anchors)} anchors, "
          f"{len(checker.assets)} local assets, all sections present, tags balanced")


if __name__ == "__main__":
    main()
