"""Editorial guards for specification versions that are still being prepared."""

import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
# Versions published before these guards existed keep their original text.
FIRST_GUARDED = (1, 6, 0)


def guarded_versions():
    rows = json.loads((ROOT / "versions.json").read_text())["versions"]
    return [row["version"] for row in rows
            if tuple(map(int, row["version"].split("."))) >= FIRST_GUARDED]


class SpecificationText(unittest.TestCase):
    def test_sections_are_numbered_without_gaps(self):
        for version in guarded_versions():
            text = (ROOT / "specification" / f"{version}.md").read_text()
            numbers = [int(n) for n in re.findall(r"^## (\d+)\. ", text, re.M)]
            self.assertEqual(numbers, list(range(1, len(numbers) + 1)), version)

    def test_section_references_exist(self):
        for version in guarded_versions():
            text = (ROOT / "specification" / f"{version}.md").read_text()
            last = max(int(n) for n in re.findall(r"^## (\d+)\. ", text, re.M))
            for number in re.findall(r"[Ss]ections? (\d+)", text):
                self.assertLessEqual(int(number), last, f"{version}: section {number}")

    def test_included_library_rules_copy_the_specification(self):
        for version in guarded_versions():
            specification = (ROOT / "specification" / f"{version}.md").read_text()
            included = (ROOT / "archive" / version / "docs/darkbox/large-libraries.md").read_text()
            start = included.index("## ")
            heading = included[start:included.index("\n", start)]
            self.assertIn(heading, specification, version)
            self.assertEqual(included[start:], specification[specification.index(heading):], version)

    def test_normative_text_names_no_implementation(self):
        for version in guarded_versions():
            text = (ROOT / "specification" / f"{version}.md").read_text()
            for word in ("fs2", "Rust SDK", "The SDK uses", "exit code"):
                self.assertNotIn(word, text, f"{version}: {word}")

    def test_readme_lists_every_registered_specification_and_extension(self):
        registry = json.loads((ROOT / "versions.json").read_text())
        section = (ROOT / "README.md").read_text().split("## Version numbers", 1)[1].split("\n## ", 1)[0]
        latest = registry["versions"][-1]["version"]
        self.assertIn(f"1.0.0 to {latest}", section)
        for row in registry.get("extensions", []):
            self.assertIn(row["version"], section, row["namespace"])

    def test_authored_text_has_no_em_dash(self):
        paths = [ROOT / "README.md", ROOT / "CHANGELOG.md", ROOT / "SECURITY.md", ROOT / "conformance/README.md"]
        for version in guarded_versions():
            paths += [ROOT / "specification" / f"{version}.md", ROOT / "archive" / version / "README.md",
                      ROOT / "archive" / version / "docs/darkbox/large-libraries.md"]
        paths += sorted((ROOT / "docs").glob("*.md"))
        for path in paths:
            self.assertNotIn("—", path.read_text(), str(path.relative_to(ROOT)))


if __name__ == "__main__":
    unittest.main()
