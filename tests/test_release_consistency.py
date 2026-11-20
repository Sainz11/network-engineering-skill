from pathlib import Path
import unittest


class TestReleaseConsistency(unittest.TestCase):
    def test_skill_mirrors_match_canonical_skill(self):
        root = Path(__file__).resolve().parent.parent
        canonical = (root / "SKILL.md").read_bytes()
        self.assertEqual((root / ".claude/skills/network-engineering/SKILL.md").read_bytes(), canonical)
        self.assertEqual((root / ".agents/skills/network-engineering/SKILL.md").read_bytes(), canonical)

    def test_skill_explicitly_excludes_continuous_monitoring(self):
        root = Path(__file__).resolve().parent.parent
        skill = (root / "SKILL.md").read_text(encoding="utf-8").casefold()
        self.assertIn("continuous monitoring/background polling/automatic alerts: **out of scope**", skill)
        self.assertNotIn("low-impact monitoring only", skill)

    def test_dependency_manifests_are_present_and_separate_dev_tools(self):
        root = Path(__file__).resolve().parent.parent
        runtime = (root / "requirements.txt").read_text(encoding="utf-8")
        dev = (root / "requirements-dev.txt").read_text(encoding="utf-8")
        self.assertIn("cryptography==46.0.4", runtime)
        self.assertIn("-r requirements.txt", dev)
        self.assertIn("pytest==9.0.2", dev)


if __name__ == "__main__":
    unittest.main()
