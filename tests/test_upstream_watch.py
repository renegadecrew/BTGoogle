import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import check_antigravity_upstream as watch


class UpstreamWatchTests(unittest.TestCase):
    def test_hooks_extractor_keeps_contract_and_decision_blocks(self):
        html = """
        <main><h1>Hooks</h1>
        <p>PreToolUse receives a toolCall object and a tool name.</p>
        <li>The force_ask decision always requests approval.</li>
        <p>Unrelated editor theme details.</p></main>
        """
        text = watch.relevant_text(html, "hooks_contract")
        self.assertIn("PreToolUse", text)
        self.assertIn("force_ask", text)
        self.assertNotIn("Unrelated editor theme", text)

    def test_changelog_extractor_keeps_release_context_for_hook_updates(self):
        html = """
        <main><h2>v9.8.7</h2><p>October 2, 2026</p>
        <h3>Hook decision compatibility</h3>
        <li>Added hookEventName and cwd to the PreToolUse payload.</li>
        <h3>Unrelated color improvements</h3><li>Added a blue theme.</li></main>
        """
        text = watch.relevant_text(html, "ide_changelog")
        self.assertIn("v9.8.7", text)
        self.assertIn("October 2, 2026", text)
        self.assertIn("hookEventName", text)
        self.assertNotIn("Added a blue theme", text)

    def test_unknown_source_is_rejected(self):
        with self.assertRaises(ValueError):
            watch.relevant_text("<p>anything</p>", "gemini_api")


if __name__ == "__main__":
    unittest.main()