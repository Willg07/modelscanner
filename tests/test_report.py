"""Report rendering: the summary table must show every scanner and never hide a gap."""
import unittest

from modelscanner.cli import render_md


def report(scanners):
    return {"target": "t", "revision": None, "timestamp": "now", "verdict": "v",
            "files": [], "scanners": scanners}


def scanner(tool, status, code=0, reason=None):
    if status == "unavailable":
        return {"tool": tool, "available": False, "status": status, "reason": reason}
    return {"tool": tool, "available": True, "status": status, "exit_code": code, "stdout": "", "stderr": ""}


class SummaryTableTests(unittest.TestCase):
    def test_all_four_scanners_listed_with_status(self):
        md = render_md(report([
            scanner("modelscan", "findings", 1), scanner("picklescan", "clean"),
            scanner("bandit", "findings", 1), scanner("semgrep", "unavailable", reason="docker daemon not running"),
        ]))
        self.assertIn("## Summary", md)
        self.assertIn("| modelscan | FINDINGS | exit code 1 |", md)
        self.assertIn("| picklescan | CLEAN | exit code 0 |", md)
        self.assertIn("| semgrep | SKIPPED | docker daemon not running |", md)

    def test_source_scanners_marked_not_run_without_py_files(self):
        md = render_md(report([scanner("modelscan", "clean"), scanner("picklescan", "clean")]))
        self.assertIn("| bandit | not run |", md)
        self.assertIn("| semgrep | not run |", md)

    def test_summary_comes_before_details(self):
        md = render_md(report([scanner("modelscan", "clean"), scanner("picklescan", "clean")]))
        self.assertLess(md.index("## Summary"), md.index("## Files"))


class InventoryTests(unittest.TestCase):
    def test_hf_cache_bookkeeping_is_excluded(self):
        import tempfile
        from pathlib import Path

        from modelscanner.cli import inventory

        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "model.bin").write_bytes(b"x")
            (root / ".cache" / "huggingface" / "download").mkdir(parents=True)
            (root / ".cache" / "huggingface" / "download" / "model.bin.metadata").write_text("m")
            paths = [f["path"] for f in inventory(root)]
        self.assertEqual(paths, ["model.bin"])

if __name__ == "__main__":
    unittest.main()
