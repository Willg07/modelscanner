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


if __name__ == "__main__":
    unittest.main()
