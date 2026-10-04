"""bandit/semgrep must run only when the target has .py files (the trust_remote_code surface).
The real scanners are stubbed, so these tests need neither Docker nor bandit."""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from modelscanner import cli


def fake_result(tool):
    return {"tool": tool, "available": True, "status": "clean", "exit_code": 0, "stdout": "", "stderr": ""}


class SourceGatingTests(unittest.TestCase):
    def scan(self, root: Path):
        with mock.patch.object(cli, "run", side_effect=lambda cmd, label=None, **kw: fake_result(label or cmd[0])) as run, \
             mock.patch.object(cli, "semgrep_docker", side_effect=lambda r: fake_result("semgrep")) as sg:
            return cli.source_scanners(root), run, sg

    def test_no_py_files_runs_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "model.safetensors").write_bytes(b"x")
            (root / "config.json").write_text("{}")
            result, run, sg = self.scan(root)
        self.assertEqual(result, [])
        run.assert_not_called()
        sg.assert_not_called()

    def test_py_file_in_directory_runs_both(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "sub").mkdir()
            (root / "sub" / "modeling_x.py").write_text("x = 1\n")  # nested counts too
            result, run, sg = self.scan(root)
        self.assertEqual([r["tool"] for r in result], ["bandit", "semgrep"])
        run.assert_called_once()
        sg.assert_called_once()

    def test_single_py_file_target_runs_both(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "tokenizer.py"
            f.write_text("x = 1\n")
            result, _, _ = self.scan(f)
        self.assertEqual([r["tool"] for r in result], ["bandit", "semgrep"])

    def test_single_non_py_file_target_runs_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "model.gguf"
            f.write_bytes(b"GGUF")
            result, run, sg = self.scan(f)
        self.assertEqual(result, [])
        run.assert_not_called()
        sg.assert_not_called()


if __name__ == "__main__":
    unittest.main()
