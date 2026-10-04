"""GGUF metadata check, using tiny synthetic GGUF files built at test time."""
import tempfile
import unittest
from pathlib import Path

try:
    from gguf import GGUFWriter
except ImportError:  # pragma: no cover
    GGUFWriter = None

from modelscanner import gguf_check


def make_gguf(path: Path, template: str | None) -> None:
    w = GGUFWriter(str(path), "llama")
    w.add_name("test-model")
    if template is not None:
        w.add_chat_template(template)
    w.write_header_to_file()
    w.write_kv_data_to_file()
    w.write_tensors_to_file()
    w.close()


@unittest.skipIf(GGUFWriter is None, "gguf package not installed")
class GgufCheckTests(unittest.TestCase):
    def check(self, template):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "m.gguf"
            make_gguf(p, template)
            return gguf_check.check(p)

    def test_benign_template_is_clean(self):
        r = self.check("{% for m in messages %}{{ m['role'] }}: {{ m['content'] }}\n{% endfor %}")
        self.assertEqual(r["status"], "clean", r["stdout"])

    def test_no_template_is_clean(self):
        self.assertEqual(self.check(None)["status"], "clean")

    def test_sandbox_escape_template_flagged(self):
        r = self.check("{{ ''.__class__.__mro__[1].__subclasses__() }}")
        self.assertEqual(r["status"], "findings")
        self.assertIn("dunder", r["stdout"])

    def test_code_execution_keyword_flagged(self):
        r = self.check("{{ lipsum.__globals__['os'].popen('id').read() }}")
        self.assertEqual(r["status"], "findings")

    def test_non_gguf_file_is_error_not_clean(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "fake.gguf"
            p.write_bytes(b"not a gguf file at all" * 10)
            self.assertEqual(gguf_check.check(p)["status"], "error")


if __name__ == "__main__":
    unittest.main()
