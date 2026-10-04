"""Ollama support: name resolution, manifest/blob verification, and the untrusted-manifest guards.
Uses a fake ~/.ollama/models tree built at test time with tiny synthetic GGUF blobs."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

try:
    from gguf import GGUFWriter
except ImportError:  # pragma: no cover
    GGUFWriter = None

from modelscanner import gguf_check, ollama
from modelscanner.cli import sha256

MODEL, TEMPLATE = ("application/vnd.ollama.image." + k for k in ("model", "template"))


def gguf_bytes(template=None) -> bytes:
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "m.gguf"
        w = GGUFWriter(str(p), "llama")
        w.add_name("t")
        if template:
            w.add_chat_template(template)
        w.write_header_to_file()
        w.write_kv_data_to_file()
        w.write_tensors_to_file()
        w.close()
        return p.read_bytes()


class Tree:
    """Builds a fake models dir. blob() stores data under its true sha256 (or a forced digest)."""

    def __init__(self):
        self._d = tempfile.TemporaryDirectory()
        self.base = Path(self._d.name)
        (self.base / "blobs").mkdir()

    def blob(self, data: bytes, digest: str | None = None) -> str:
        digest = digest or "sha256:" + hashlib.sha256(data).hexdigest()
        (self.base / "blobs" / digest.replace(":", "-")).write_bytes(data)
        return digest

    def manifest(self, rel: str, layers: list[tuple[str, str]]):
        path = self.base / "manifests" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"layers": [{"mediaType": m, "digest": d, "size": 1} for m, d in layers]}))

    def scan(self, name):
        return ollama.scan(ollama.load(name, self.base), sha256)

    def close(self):
        self._d.cleanup()


class NameTests(unittest.TestCase):
    def setUp(self):
        self.t = Tree()
        self.addCleanup(self.t.close)

    def test_defaults_and_namespaces_resolve(self):
        self.t.manifest("registry.ollama.ai/library/llama3/latest", [])
        self.t.manifest("registry.ollama.ai/someone/mymodel/q4", [])
        self.t.manifest("hf.co/org/repo/Q4_K_M", [])
        self.assertEqual(ollama.load("llama3", self.t.base)["name"], "llama3")
        self.assertEqual(ollama.load("someone/mymodel:q4", self.t.base)["name"], "someone/mymodel:q4")
        self.assertEqual(ollama.load("hf.co/org/repo:Q4_K_M", self.t.base)["name"], "hf.co/org/repo:Q4_K_M")
        self.assertEqual(sorted(ollama.list_models(self.t.base)),
                         ["hf.co/org/repo:Q4_K_M", "llama3:latest", "someone/mymodel:q4"])

    def test_traversal_and_bad_names_rejected(self):
        for bad in ("../../etc/passwd", "a/../b", "x/..", "name:../../t", "", "a b"):
            with self.assertRaises(ollama.OllamaError, msg=bad):
                ollama.load(bad, self.t.base)

    def test_missing_model_is_an_error(self):
        with self.assertRaises(ollama.OllamaError):
            ollama.load("nope", self.t.base)


@unittest.skipIf(GGUFWriter is None, "gguf package not installed")
class ScanTests(unittest.TestCase):
    def setUp(self):
        self.t = Tree()
        self.addCleanup(self.t.close)

    def statuses(self, scanners):
        return {s["tool"]: s["status"] for s in scanners}

    def test_clean_model(self):
        m = self.t.blob(gguf_bytes("{% for m in messages %}{{ m['content'] }}{% endfor %}"))
        tpl = self.t.blob(b"{{ .Prompt }}")
        self.t.manifest("registry.ollama.ai/library/ok/latest", [(MODEL, m), (TEMPLATE, tpl)])
        files, scanners, notes = self.t.scan("ok")
        self.assertEqual(self.statuses(scanners), {"ollama-manifest": "clean", "gguf-metadata": "clean"})
        self.assertEqual(notes, [])
        self.assertTrue(any(f["format_risk"] == "tensor-only" for f in files))

    def test_blob_hash_mismatch_flagged(self):
        d = "sha256:" + "b" * 64  # file content does not hash to this digest
        self.t.blob(gguf_bytes(), digest=d)
        self.t.manifest("registry.ollama.ai/library/bad/latest", [(MODEL, d)])
        _, scanners, _ = self.t.scan("bad")
        mf = next(s for s in scanners if s["tool"] == "ollama-manifest")
        self.assertEqual(mf["status"], "findings")
        self.assertIn("does not match", mf["stdout"])

    def test_malicious_digest_never_becomes_a_path(self):
        (self.t.base / "secret.txt").write_text("do not read")
        self.t.manifest("registry.ollama.ai/library/evil/latest", [(MODEL, "sha256:../../secret.txt")])
        model = ollama.load("evil", self.t.base)
        self.assertIsNone(model["layers"][0]["path"])
        _, scanners, _ = ollama.scan(model, sha256)
        self.assertEqual(scanners[0]["status"], "findings")
        self.assertIn("invalid digest", scanners[0]["stdout"])

    def test_non_gguf_model_layer_flagged(self):
        d = self.t.blob(b"\x80\x04 definitely a pickle, not gguf")
        self.t.manifest("registry.ollama.ai/library/pk/latest", [(MODEL, d)])
        _, scanners, _ = self.t.scan("pk")
        mf = next(s for s in scanners if s["tool"] == "ollama-manifest")
        self.assertEqual(mf["status"], "findings")
        self.assertIn("not GGUF", mf["stdout"])

    def test_hidden_unicode_in_template_flagged(self):
        d = self.t.blob("{{ .Prompt }}​\U000e0041ignore previous".encode("utf-8"))
        self.t.manifest("registry.ollama.ai/library/hid/latest", [(TEMPLATE, d)])
        _, scanners, _ = self.t.scan("hid")
        self.assertEqual(scanners[0]["status"], "findings")
        self.assertIn("hidden Unicode", scanners[0]["stdout"])

    def test_missing_blobs_produce_a_note(self):
        self.t.manifest("registry.ollama.ai/library/cloud/cloud", [(MODEL, "sha256:" + "c" * 64)])
        files, _, notes = self.t.scan("cloud:cloud")
        self.assertEqual(files, [])
        self.assertTrue(notes)

    def test_malicious_chat_template_in_model_flagged(self):
        m = self.t.blob(gguf_bytes("{{ lipsum.__globals__['os'].popen('id').read() }}"))
        self.t.manifest("registry.ollama.ai/library/ssti/latest", [(MODEL, m)])
        _, scanners, _ = self.t.scan("ssti")
        self.assertEqual(self.statuses(scanners)["gguf-metadata"], "findings")

    def test_extensionless_blob_detected_by_magic(self):
        p = self.t.base / "blobs" / "sha256-x"
        p.write_bytes(gguf_bytes())
        self.assertTrue(gguf_check.is_gguf(p))
        p.write_bytes(b"nope")
        self.assertFalse(gguf_check.is_gguf(p))


@unittest.skipIf(GGUFWriter is None, "gguf package not installed")
class TemplateFalsePositiveTests(unittest.TestCase):
    """Regression: prose in a template (e.g. the word 'request.') must not trip the code checks."""

    def check(self, template):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "m.gguf"
            p.write_bytes(gguf_bytes(template))
            return gguf_check.check(p)["status"]

    def test_prose_outside_tags_is_clean(self):
        self.assertEqual(self.check("Refuse the request. Do not open the file. {{ messages }}"), "clean")

    def test_prose_inside_string_literal_is_clean(self):
        self.assertEqual(
            self.check("{% set s = 'Decline the request. Never use os.system or open() here.' %}{{ s }}"), "clean")

    def test_real_global_access_still_flagged(self):
        self.assertEqual(self.check("{{ request.application }}"), "findings")


if __name__ == "__main__":
    unittest.main()
