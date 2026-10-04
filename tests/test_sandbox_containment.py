"""Regression tests: the sandbox must contain a malicious Linux pickle.

The pickle is built at test time (never committed). It calls posix.system, which
resolves on Linux, so it really executes inside the container. Tests assert BOTH
that the payload ran (so the test is not vacuous) and that every escape attempt
was contained. Run:  python -m unittest discover -s tests -v
Docker tests are skipped when the daemon is unavailable.
"""
import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("run_sandboxed", ROOT / "sandbox" / "run_sandboxed.py")
run_sandboxed = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run_sandboxed)

# Single-line shell payload; each line of output is a marker the tests assert on.
PAYLOAD = (
    "echo MARK_EXECUTED; "
    "echo MARK_UID=$(id -u); "
    "grep CapEff /proc/self/status | tr -d '[:space:]' | sed 's/^/MARK_/'; "
    "(echo x > /model/pwn) 2>/dev/null && echo MARK_MODEL_WRITABLE || echo MARK_MODEL_READONLY; "
    "python -c \"import socket;socket.create_connection(('1.1.1.1',53),3);print('MARK_NET_OPEN')\" "
    "2>/dev/null || echo MARK_NET_BLOCKED"
)


def build_pickle(path: Path) -> None:
    assert "\n" not in PAYLOAD and "\\" not in PAYLOAD
    # Protocol 0: GLOBAL posix.system, MARK, UNICODE string, TUPLE, REDUCE, STOP.
    path.write_bytes(b"cposix\nsystem\n(V" + PAYLOAD.encode("ascii") + b"\ntR.")


def docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


class StaticFlagTests(unittest.TestCase):
    """Cheap checks that run without Docker: nobody weakens the docker run flags."""

    def test_containment_flags_present(self):
        cmd = run_sandboxed.build_cmd(Path("/m"))
        for flag in ("--network=none", "--read-only", "--cap-drop=ALL",
                     "--security-opt=no-new-privileges"):
            self.assertIn(flag, cmd)
        self.assertIn("10001:10001", cmd)
        self.assertTrue(any(a.endswith(":/model:ro") for a in cmd), "model mount must be read-only")
        self.assertFalse(any(a.startswith("--privileged") for a in cmd))
        self.assertFalse(any("docker.sock" in a for a in cmd))

    def test_trace_mode_still_has_no_network(self):
        cmd = run_sandboxed.build_cmd(Path("/m"), trace=True)
        self.assertIn("--network=none", cmd)
        self.assertIn("--read-only", cmd)


class ScannerTests(unittest.TestCase):
    def test_modelscan_flags_linux_pickle(self):
        if shutil.which("modelscan") is None:
            self.skipTest("modelscan not installed")
        with tempfile.TemporaryDirectory() as d:
            build_pickle(Path(d) / "evil_linux.pkl")
            p = subprocess.run(["modelscan", "-p", d], capture_output=True, text=True,
                               encoding="utf-8", errors="replace")
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("posix", p.stdout)


@unittest.skipUnless(docker_ready(), "docker daemon not available")
class SandboxContainmentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = Path(tempfile.mkdtemp(prefix="msc-contain-"))
        build_pickle(cls.dir / "evil_linux.pkl")
        p = subprocess.run(
            [sys.executable, str(ROOT / "sandbox" / "run_sandboxed.py"), str(cls.dir), "--timeout", "300"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900,
        )
        cls.out = p.stdout + p.stderr
        cls.code = p.returncode

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def test_payload_actually_executed(self):
        # Guards against a vacuous pass: if this fails the other assertions prove nothing.
        self.assertIn("MARK_EXECUTED", self.out, self.out)

    def test_runs_as_unprivileged_user(self):
        self.assertIn("MARK_UID=10001", self.out, self.out)

    def test_no_capabilities(self):
        self.assertIn("MARK_CapEff:0000000000000000", self.out, self.out)

    def test_model_dir_is_read_only(self):
        self.assertIn("MARK_MODEL_READONLY", self.out, self.out)
        self.assertNotIn("MARK_MODEL_WRITABLE", self.out)
        self.assertFalse((self.dir / "pwn").exists(), "payload wrote to the host folder")

    def test_network_blocked(self):
        self.assertIn("MARK_NET_BLOCKED", self.out, self.out)
        self.assertNotIn("MARK_NET_OPEN", self.out)

    def test_harness_reports_failure(self):
        self.assertNotEqual(self.code, 0, "harness must not report a malicious load as clean")


if __name__ == "__main__":
    unittest.main()
