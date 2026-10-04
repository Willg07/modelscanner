"""Dynamic check: load an untrusted model inside a locked-down Docker container.

Usage:
    python sandbox/run_sandboxed.py PATH_TO_MODEL_DIR [--timeout 120] [--trace]

The container has: no network, read-only root FS, model mounted read-only,
all capabilities dropped, no-new-privileges, memory/pid/CPU limits, non-root.
It attempts torch.load(weights_only=False) -- the dangerous path on purpose --
and reports whether the load completed. With --trace, strace logs syscalls so
you can grep for connect/execve/openat outside the model dir.

This reduces risk; it is not a perfect boundary. For high-risk samples use a
disposable VM (or gVisor: add --runtime=runsc).
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

IMAGE = "modelscanner-sandbox"
HERE = Path(__file__).parent


def sh(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, text=True, **kw)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("model_dir")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--trace", action="store_true", help="strace syscalls (needs SYS_PTRACE)")
    a = ap.parse_args()

    model = Path(a.model_dir).resolve()
    if not model.exists():
        print(f"not found: {model}", file=sys.stderr)
        return 2

    if sh(["docker", "build", "-q", "-t", IMAGE, str(HERE)]).returncode != 0:
        return 2

    cmd = [
        "docker", "run", "--rm",
        "--network=none", "--read-only", "--tmpfs", "/tmp:rw,size=256m,noexec",
        "--cap-drop=ALL", "--security-opt=no-new-privileges",
        "--memory=4g", "--cpus=2", "--pids-limit=128",
        "--user", "10001:10001",
        "-v", f"{model}:/model:ro",
        "-e", f"TRACE={'1' if a.trace else '0'}",
    ]
    if a.trace:
        cmd += ["--cap-add=SYS_PTRACE", "--user", "0:0"]  # strace needs ptrace; still no network
    cmd += [IMAGE]

    try:
        p = sh(cmd, timeout=a.timeout)
    except subprocess.TimeoutExpired:
        print("TIMEOUT: load hung or looped — treat as suspicious.")
        sh(["docker", "ps", "-q", "--filter", f"ancestor={IMAGE}"])
        return 1
    print(f"container exit code: {p.returncode}")
    return p.returncode


if __name__ == "__main__":
    sys.exit(main())
