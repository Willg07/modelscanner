"""Runs INSIDE the container. Tries to load every pickle-capable file in /model."""
import os
import subprocess
import sys
from pathlib import Path

EXT = {".pt", ".pth", ".bin", ".ckpt", ".pkl", ".pickle"}


def load_all() -> int:
    bad = 0
    import torch

    for p in sorted(Path("/model").rglob("*")):
        if p.suffix.lower() not in EXT:
            continue
        try:
            # weights_only=False is deliberate: this is the exploitable path we are testing.
            torch.load(p, map_location="cpu", weights_only=False)
            print(f"LOADED  {p}")
        except Exception as e:  # noqa: BLE001
            bad += 1
            print(f"FAILED  {p}: {type(e).__name__}: {e}")
    return bad


if __name__ == "__main__":
    if os.environ.get("TRACE") == "1" and os.environ.get("_TRACED") != "1":
        env = dict(os.environ, _TRACED="1")
        rc = subprocess.call(
            ["strace", "-f", "-o", "/tmp/trace.log", "-e", "trace=network,process,file", sys.executable, __file__],
            env=env,
        )
        suspicious = [
            l for l in Path("/tmp/trace.log").read_text(errors="ignore").splitlines()
            if ("connect(" in l or "execve(" in l) and "/usr" not in l and "/opt" not in l
        ]
        print(f"--- {len(suspicious)} suspicious connect/execve syscalls ---")
        print("\n".join(suspicious[:50]))
        sys.exit(rc or (1 if suspicious else 0))
    sys.exit(1 if load_all() else 0)
