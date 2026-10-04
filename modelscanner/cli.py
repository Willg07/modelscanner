"""Static scan of a model file/directory/HF repo with modelscan + picklescan.

Usage:
    python -m modelscanner.cli PATH_OR_HF_REPO [--revision SHA] [--out report]

Exit code: 0 = no findings, 1 = findings, 2 = tool/usage error.
A clean scan means "no known-bad pattern found", not "safe".
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

RISKY_EXT = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".h5", ".keras", ".joblib", ".npy", ".npz"}
SAFE_EXT = {".safetensors", ".gguf", ".onnx"}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd: list[str]) -> dict:
    if shutil.which(cmd[0]) is None:
        return {"tool": cmd[0], "available": False}
    p = subprocess.run(cmd, capture_output=True, text=True)
    return {
        "tool": cmd[0],
        "available": True,
        "exit_code": p.returncode,
        "stdout": p.stdout,
        "stderr": p.stderr,
    }


def fetch_hf(repo: str, revision: str | None, dest: Path) -> Path:
    from huggingface_hub import snapshot_download  # lazy: only needed for repos

    return Path(snapshot_download(repo_id=repo, revision=revision, local_dir=dest))


def inventory(root: Path) -> list[dict]:
    files = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())
    out = []
    for p in files:
        ext = p.suffix.lower()
        out.append({
            "path": str(p.relative_to(root.parent if root.is_file() else root)),
            "bytes": p.stat().st_size,
            "sha256": sha256(p),
            "format_risk": "pickle-capable" if ext in RISKY_EXT else "tensor-only" if ext in SAFE_EXT else "other",
            "remote_code": ext == ".py",
        })
    return out


def render_md(report: dict) -> str:
    L = [f"# Model scan report", "", f"- Target: `{report['target']}`", f"- Revision: `{report['revision'] or 'n/a'}`",
         f"- Scanned: {report['timestamp']}", f"- Verdict: **{report['verdict']}**", ""]
    L += ["## Files", "", "| File | Bytes | Format risk | sha256 |", "|---|---|---|---|"]
    for f in report["files"]:
        flag = " (remote code)" if f["remote_code"] else ""
        L.append(f"| {f['path']}{flag} | {f['bytes']} | {f['format_risk']} | `{f['sha256'][:16]}…` |")
    for s in report["scanners"]:
        L += ["", f"## {s['tool']}", ""]
        if not s["available"]:
            L.append("_Not installed — skipped._")
            continue
        L += [f"Exit code: {s['exit_code']}", "", "```", (s["stdout"] + s["stderr"]).strip() or "(no output)", "```"]
    L += ["", "> A clean scan means no *known-bad* pattern was found. It does not prove safety;",
          "> backdoors in weights are not detectable statically. Load untrusted pickle-format",
          "> models only in the sandbox (`sandbox/run_sandboxed.py`)."]
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="local file/dir, or a Hugging Face repo id (org/name)")
    ap.add_argument("--revision", help="HF commit sha to pin (recommended)")
    ap.add_argument("--out", default="report", help="output basename (writes .json and .md)")
    a = ap.parse_args()

    tmp = None
    path = Path(a.target)
    try:
        if not path.exists():
            tmp = Path(tempfile.mkdtemp(prefix="modelscanner-"))
            path = fetch_hf(a.target, a.revision, tmp)
        scanners = [
            run(["modelscan", "-p", str(path)]),
            run(["picklescan", "--path", str(path)]),
        ]
        if not any(s["available"] for s in scanners):
            print("Neither modelscan nor picklescan is installed (pip install -r requirements.txt).", file=sys.stderr)
            return 2
        findings = any(s["available"] and s["exit_code"] != 0 for s in scanners)
        files = inventory(path)
        report = {
            "target": a.target, "revision": a.revision,
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "verdict": "FINDINGS" if findings else "no known-bad patterns found",
            "files": files, "scanners": scanners,
        }
        Path(f"{a.out}.json").write_text(json.dumps(report, indent=2))
        Path(f"{a.out}.md").write_text(render_md(report), encoding="utf-8")
        print(f"{report['verdict']} -> {a.out}.md / {a.out}.json")
        return 1 if findings else 0
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
