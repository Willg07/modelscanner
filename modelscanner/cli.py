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
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

RISKY_EXT = {".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt", ".h5", ".keras", ".joblib", ".npy", ".npz"}
SAFE_EXT = {".safetensors", ".gguf", ".onnx"}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd: list[str], label: str | None = None, ok_codes: tuple[int, ...] = (0,), finding_codes: tuple[int, ...] = (1,)) -> dict:
    """Run a scanner. status: clean | findings | error | unavailable."""
    name = label or cmd[0]
    if shutil.which(cmd[0]) is None:
        return {"tool": name, "available": False, "status": "unavailable", "reason": "not installed"}
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    except OSError as e:  # e.g. blocked by Windows Application Control
        return {"tool": name, "available": False, "status": "unavailable", "reason": f"could not run: {e}"}
    status = "clean" if p.returncode in ok_codes else "findings" if p.returncode in finding_codes else "error"
    return {
        "tool": name,
        "available": True,
        "status": status,
        "exit_code": p.returncode,
        "stdout": p.stdout,
        "stderr": p.stderr,
    }


RULES_DIR = Path(__file__).resolve().parent.parent / "rules"


def semgrep_docker(root: Path) -> dict:
    """semgrep (CE) in Docker: read-only mount, local rules + registry rules."""
    if shutil.which("docker") is None:
        return {"tool": "semgrep", "available": False, "status": "unavailable", "reason": "docker not installed"}
    if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        return {"tool": "semgrep", "available": False, "status": "unavailable",
                "reason": "docker daemon not running (start Docker Desktop)"}
    src = root if root.is_dir() else root.parent
    cmd = ["docker", "run", "--rm", "-v", f"{src}:/src:ro", "-v", f"{RULES_DIR}:/rules:ro",
           "semgrep/semgrep", "semgrep", "scan", "--config", "/rules",
           "--config", "p/python", "--config", "p/security-audit",  # registry rules need network
           "--error", "--quiet", "--metrics=off", "/src"]
    return run(cmd, label="semgrep")


def source_scanners(root: Path) -> list[dict]:
    """bandit (native) + semgrep (Docker) on repo Python files, run in parallel."""
    if not (root.is_file() and root.suffix == ".py") and not (root.is_dir() and any(root.rglob("*.py"))):
        return []
    with ThreadPoolExecutor(max_workers=2) as ex:
        b = ex.submit(run, [sys.executable, "-m", "bandit", "-r", str(root), "-q"], "bandit")
        s = ex.submit(semgrep_docker, root)
        return [b.result(), s.result()]


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
    L += ["## Summary", "", "| Scanner | Status | Detail |", "|---|---|---|"]
    ran = {s["tool"]: s for s in report["scanners"]}
    for tool in ("modelscan", "picklescan", "bandit", "semgrep"):
        s = ran.get(tool)
        if s is None:
            L.append(f"| {tool} | not run | no `.py` files in the target |")
        elif not s["available"]:
            L.append(f"| {tool} | SKIPPED | {s['reason']} |")
        else:
            L.append(f"| {tool} | {s['status'].upper()} | exit code {s['exit_code']} |")
    L += ["", "Status meanings: **CLEAN** = no known-bad pattern; **FINDINGS** = review the section below;",
          "**ERROR/SKIPPED** = the scanner did not complete, so the result is incomplete.", ""]
    L += ["## Files", "", "| File | Bytes | Format risk | sha256 |", "|---|---|---|---|"]
    for f in report["files"]:
        flag = " (remote code)" if f["remote_code"] else ""
        L.append(f"| {f['path']}{flag} | {f['bytes']} | {f['format_risk']} | `{f['sha256'][:16]}…` |")
    for s in report["scanners"]:
        L += ["", f"## {s['tool']}", ""]
        if not s["available"]:
            L.append(f"_Skipped — {s['reason']}._")
            continue
        L += [f"Status: **{s['status']}** (exit {s['exit_code']})", "", "```",
              (s["stdout"] + s["stderr"]).strip() or "(no output)", "```"]
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
        with ThreadPoolExecutor(max_workers=2) as ex:
            fs = [ex.submit(run, ["modelscan", "-p", str(path)]),
                  ex.submit(run, ["picklescan", "--path", str(path)])]
            scanners = [f.result() for f in fs]
        if not any(s["available"] for s in scanners):
            print("Neither modelscan nor picklescan is installed (pip install -r requirements.txt).", file=sys.stderr)
            return 2
        scanners += source_scanners(path)
        findings = any(s["status"] == "findings" for s in scanners)
        degraded = [s["tool"] for s in scanners if s["status"] in ("error", "unavailable")]
        files = inventory(path)
        report = {
            "target": a.target, "revision": a.revision,
            "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            "verdict": ("FINDINGS" if findings else "no known-bad patterns found")
            + (f" (incomplete: {', '.join(degraded)} did not run cleanly)" if degraded else ""),
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
