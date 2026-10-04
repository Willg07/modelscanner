# modelscanner

Security triage for Hugging Face (and local) model files.

1. **Static scan** — runs `modelscan` + `picklescan`, inventories files (sha256, pickle-capable vs tensor-only, remote-code `.py`), writes `report.md` + `report.json`. If the target contains `.py` files (the `trust_remote_code` attack surface), it also runs **bandit** and **semgrep** (`p/python`, `p/security-audit`) on them.
2. **Dynamic load** — loads pickle-format weights inside a locked-down Docker container (no network, read-only FS, dropped caps, non-root, resource limits), optionally with `strace`.

```bash
# modelscan needs Python <=3.12 (not 3.13/3.14)
uv venv --python 3.12 .venv && .venv\Scripts\activate
uv pip install -r requirements.txt

# static
python -m modelscanner.cli ./some_model_dir
python -m modelscanner.cli org/model-name --revision <commit-sha>   # downloads, scans, deletes

# dynamic (needs Docker)
python sandbox/run_sandboxed.py ./some_model_dir --trace
```

Exit codes: `0` clean, `1` findings (or suspicious behavior), `2` tool/usage error.

## Source scanners (bandit, semgrep)

Invoked as `python -m bandit` / `python -m semgrep`, so they don't depend on PATH launcher shims. A scanner that can't run is reported as *skipped* or *error* and the verdict is marked incomplete, never silently clean.

- **semgrep** is not natively supported on Windows (and its binaries may be blocked by Application Control). Run it under WSL or Docker/Linux. Its rulesets download from the semgrep registry, so it needs network access.

## Limits

A clean result means *no known-bad pattern found*, not *safe*. Scanners are blocklist-based and have been bypassed; backdoors in weights are invisible to static analysis. Prefer `.safetensors`, `torch.load(weights_only=True)`, no `trust_remote_code`, and pin revisions. For high-risk samples use a disposable VM (or gVisor: `--runtime=runsc`) instead of plain Docker.

Only scan/load models you are authorized to handle.
