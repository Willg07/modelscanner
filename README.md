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

- **bandit** runs natively (`python -m bandit`).
- **semgrep CE** runs in Docker (`semgrep/semgrep`, folder mounted read-only), using the local rules in `rules/model_repo.yml` (offline) plus the registry rulesets `p/python` and `p/security-audit` (these need network). Docker Desktop must be running; the first run pulls the image.
- All scanners run in parallel. A scanner that can't run is reported as *skipped* or *error* and the verdict is marked incomplete, never silently clean.
- CE analyzes one file at a time (no cross-file dataflow), so code split across several files can be missed.

## Recommended workflow

```bash
hf download org/model --revision <sha> --local-dir ./models/model   # download once
python -m modelscanner.cli ./models/model --out report-model        # scan the folder
python sandbox/run_sandboxed.py ./models/model --trace              # only for pickle-format weights
```

## Tests

```bash
python -m unittest discover -s tests -v     # venv active; Docker tests skip if the daemon is down
```

`tests/test_sandbox_containment.py` builds a malicious Linux pickle at test time (`posix.system`, never committed), loads it in the sandbox, and asserts the payload **did execute** (so the test isn't vacuous) but ran as uid 10001 with no capabilities, could not write the read-only model folder, and could not open a network connection. Static tests also guard the `docker run` flags (`--network=none`, `--read-only`, `--cap-drop=ALL`, read-only mount, no `--privileged`/docker.sock). Run these after any change to `sandbox/`.

## Limits

A clean result means *no known-bad pattern found*, not *safe*. Scanners are blocklist-based and have been bypassed; backdoors in weights are invisible to static analysis. Prefer `.safetensors`, `torch.load(weights_only=True)`, no `trust_remote_code`, and pin revisions. For high-risk samples use a disposable VM (or gVisor: `--runtime=runsc`) instead of plain Docker.

Only scan/load models you are authorized to handle.
