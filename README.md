# modelscanner

Security triage for Hugging Face (and local) model files, before you load them.

Downloading a model doesn't run anything. **Loading** it can: pickle-based formats (`.bin`, `.pt`, `.ckpt`, `.pkl`) can execute arbitrary code, and repos that use `trust_remote_code=True` run their Python files. `modelscanner` checks for that first.

| Step | Tools | What it does |
|---|---|---|
| **1. Static scan** | modelscan, picklescan | Looks inside model files for dangerous pickle operations |
| | bandit, semgrep CE | Scans the repo's `.py` files (the `trust_remote_code` surface) |
| **2. Dynamic load** *(optional)* | Docker | Loads pickle-format weights in a locked-down container (no network, read-only, non-root) |

Everything writes one report: `report.md` (readable) and `report.json` (machine-readable).

## Prerequisites

- **Python 3.12 or older.** `modelscan` doesn't install on 3.13/3.14. [`uv`](https://docs.astral.sh/uv/) makes this easy.
- **Docker Desktop**, running, for semgrep and the sandbox. Without it, those parts are skipped and the report says it's incomplete.
- Network access for the first run: Docker pulls the semgrep image, and semgrep downloads its rulesets.

## Quick start

```bash
git clone https://github.com/Willg07/modelscanner
cd modelscanner

uv venv --python 3.12 .venv
.venv\Scripts\activate            # macOS/Linux: source .venv/bin/activate
uv pip install -r requirements.txt
```

Scan a model. Pick **one**:

```bash
# A. Let the tool download, scan, and clean up (simplest)
python -m modelscanner.cli org/model-name --revision <commit-sha>

# B. Download once, scan the folder (better for large models; you keep the files)
hf download org/model-name --revision <commit-sha> --local-dir ./models/model-name
python -m modelscanner.cli ./models/model-name --out report-model-name
```

Find the commit sha on the model's **Files and versions** page. Pinning it means the repo can't change between your scan and your use.

Only if the model has pickle-format weights *and* you need to confirm what loading does:

```bash
python sandbox/run_sandboxed.py ./models/model-name --trace
```

## Reading the report

`report.md` starts with a verdict and a summary table, for example:

| Scanner | Status | Detail |
|---|---|---|
| modelscan | FINDINGS | exit code 1 |
| picklescan | CLEAN | exit code 0 |
| bandit | not run | no `.py` files in the target |
| semgrep | SKIPPED | docker daemon not running |

- **CLEAN**: no known-bad pattern found.
- **FINDINGS**: read that scanner's section further down. Don't load the model until you understand it.
- **SKIPPED / ERROR**: the scanner didn't finish, so the verdict says `(incomplete: …)`. Fix the cause (usually Docker isn't running) and re-run. An incomplete result is never reported as clean.

Exit codes: `0` clean, `1` findings, `2` no scanner could run. Use `--out name` to keep reports instead of overwriting `report.md`.

## How the source scanners work

- **bandit** runs natively (`python -m bandit`).
- **semgrep CE** runs in Docker with your folder mounted read-only, using the local rules in `rules/model_repo.yml` (offline) plus the registry rulesets `p/python` and `p/security-audit` (these need network).
- CE analyzes one file at a time, so malicious code split across several files can be missed.
- All scanners run in parallel.

## Tests

```bash
python -m unittest discover -s tests -v     # Docker tests skip if the daemon is down
```

`tests/test_sandbox_containment.py` builds a malicious Linux pickle at test time (never committed), loads it in the sandbox, and asserts the payload **did execute** (so the test isn't vacuous) but ran as a non-root user with no capabilities, could not write the read-only model folder, and could not reach the network. Static tests guard the `docker run` flags. `tests/test_report.py` checks the report summary. Run these after changing anything in `sandbox/` or the report code.

## Limits (please read)

A clean result means *no known-bad pattern found*, **not** *safe*:

- Scanners are blocklist-based and have been bypassed before.
- A backdoor hidden in the weights is invisible to static analysis.
- Docker shares your host's kernel. It blocks file and network access but isn't a perfect boundary. For high-risk samples use a disposable VM, or gVisor (`--runtime=runsc`).

Safer habits: prefer `.safetensors`, load with `torch.load(..., weights_only=True)`, avoid `trust_remote_code`, and pin revisions.

Only scan and load models you are authorized to handle.
