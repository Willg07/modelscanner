# modelscanner

Security triage for Hugging Face (and local) model files, before you load them.

Downloading a model doesn't run anything. **Loading** it can: pickle-based formats (`.bin`, `.pt`, `.ckpt`, `.pkl`) can execute arbitrary code, and repos that use `trust_remote_code=True` run their Python files. `modelscanner` checks for that first.

| Step | Tools | What it does |
|---|---|---|
| **1. Static scan** | modelscan, picklescan | Looks inside model files for dangerous pickle operations |
| | bandit, semgrep CE | Scans the repo's `.py` files (the `trust_remote_code` surface) |
| | gguf-metadata | For `.gguf` files (not a pickle format): checks the chat template for sandbox-escape constructs and tensor extents for truncation |
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

### What is `--revision`? (optional)

Every Hugging Face model repo is a git repo, and each save of it has a **commit sha**: a long ID such as `a1b2c3d4e5f6…`. `--revision` tells `modelscanner` to download that exact version. If you leave it out, you get the latest version (the `main` branch).

Why pin it: the repo owner can change files on `main` at any time, including swapping in a malicious file after you scanned it. If you scan `main` today and load `main` next week, you may be loading something different from what you scanned. Pinning means the scan and your later load use the same bytes.

```bash
# Without --revision: scans whatever main is right now
python -m modelscanner.cli org/model-name

# With --revision: scans exactly that version
python -m modelscanner.cli org/model-name --revision a1b2c3d4e5f6

# Then load the SAME version you scanned (in Python)
#   AutoModel.from_pretrained("org/model-name", revision="a1b2c3d4e5f6")
```

To find the sha: open the model page, click **Files and versions**, then **History** (or the latest commit link at the top of the file list). The short code next to a commit is its sha. You can paste the short or the full one.

Use `--revision` whenever you plan to run the model afterward; skip it for a quick look. It applies to Hugging Face downloads only. Local files and `ollama:` models are already on disk, so it isn't needed (for Ollama, the manifest digests serve the same purpose).

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
- **UNSUPPORTED**: the tool doesn't read this file format (for example modelscan on a `.gguf`). The report notes when the pickle scanners had nothing to analyze, so a model isn't presented as "scanned" when no scanner actually read it.
- **FINDINGS**: read that scanner's section further down. Don't load the model until you understand it.
- **SKIPPED / ERROR**: the scanner didn't finish, so the verdict says `(incomplete: …)`. Fix the cause (usually Docker isn't running) and re-run. An incomplete result is never reported as clean.

Exit codes: `0` clean, `1` findings, `2` no scanner could run. Use `--out name` to keep reports instead of overwriting `report.md`.

## How the source scanners work

- **bandit** runs natively (`python -m bandit`).
- **semgrep CE** runs in Docker with your folder mounted read-only, using the local rules in `rules/model_repo.yml` (offline) plus the registry rulesets `p/python` and `p/security-audit` (these need network).
- CE analyzes one file at a time, so malicious code split across several files can be missed.
- All scanners run in parallel.

## Ollama models

Scan a model you already pulled with Ollama, by name:

```bash
python -m modelscanner.cli --list-ollama                       # see what's installed
python -m modelscanner.cli ollama:qwen3:8b --out report-qwen3  # NAME[:TAG], default tag is "latest"
python -m modelscanner.cli "ollama:hf.co/org/repo:Q4_K_M"      # Hugging Face imports work too
```

Ollama keeps models as a manifest plus extensionless blobs in `~/.ollama/models` (override with `OLLAMA_MODELS`). `modelscanner` reads the manifest and, for each layer:

- verifies the blob's sha256 matches the manifest digest (catches corruption or tampering; this hashes the whole file, so a 10 GB model takes ~30 s),
- recognises GGUF by its magic bytes and runs the GGUF metadata check on the weights, so a model layer that is *not* GGUF is flagged,
- shows the template, system prompt and parameters, and flags hidden Unicode in them (zero-width, bidi and "tag" characters used to smuggle instructions).

The manifest is treated as untrusted: digests are validated and no path can leave the models folder. Cloud models (for example `…:cloud`) have no local weights, so the report says nothing was analyzed instead of calling them clean. It also works on a folder of blobs: extensionless GGUF files are detected by magic bytes.

## GGUF models

GGUF has no pickle, so modelscan and picklescan don't apply. The `gguf-metadata` check reads only the header (memory-mapped; weights are never loaded and nothing is executed) and flags Jinja constructs in `tokenizer.chat_template` that are used in sandbox-escape payloads (dunder access, `lipsum`/`cycler` globals, `os`/`popen`/`eval`, hard-coded URLs) and tensors that extend past the end of the file. It does **not** detect parser bugs in a specific runtime or a backdoor in the weights, so keep your inference runtime (llama.cpp, Ollama, LM Studio) updated.

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
