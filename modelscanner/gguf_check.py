"""GGUF metadata checks. GGUF is not a pickle format, so modelscan/picklescan skip it.

The practical risks are (1) a malicious Jinja chat template (rendered by some runtimes)
and (2) malformed headers that target parser bugs. This reads metadata only (memory-mapped,
never loads weights, never executes anything) and reports:
  - suspicious Jinja constructs in tokenizer.chat_template
  - tensor extents that fall outside the file
Result shape matches modelscanner.cli.run(): status clean | findings | error.
"""
from __future__ import annotations

import re
from pathlib import Path

# Only text inside Jinja tags ({{ }} / {% %}) can execute; prose outside them is just text.
TAG_RE = re.compile(r"\{\{.*?\}\}|\{%.*?%\}", re.S)
STR_RE = re.compile(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"")

# Constructs used in Jinja sandbox-escape / SSTI payloads. Legit chat templates don't use these.
# RAW patterns run on tag bodies as written (a dunder inside a string literal is still suspicious);
# CODE patterns run with string literals blanked, so prose inside quotes can't trigger them.
RAW_SUSPICIOUS = [
    (r"__\w+__", "dunder attribute access"),
    (r"\.\s*(mro|subclasses|globals|builtins)\b|\bgetattr\b|\|\s*attr\s*\(", "object-graph traversal"),
    (r"https?://", "hard-coded URL in template code"),
]
CODE_SUSPICIOUS = [
    (r"\b(lipsum|cycler|joiner|config|request|self)\b\s*[.\[]", "Jinja global object access"),
    (r"\b(import|eval|exec|compile|open|popen|system|subprocess|os)\b\s*[.(]", "code/process execution keyword"),
]


def is_gguf(path: Path) -> bool:
    """GGUF files start with the magic bytes b'GGUF' (Ollama blobs have no extension)."""
    try:
        with path.open("rb") as f:
            return f.read(4) == b"GGUF"
    except OSError:
        return False


def _field_text(reader, key: str) -> str | None:
    f = reader.fields.get(key)
    if f is None:
        return None
    try:
        return str(f.contents())
    except Exception:  # noqa: BLE001 - older gguf versions
        return bytes(f.parts[f.data[0]]).decode("utf-8", "replace")


def check(path: Path) -> dict:
    out = {"tool": "gguf-metadata", "available": True, "exit_code": 0, "stderr": ""}
    try:
        from gguf import GGUFReader  # lazy: optional dependency

        r = GGUFReader(str(path))
    except ImportError:
        return {"tool": "gguf-metadata", "available": False, "status": "unavailable",
                "reason": "`gguf` package not installed"}
    except Exception as e:  # noqa: BLE001
        return {**out, "status": "error", "exit_code": 2, "stdout": f"Could not parse GGUF header: {e}"}

    lines, findings = [], []
    arch = _field_text(r, "general.architecture")
    name = _field_text(r, "general.name")
    lines.append(f"architecture: {arch}   name: {name}   tensors: {len(r.tensors)}   metadata fields: {len(r.fields)}")

    size = path.stat().st_size
    bad = [t.name for t in r.tensors if int(t.data_offset) + int(t.n_bytes) > size]
    if bad:
        findings.append(f"{len(bad)} tensor(s) extend past end of file (truncated or malformed header), e.g. {bad[:3]}")

    tmpl = _field_text(r, "tokenizer.chat_template")
    if tmpl is None:
        lines.append("chat template: none")
    else:
        lines.append(f"chat template: {len(tmpl)} chars")
        raw = "\n".join(TAG_RE.findall(tmpl))
        code = STR_RE.sub("''", raw)
        for text, pats in ((raw, RAW_SUSPICIOUS), (code, CODE_SUSPICIOUS)):
            for pat, why in pats:
                m = re.search(pat, text)
                if m:
                    ctx = text[max(0, m.start() - 40): m.end() + 40].replace("\n", " ")
                    findings.append(f"chat template: {why}: ...{ctx}...")

    if findings:
        out.update(status="findings", exit_code=1,
                   stdout="\n".join(lines + ["", "FINDINGS:"] + [f"- {x}" for x in findings]))
    else:
        out.update(status="clean", stdout="\n".join(lines + ["", "No suspicious template constructs; tensor extents within file."]))
    return out
