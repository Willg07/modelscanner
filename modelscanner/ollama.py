"""Scan Ollama-installed models by name (e.g. `ollama:qwen3.8-27b-uncensored:latest`).

Ollama stores each model as a manifest (JSON) listing content-addressed blobs:
  models/manifests/<host>/<namespace>/<name>/<tag>      -> layers
  models/blobs/sha256-<hex>                              -> GGUF weights, template, params, ...
Blob files have no extension, so GGUF is recognised by its magic bytes. Manifests are
treated as UNTRUSTED input: digests are validated and every path stays inside the models dir.

Per layer we (1) verify the blob's sha256 equals its manifest digest, (2) run the GGUF
metadata check on model/adapter layers (a non-GGUF model layer is itself a finding), and
(3) show template/system/params text and flag hidden Unicode (zero-width, bidi, tag chars).
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from . import gguf_check

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
PART_RE = re.compile(r"^[A-Za-z0-9._-]+$")
DEFAULT_HOST, DEFAULT_NS, DEFAULT_TAG = "registry.ollama.ai", "library", "latest"
MODEL_KINDS = {"model", "adapter", "projector"}
TEXT_KINDS = {"template", "system", "params", "license", "messages"}
# zero-width, bidi controls, BOM, and the Unicode Tags block (invisible "ASCII smuggling")
HIDDEN_RE = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f]")


class OllamaError(Exception):
    pass


def models_dir() -> Path:
    return Path(os.environ.get("OLLAMA_MODELS") or Path.home() / ".ollama" / "models")


def _manifest_path(name: str, base: Path) -> Path:
    name = name.strip()
    tag = DEFAULT_TAG
    if ":" in name:
        name, tag = name.rsplit(":", 1)
    parts = [p for p in name.split("/") if p]
    if len(parts) == 1:
        parts = [DEFAULT_HOST, DEFAULT_NS, parts[0]]
    elif len(parts) == 2:
        parts = [DEFAULT_HOST, *parts]
    parts.append(tag)
    if not all(PART_RE.match(p) and p not in (".", "..") for p in parts):
        raise OllamaError(f"invalid model name: {name!r}")
    path = base / "manifests" / Path(*parts)
    if not path.resolve().is_relative_to((base / "manifests").resolve()):
        raise OllamaError("model name escapes the manifests directory")
    return path


def list_models(base: Path | None = None) -> list[str]:
    base = base or models_dir()
    root = base / "manifests"
    names = []
    for f in sorted(p for p in root.rglob("*") if p.is_file()) if root.exists() else []:
        rel = f.relative_to(root).parts  # host, ns, name..., tag
        host, rest, tag = rel[0], rel[1:-1], rel[-1]
        shown = "/".join(rest[1:] if (host == DEFAULT_HOST and rest[0] == DEFAULT_NS) else (host, *rest) if host != DEFAULT_HOST else rest)
        names.append(f"{shown}:{tag}")
    return names


def load(name: str, base: Path | None = None) -> dict:
    """Resolve a model name to {name, manifest, layers:[{kind,digest,size,path,exists}]}."""
    base = base or models_dir()
    mp = _manifest_path(name, base)
    if not mp.is_file():
        raise OllamaError(f"no Ollama manifest for {name!r} (looked in {mp})")
    try:
        manifest = json.loads(mp.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise OllamaError(f"unreadable manifest: {e}") from e
    layers = []
    cfg = [{**manifest["config"], "mediaType": "config"}] if manifest.get("config") else []
    for lay in manifest.get("layers", []) + cfg:
        digest = str(lay.get("digest", ""))
        kind = str(lay.get("mediaType", "")).rsplit(".", 1)[-1] or "unknown"
        entry = {"kind": kind, "digest": digest, "size": lay.get("size"), "path": None, "exists": False, "valid": True}
        if not DIGEST_RE.match(digest):
            entry["valid"] = False  # never turn an untrusted digest into a filesystem path
        else:
            bp = base / "blobs" / digest.replace(":", "-")
            entry["path"], entry["exists"] = bp, bp.is_file()
        layers.append(entry)
    return {"name": name, "manifest_path": mp, "layers": layers}


def _status_rank(s: str) -> int:
    return {"clean": 0, "unavailable": 1, "error": 2, "findings": 3}[s]


def scan(model: dict, sha256_fn) -> tuple[list[dict], list[dict], list[str]]:
    """Return (files, scanners, notes) in the shapes the main CLI report uses."""
    files, findings, notes, info = [], [], [], []
    gguf_results = []
    for lay in model["layers"]:
        label = f"{lay['kind']} ({lay['digest'][:19]}…)"
        if not lay["valid"]:
            findings.append(f"{lay['kind']}: invalid digest in manifest {lay['digest']!r} (possible tampering)")
            continue
        if not lay["exists"]:
            info.append(f"{lay['kind']}: blob not present locally (cloud model or partial pull)")
            continue
        p: Path = lay["path"]
        actual = sha256_fn(p)
        ok = actual == lay["digest"].split(":", 1)[1]
        if not ok:
            findings.append(f"{lay['kind']}: blob hash does not match manifest digest (corrupt or tampered): {actual[:16]}…")
        is_gguf = gguf_check.is_gguf(p)
        files.append({"path": label, "bytes": p.stat().st_size, "sha256": actual,
                      "format_risk": "tensor-only" if is_gguf else "other", "remote_code": False})
        if lay["kind"] in MODEL_KINDS:
            if is_gguf:
                gguf_results.append((label, gguf_check.check(p)))
            else:
                findings.append(f"{lay['kind']}: layer is not GGUF (unexpected for an Ollama model)")
        elif lay["kind"] in TEXT_KINDS:
            text = p.read_bytes()[:200_000].decode("utf-8", "replace")
            hidden = HIDDEN_RE.findall(text)
            if hidden:
                findings.append(f"{lay['kind']}: {len(hidden)} hidden Unicode character(s) "
                                f"(zero-width/bidi/tag): {sorted({hex(ord(c)) for c in hidden})[:6]}")
            snippet = text if len(text) < 1500 else text[:1500] + "…"
            info.append(f"{lay['kind']} ({len(text)} chars):\n{snippet}")

    scanners = []
    body = [f"model: {model['name']}"] + [f"- {x}" for x in findings] if findings else [f"model: {model['name']}"]
    scanners.append({
        "tool": "ollama-manifest", "available": True, "exit_code": 1 if findings else 0, "stderr": "",
        "status": "findings" if findings else "clean",
        "stdout": "\n".join(body + (["", "FINDINGS above."] if findings else ["", "Blob hashes match the manifest; layers well-formed."])
                            + (["", "Layer details:"] + info if info else [])),
    })
    if gguf_results:
        worst = max((r for _, r in gguf_results), key=lambda r: _status_rank(r["status"]))
        text = "\n\n".join(f"== {lab}\n{r.get('stdout') or r.get('reason', '')}" for lab, r in gguf_results)
        scanners.append({**worst, "tool": "gguf-metadata", "stdout": text})
    if not gguf_results:
        notes.append("no local model weights were analyzed (cloud model, partial pull, or no model layer)")
    return files, scanners, notes
