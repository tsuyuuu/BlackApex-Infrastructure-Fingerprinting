#!/usr/bin/env python3
"""Offline structural evidence comparison, not a BlackApex malware classifier.

Reads local archived transcript files only; no network calls or external packages.
1. Compare observed response SHA-256s with verified transcript bytes.
2. Normalize configured sitemap/robots hostname values for template comparison.
3. Inspect HTML/JS content for a SPECIFIC client-side verification workflow.

Classification is technical structure, not operator attribution or malice.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
STATIC_EXTS = {".xml", ".txt"}
ORIGINAL_DOMAIN = "centralstructure.online"
CONFIGURED_DOMAIN = "confmic.us"
EXPECTED_ORIGINAL = {
    "sitemap.xml": "5ec645bf49961d0f1b14e5ddc354e44df42b75b4451c19c6362e6a1d829a917f",
    "robots.txt": "831a8dec4cd5c41ec5f7cb61e9add4e547d564f207f75c053aee19f6f0cf6135",
}
EXPECTED_CONFIGURED = {
    "sitemap.xml": "84c27062a2361d21f0800e392603de3a687d155ab12891d1143d544f763f817e",
    "robots.txt": "3badb5b0b4ca9a261a19463465b3f4dad425820d00be40a0f4692ef0bfc4ea73",
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_resource(data: bytes, kind: str) -> bytes:
    """Normalize only *configured hostnames* in two specific known artifacts.

    Preserve all other bytes (including line endings, paths, and whitespace).
    Not a generic XML/text semantic parser; that's intentional for reproducibility.
    """
    text = data.decode("utf-8")
    if kind == "sitemap.xml":
        pattern = r"(?<=<loc>)https?://[^/<>\s]+"
        replacement = "https://<DOMAIN>"
    elif kind == "robots.txt":
        pattern = r"(?im)^(Sitemap:\s*)https?://[^/\s]+"
        # \g<1> cannot be placed inside a literal replace string without regex expansion.
        new, n = re.subn(pattern, lambda m: m.group(1) + "https://<DOMAIN>", text)
        if n != 1:
            raise ValueError(f"Expected exactly one robots sitemap URL; found {n}")
        return new.encode("utf-8")
    else:
        raise ValueError(f"Unsupported static resource: {kind}")
    new, n = re.subn(pattern, replacement, text)
    if n != 1:
        raise ValueError(f"Expected exactly one sitemap <loc> hostname; found {n}")
    return new.encode("utf-8")


def js_features(data: bytes) -> dict[str, bool]:
    html = data.decode("utf-8", errors="replace")
    # Inspects raw saved source; does NOT execute JS, complete challenges, or fetch assets.
    # Exact patterns are deliberately narrower than general Turnstile presence.
    definitions = {
        "generic_turnstile": r"(?i)turnstile",
        "keyword_verifyturnstile": r"(?i)verifyturnstile",
        "function_verifyturnstile_token": r"\b(?:async\s+)?function\s+verifyTurnstile\s*\(\s*token\s*\)",
        "post_verify_turnstile": r"\bfetch\s*\(\s*['\"]/?verify-turnstile['\"]\s*,\s*\{.{0,400}?\bmethod\s*:\s*['\"]POST['\"]",
        "json_turnstile_token": r"\bJSON\s*\.\s*stringify\s*\(\s*\{\s*['\"]?turnstile_token['\"]?\s*:\s*token\b",
        "landing_paths_api": r"/api/landing-paths/active",
        "server_redirect_keys": r"\b(?:loader_url|redirect_url)\b",
    }
    feats = {name: bool(re.search(pattern, html, re.S)) for name, pattern in definitions.items()}
    feats["distinctive_verification_workflow"] = all(
        feats[k] for k in (
            "function_verifyturnstile_token", "post_verify_turnstile", "json_turnstile_token"
        )
    )
    return feats


def resource_kind(filename: str) -> str | None:
    lower = filename.lower()
    if lower.endswith("sitemap.xml"):
        return "sitemap.xml"
    if lower.endswith("robots.txt"):
        return "robots.txt"
    return None


def evaluate(root: Path) -> dict:
    folder = root / "samples"
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest_map = {row["file"]: row for row in manifest}
    entries = []
    for f in sorted(folder.iterdir()):
        if not f.is_file():
            continue
        content = f.read_bytes()
        kind = resource_kind(f.name)
        rec = {
            "file": f.name,
            "bytes": len(content),
            "sha256": sha256(content),
            "source_kind": manifest_map.get(f.name, {}).get("source_kind", "transcribed_archive"),
        }
        metadata = manifest_map.get(f.name, {})
        if metadata.get("declared_censys_hash"):
            rec["declared_censys_hash"] = metadata["declared_censys_hash"]
            rec["hash_matches_declared"] = rec["sha256"] == metadata["declared_censys_hash"]
        if kind:
            rec["artifact_kind"] = kind
            try:
                rec["normalized_sha256"] = sha256(normalize_resource(content, kind))
            except ValueError as ex:
                rec["normalization_error"] = str(ex)
        else:
            rec["artifact_kind"] = "html_or_js"
            rec["features"] = js_features(content)
        entries.append(rec)

    # Core independent cross-check: a *single-domain substitution* transforms two
    # independently hash-verified seed artifacts into BOTH recorded configured hashes.
    cross_checks = []
    originals = {
        "sitemap.xml": folder / "192_166_82_111_https443_sitemap.xml",
        "robots.txt": folder / "192_166_82_111_port5000_robots.txt",
    }
    reconstructed = {
        "sitemap.xml": folder / "140_150_232_108_reconstructed_sitemap.xml",
        "robots.txt": folder / "140_150_232_108_reconstructed_robots.txt",
    }
    for kind in ("sitemap.xml", "robots.txt"):
        seed = originals[kind].read_bytes()
        replacement = seed.replace(ORIGINAL_DOMAIN.encode(), CONFIGURED_DOMAIN.encode())
        generated = reconstructed[kind].read_bytes()
        result = {
            "resource": kind,
            "original_hash_verified": sha256(seed) == EXPECTED_ORIGINAL[kind],
            "domain_occurrences_in_original": seed.count(ORIGINAL_DOMAIN.encode()),
            "reconstruction_matches_staged_bytes": replacement == generated,
            "single_substitution_matches_recorded_host_hash": sha256(replacement) == EXPECTED_CONFIGURED[kind],
            "calculated_configured_sha256": sha256(replacement),
            "recorded_configured_sha256": EXPECTED_CONFIGURED[kind],
            "normalized_template_matches": sha256(normalize_resource(seed, kind)) == sha256(normalize_resource(generated, kind)),
        }
        cross_checks.append(result)

    # A validation smoke test, NOT an independent ground-truth malicious/benign test.
    expected = {
        "143_110_222_169_port5000_vesta_excerpt.html": True,
        "108_186_202_36_port5000_vesta_excerpt.html": True,
        "18_198_139_163_https443_moneyflex_login.html": False,
    }
    smoke = []
    for name, expected_workflow in expected.items():
        observed = next(r for r in entries if r["file"] == name)["features"]["distinctive_verification_workflow"]
        smoke.append({"file": name, "expected_workflow_presence": expected_workflow, "observed": observed, "agrees": expected_workflow == observed})

    report = {
        "method": "Offline static-artifact equivalence + JavaScript source-feature extraction",
        "scope": "Preserved/reconstructed/transcribed samples only; not a BlackApex classifier",
        "sample_count": len(entries),
        "cross_checks": cross_checks,
        "workflow_smoke_tests": smoke,
        "entries": entries,
        "caveats": [
            "Reconstructed .108 static resources are DERIVED by applying a single documented hostname substitution to preserved, SHA-256-verified seed bytes; their calculated hashes match independently recorded Censys values. They are not original captured .108 response bytes.",
            "Two vesta HTML samples are manually transcribed CLIENT-SIDE CODE EXCERPTS from user-supplied responses, not byte-for-byte archived full HTTP response bodies.",
            "A source-feature match is not proof of maliciousness, common operator ownership, or device-code token acquisition.",
            "The purposefully selected comparison sample does not support population-level false-positive rates.",
        ],
    }
    assert all(r["original_hash_verified"] and r["domain_occurrences_in_original"] == 1 and r["reconstruction_matches_staged_bytes"] and r["single_substitution_matches_recorded_host_hash"] and r["normalized_template_matches"] for r in cross_checks)
    assert all(s["agrees"] for s in smoke)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT, help="Evidence package folder (contains samples/ and manifest.json)")
    parser.add_argument("--output", type=Path, default=None, help="Results path (default: <root>/detector_results.json)")
    args = parser.parse_args()
    try:
        report = evaluate(args.root)
    except (ValueError, AssertionError, FileNotFoundError, KeyError) as err:
        print(f"Validation failed: {err}", file=sys.stderr)
        return 1
    output = args.output or args.root / "detector_results.json"
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("Offline structural check: PASS")
    for row in report["cross_checks"]:
        print(f"  {row['resource']}: exact single-domain substitution SHA-256 match = {row['single_substitution_matches_recorded_host_hash']}; normalized template match = {row['normalized_template_matches']}")
    for row in report["workflow_smoke_tests"]:
        print(f"  {row['file']}: distinctive workflow found = {row['observed']} (expected {row['expected_workflow_presence']})")
    print(f"Saved: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
