# BlackApex capstone — Offline structural detector (prototype)

**Purpose:** Reproduce and test two types of technical relationship in saved Censys material without contacting candidate hosts:

1. **Byte-level static template relationship.** Start with hash-verified `sitemap.xml` and `robots.txt` response bodies from published DarkApex-associated `192.166.82.111`. Replace exactly `centralstructure.online` with `confmic.us`. The resulting SHA-256s are **identical** to the independently transcribed Censys response hashes for unlisted candidate `140.150.232.108` on both resources.
2. **Client-side source pattern matching.** Search saved HTML/JS for a more specific combination than the generic word `verifyTurnstile`: an actual `function verifyTurnstile(token)` declaration, `fetch('/verify-turnstile', { method:'POST' ... })`, and JSON serialization of `turnstile_token: token`.

**Important:** This is a reproducible *technical similarity* check, not a maliciousness classifier. Do not refer to any candidate as confirmed BlackApex infrastructure or infer token theft/common operator control from these results.

## Run

Requires Python **3.10+**, standard library only, offline. From this folder:

```sh
python structural_detector.py
```

Expected console results:

```text
Offline structural check: PASS
  sitemap.xml: exact single-domain substitution SHA-256 match = True; normalized template match = True
  robots.txt: exact single-domain substitution SHA-256 match = True; normalized template match = True
  143_110_222_169_port5000_vesta_excerpt.html: distinctive workflow found = True (expected True)
  108_186_202_36_port5000_vesta_excerpt.html: distinctive workflow found = True (expected True)
  18_198_139_163_https443_moneyflex_login.html: distinctive workflow found = False (expected False)
Saved: .../detector_results.json
```

The full per-file feature results are saved in `detector_results.json`.

## Evidence provenance

- `samples/192_166_82_111_{https443,port5000}_sitemap.xml` and `..._robots.txt` were transcribed from earlier Censys response text supplied in the investigation. Their local byte SHA-256s match the independently reported Censys values. These are **hash-verified preserved texts**.
- `samples/140_150_232_108_reconstructed_sitemap.xml` and `..._robots.txt` are **derived reconstructions**, created solely by replacing the domain in the first host's files. They are **not independently extracted from the .108 response stream**; however, their calculated hashes exactly reproduce the separately supplied .108 Censys digests. This provides strong evidence for an exact single-string-substitution relationship, contingent on the reported hashes being accurate.
- `samples/143_110_222_169_port5000_vesta_excerpt.html` and `...108_186_202_36...` contain **manually transcribed relevant JavaScript excerpts** from the full 5,842-byte HTML response bodies supplied in the conversation. They do not reproduce the full HTML, and their local SHA-256s are NOT comparable to Censys root-response hashes.
- `samples/18_198_139_163_https443_moneyflex_login.html` was extracted from the pasted Censys response transcription. It is a **structurally different comparison case**, not a confirmed-benign sample.
- Other staged HTML files can be incomplete/truncated or whitespace-altered; `manifest.json` contains original and local hashes and provenance. Do not call those byte-identical originals.

## What this establishes—and does not

**Established (conditional on the supplied Censys hash records):** Two separate HTTP resources from `140.150.232.108` have reported response hashes exactly reproduced by a one-domain substitution to resources observed on a LevelBlue-listed DarkApex host. This is more specific than Turnstile reuse and the static template match can be reproduced from saved evidence.

**Established from code excerpts:** The two manually transcribed `vesta-io` code excerpts have a characteristic verification workflow. The MoneyFlex comparison contains verification-related content but does not have that workflow in the preserved transcription.

**Not established:** Operational device-code phishing on the candidates; actor identity; common operator control; true population-wide precision/recall or false-positive rates; an externally validated new structural detector. Two selected positive excerpts and one dissimilar comparison are **smoke tests**, not independent ground truth or a representative evaluation.

## Why the domain substitution is persuasive

- Original sitemap: 273 bytes; replacing a 23-character hostname with a 10-character hostname yields 260 bytes, with SHA-256 `84c27062a2361d21f0800e392603de3a687d155ab12891d1143d544f763f817e`—the recorded .108 sitemap hash.
- Original robots: 232 bytes; the same substitution yields 219 bytes, with SHA-256 `3badb5b0b4ca9a261a19463465b3f4dad425820d00be40a0f4692ef0bfc4ea73`—the recorded .108 robots hash.
- This is an observed correlation between template artifacts, not evidence that either host successfully delivered tokens to an attacker.

## Other research materials

These outputs supplement rather than replace the earlier `Component7_Offline_Evaluation.py` list-overlap analysis. The original 170-IP comparison relied on retrieved search lists with incomplete recovery for two searches.

No external connections, form submissions, or device-code authorizations are made by this script.
