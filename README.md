# Beyond the Hash — BlackApex-family infrastructure fingerprinting

Reproducible **offline** research materials for a cyber threat intelligence capstone.
The study compares three Censys search-result sets, reproduces two candidate
HTTP SHA-256 values through one hostname substitution, and tests selected
static application source-feature rules. It does **not** confirm maliciousness,
operator identity, OAuth token theft, or population-wide detector performance.

## Start here (Python 3.9+, standard library only)

Extract this repository into a folder, open a terminal at the **repository root**, and run:

```bash
python run_all.py
```

This runs:
1. `experiments/indicator_overlap/Component7_Offline_Evaluation.py` —
   recovered IP-set and published-reference overlap checks.
2. `experiments/structural/structural_detector.py` —
   exact two-resource domain-substitution SHA-256 reproduction and limited
   verification-workflow smoke tests.
3. `experiments/structural/heldout_validation.py` —
   configurable-workflow source-feature tests and synthetic controls.

Without the complete OneDrive root HTML, step 3 deliberately reports
`NOT_TESTED` for that response; other packaged checks still run. The complete
response was previously tested in the researcher's GitHub Codespaces, and
its **user-reported** result is archived under `results/` with its provenance
clearly stated. The original response bytes were not available when this ZIP
was assembled. Do not treat the archived user-reported result as a new local
verification.

### Import the actual OneDrive response from Codespaces

If the original file still exists in that Codespace, from the **new** repo root:

```bash
python scripts/import_onedrive.py /workspaces/BlackApex-Validator/heldout/140_150_232_108_port5000_root.html
python run_all.py
```

Or place the same original Censys response-body file manually at:
`experiments/structural/heldout/140_150_232_108_port5000_root.html`.
Its SHA-256 **must** be:
`069d914aec2d313fb9e65e4b21aa9ef17b97718da3e0fbb3fb612a3c081cb76a`.
The import script refuses mismatched files. A Markdown transcription or a
shortened excerpt is not equivalent evidence.

The held-out HTML is ignored by Git by default as a precaution: if you intend
it to be public, inspect it first and explicitly stage it with
`git add -f experiments/structural/heldout/140_150_232_108_port5000_root.html`.

## Repository map

```text
experiments/indicator_overlap/    Original 170-IP CSV, 6-host review CSV, and evaluator
experiments/structural/           Original structural Python scripts, sample files, source manifest
experiments/structural/heldout/   Placeholder for the COMPLETE OneDrive HTTP response body
results/                          Original JSON outputs + explicitly labeled Codespaces report
supplementary/                    Original Excel workbook and conceptual Entra hunting KQL
scripts/import_onedrive.py         Verify/copy exact saved OneDrive response bytes
run_all.py                         Run and validate all available tests offline
docs/                              Detailed caveats, provenance, and research methods
```

## Grounded findings

| Measurement | Result | Meaning |
|---|---:|---|
| Recovered Censys IP union | 170 | From three non-exhaustively recovered search lists |
| Published LevelBlue reference-IP overlap | 31 | Overlap, **not** recall across all malicious hosts |
| Static hash union A∪B | 128 | 100 A, 99 B, with 71 shared |
| B-only additional published reference IPs | 4 | All already published by LevelBlue |
| Reference domain → candidate domain | `centralstructure.online` → `confmic.us` | One hostname substitution in each resource |
| Candidate sitemap hash reproduction | Exact match | Compared against separately recorded Censys SHA-256 |
| Candidate robots hash reproduction | Exact match | Same experiment on a second resource |
| Configurable-workflow root test | User reported positive in Codespaces | Only locally reproducible after importing the ORIGINAL complete HTML |

The two static hash reproductions show **template correspondence** under the
specified transformation. The feature checks identify **source patterns**;
no claim of maliciousness, distinct independent corroboration, backend execution,
common operator, real-world precision, recall or false-positive rate is made.

## Dataset provenance & important caveats

- `Component7_BlackApex_Indicator_Matrix.csv`: recovered search-result IPs;
  not an exhaustive Censys export or a list of 170 malicious servers.
- `Component7_BlackApex_Manual_Reviews.csv`: six purposefully selected cases;
  not six independently labeled positives/negatives.
- `samples/*`: some byte-verified reference static resources, some **reconstructed**
  candidate static resources, some manually transcribed HTML **excerpts** with
  hashes that differ from Censys full-response hashes. See `manifest.json`.
- `results/codespaces_heldout_user_reported.json`: explicitly user-provided
  report, **not locally regenerated** without its full HTML input.
- `heldout_validation.py` uses lightweight source-pattern checks; a field named
  `verification_post` is NOT a full JavaScript semantic or network-behavior check.
- The OneDrive candidate was inspected before the rule was finalized: it is
  separately tested archived source, **not a blind independent holdout**.
- Static resources do not establish common operator ownership or actual
  device-code phishing / token acquisition.

See `docs/REPRODUCIBILITY_AND_LIMITATIONS.md` for exact scopes and checks.

## Public release checklist

1. Verify that every file is yours to publish and review stored HTTP content.
2. Remove any unintended secrets, credentials, private analyst comments,
   and personal data; source code and samples remain fully offline.
3. Import and re-run the full OneDrive sample if publishing the positive
   result as independently reproducible from a fresh clone.
4. Cite a **stable Git release or commit SHA**, not merely the branch name.
5. Add a software license if desired; none is assumed by this package.
6. Refrain from publishing any samples as "confirmed malicious" without
   independent supporting evidence.

This project is for offline research and defender education. No active
network scanning, phishing interaction, authentication, or exploit execution
is needed or performed by the scripts.
