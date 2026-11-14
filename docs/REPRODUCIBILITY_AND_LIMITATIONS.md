# Methods, provenance, and independent validation limits

## Dataset and indicators

The primary preserved input is the 170-row IP-level indicator matrix from
November 11–12, 2026. Search A is the published sitemap SHA-256, B is a
secondary robots SHA-256, and C searches for a `verifyTurnstile` string.
Censys displayed 104/99/119 matches; 100/99/100 addresses were recovered.
The resulting union is 170, with 31 addresses present in LevelBlue's 66-address
published reference set. IP-level search membership is not HTTP-endpoint-level
proof of any particular behavior, and the reference set is not comprehensive
maliciousness ground truth.

## Exactly what was reproduced

The verified reference static-resource files in `experiments/structural/samples/`
are `192_166_82_111_https443_sitemap.xml` and
`192_166_82_111_port5000_robots.txt`. SHA-256:

- Reference sitemap: `5ec645bf49961d0f1b14e5ddc354e44df42b75b4451c19c6362e6a1d829a917f`
- Reference robots: `831a8dec4cd5c41ec5f7cb61e9add4e547d564f207f75c053aee19f6f0cf6135`

Each contains precisely one reference hostname. Replacing
`centralstructure.online` with `confmic.us` yields bytes whose calculated
hashes equal the candidate's independently recorded Censys values:

- Candidate sitemap: `84c27062a2361d21f0800e392603de3a687d155ab12891d1143d544f763f817e`
- Candidate robots: `3badb5b0b4ca9a261a19463465b3f4dad425820d00be40a0f4692ef0bfc4ea73`

The candidate sitemap and robots files in the repository are deliberately
named **reconstructed**. They were not independently acquired as raw original
Censys responses. Matching a cryptographic hash is strong support for byte
correspondence *subject to the integrity of the separately reported hash*.
This is a selected, nonblind configuration substitution—not a generalized
normalization benchmark.

## Structural-feature source tests

Original `structural_detector.py` executes regex/string checks against selected
preserved HTML and JavaScript. The two ~1,178-byte vesta samples are **excerpts**;
full original HTML body hash matching is not claimed for these files. The
MoneyFlex sample and reference-root sample are not independently benign controls.

`heldout_validation.py` checks five feature categories in the OneDrive response.
The original script marks `verification_post` based on a lightweight match of an
endpoint reference and does **not** independently prove a POST network request.
No JavaScript is executed. The known archived response itself contains a fetch
call with `method:'POST'`, but the script's feature name should not be
misinterpreted as a full semantic parser.

`results/codespaces_heldout_user_reported.json` records the five-feature match
and exact root HTML SHA-256 from the user's previous Codespaces run. Its original
file was not included in the source archives available for this package.
Re-running against that exact HTML is necessary for independently reproduced
source-based claims from a fresh clone.

Synthetic keyword/comment fixtures are *smoke tests*. They do not represent
the range of real-world benign or malicious applications and do not estimate
false-positive rates. The OneDrive source was examined before rule development;
the later test was not independent blind validation.

## Published campaign versus candidate evidence

LevelBlue's October 2026 reporting documents BlackApex-family device-code
phishing and associated published IPs. The November passive Censys records
support observations about specific HTTP resources, not proof of an ongoing
phishing campaign after disclosure. Shared static-resource bytes or common
application-source features do not prove shared adversary control, working
backends, successful tokens, victim compromise, or new confirmed malicious IOCs.

## Optional future evaluation (not performed)

- Pre-register/hold fixed the normalization and feature rules.
- Independently select suitable benign, malicious, and ambiguous examples.
- Create controlled syntactic/domain/configuration mutations and test exact
  hash versus normalized template comparison on the same inputs.
- Measure classification rates **only** where labels are independently justified.
- Keep the source observation time, service path, and provenance per sample.
