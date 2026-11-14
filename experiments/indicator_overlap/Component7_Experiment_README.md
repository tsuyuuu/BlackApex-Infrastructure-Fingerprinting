# BlackApex Component 7 — Offline detection evaluation

## Purpose
Reproduce indicator-list overlap and the bounded six-host frontend structural review. This package makes **no network requests** and does **not** interact with phishing infrastructure.

## Inputs
- `Component7_BlackApex_Indicator_Matrix.csv`: 170 unique IPs obtained from three partially recovered Censys result lists on November 11–12, 2026. A (sitemap hash): 100 recovered of 104 UI results; B (robots hash): 99/99; C (`verifyTurnstile` text): 100 recovered of 119 UI results. Published IOC status is a direct IP-address comparison with LevelBlue's 66 distinct reference IPs; it is not a maliciousness verdict.
- `Component7_BlackApex_Manual_Reviews.csv`: six purposefully selected archived HTML reviews transcribed from analyst observations. Five show the characteristic `/verify-turnstile` function+POST+JSON token combination. The sixth, MoneyFlex, is structurally dissimilar. This sample is **not random**, and the sixth is **not confirmed benign**.

## Reproduce
Run `python Component7_Offline_Evaluation.py` in this folder. It uses only the Python standard library and writes `Component7_Offline_Evaluation_Results.json`.

## Interpreting output
- A+B contributes **four** more LevelBlue reference IPs than A in the recovered working files (27 to 31).
- 42 records occur only in C: 23 matched the expected function declaration snippet, 19 matched other text contexts. The C field itself is only a **keyword hit**, not code-level validation.
- Counts represent **discovery overlap**, not population-wide recall, accuracy, precision, false-positive rate, phishing activity, compromise, or common operator attribution.
- Two sampled web resources with a 13-byte difference in domain-length generated distinct exact body hashes, while retaining a visibly similar XML/robots template. Exact normalized byte equivalence would require independently preserved raw response bytes, which the pasted HTML does not furnish.

## Proposed Entra hunt
`Component7_Entra_DeviceCode_Hunt.kql` is a **conceptual, schema-checked** example; it has not been executed in a Microsoft tenant. Validate against local field availability, approved device-code use, known application exceptions, and your actual sign-in baselines. Device detail may be missing; unknown posture does not prove unmanaged status.

## Authoritative references
- LevelBlue SpiderLabs (Oct 30, 2026): https://www.levelblue.com/blogs/spiderlabs-blog/blackapex-spy-and-counting-the-emerging-wave-of-vibe-coded-phishing-kits
- Microsoft SigninLogs schema: https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs
- Conditional Access for authentication flows: https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows
- Device-code CA setup: https://learn.microsoft.com/en-us/entra/identity/conditional-access/how-to-policy-authentication-flows
