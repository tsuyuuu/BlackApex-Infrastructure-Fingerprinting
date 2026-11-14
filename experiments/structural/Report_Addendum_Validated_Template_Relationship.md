## Additional validated technical finding — Cross-host static template equivalence

A reproducible offline substitution test produced a stronger result than the initial visual comparison of Censys response bodies. Investigators used the preserved, SHA-256-verified `/sitemap.xml` (273 bytes) and `/robots.txt` (232 bytes) resources observed on LevelBlue-listed DarkApex host `192.166.82.111`. In each resource, replacing only the embedded hostname `centralstructure.online` with `confmic.us` created a new byte sequence whose calculated SHA-256 exactly equaled the independently recorded Censys digest for the corresponding resource on unlisted host `140.150.232.108`.

| Artifact | Reference body SHA-256 | Substituted body SHA-256 (matches .108's reported hash) |
|---|---|---|
| `/sitemap.xml` | `5ec645bf49961d0f1b14e5ddc354e44df42b75b4451c19c6362e6a1d829a917f` | `84c27062a2361d21f0800e392603de3a687d155ab12891d1143d544f763f817e` |
| `/robots.txt` | `831a8dec4cd5c41ec5f7cb61e9add4e547d564f207f75c053aee19f6f0cf6135` | `3badb5b0b4ca9a261a19463465b3f4dad425820d00be40a0f4692ef0bfc4ea73` |

The successful reproduction of both independent hashes demonstrates a specific byte-level template relationship consistent with reuse of the same two static resources under deployment-specific hostname configuration. It also demonstrates a concrete failure mode for exact-hash matching: both fingerprints change when a single embedded hostname changes, despite the remaining bytes being the same in the reproduced resources. The result materially strengthens the technical link between the two observed deployments but **does not establish common ownership, active device-code phishing, or successful victim compromise**. The `.108` response bodies in the offline corpus were constructed by substitution, not separately captured as raw bytes; the comparison depends on the accuracy of the recorded Censys digests.

### Offline reproduction
Run `python structural_detector.py` in the accompanying folder and review `detector_results.json` for the original hash verification, reconstructed digest equivalence, and normalized-template comparison.
