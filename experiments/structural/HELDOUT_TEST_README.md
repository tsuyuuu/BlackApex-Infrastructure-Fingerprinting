# Follow-up validation: what is and is not established

Run `python heldout_validation.py` in this folder. The script only reads saved files and makes no network requests.

## Results verified in this package
- The two previously reproduced domain-substitution hash checks pass. These are **not new independent hold-out validations** because the domain transformation and recorded hashes informed the original hypothesis.
- The previously available MoneyFlex transcript does not meet the stricter configurable-landing rule.
- Two synthetic negative controls (generic keyword, comment-only text) fail the configurable rule, and a synthetic positive fixture passes. **Synthetic fixtures do not establish field accuracy or maliciousness.**
- **The actual held-out OneDrive-themed root HTML for `140.150.232.108` is not included**, so the configurable application workflow has NOT been validated using that sample's full saved source.

## Next action
From a **passive Censys observation**, save the full response body for `http://140.150.232.108:5000/` as UTF-8 at `heldout/140_150_232_108_port5000_root.html` (create the `heldout` folder). Do not directly browse the suspected phishing service or solve Turnstile.

Re-run `python heldout_validation.py`. The output changes from `NOT_TESTED` to `TESTED_FROM_USER_SUPPLIED_FILE`, with a feature-by-feature result. Preserve the original Censys timestamp, path, and scan metadata separately. Do not call a copied browser rendering a byte-exact archive unless independently hash-verified.

The configurable rule is a deliberately narrow *static-feature screen* for a possible kit-related architecture: `/api/landing-paths/active`, `/verify-turnstile`, `turnstile_token`, `loader_url` or `redirect_url`, and `acct` or `email`. It can be triggered by static code that never executes and is **not** a maliciousness classifier.
