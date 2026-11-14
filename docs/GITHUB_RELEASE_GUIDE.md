# Publishing this package as a GitHub repository

1. Extract the ZIP and put **the contents of the `BlackApex-Fingerprinting-Capstone` folder**
   at the root of your chosen GitHub repository. Avoid nesting the project twice.
2. In GitHub Codespaces, run `python run_all.py` from the repo root.
3. If your earlier Codespace still holds the complete OneDrive HTML, import it
   using `python scripts/import_onedrive.py /workspaces/BlackApex-Validator/heldout/140_150_232_108_port5000_root.html`.
4. Run `python run_all.py` again. Confirm the expected hash and all five feature flags.
5. Review samples and data for material you cannot or should not redistribute.
   HTML is **untrusted archived content**; never open it as a live phishing page.
6. If intentionally publishing the actual OneDrive HTML, override `.gitignore` for
   that file with `git add -f` after completing the data-provenance review.
7. Add a license of your choosing and a scholarly citation/DOI if applicable.
8. Tag the tested commit (e.g. `v1.0-capstone`) and cite the permalink / commit
   hash in the report's Appendix and reference list.

Suggested citation template:

`Author. (2026). Beyond the Hash: BlackApex-family infrastructure fingerprinting (version v1.0-capstone) [Code and dataset]. GitHub. <REPLACE_WITH_RELEASE_URL>`

Do not claim the final hold-out source file is packaged unless you have added it
and verified its SHA-256 as above.
