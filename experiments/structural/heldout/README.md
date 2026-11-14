# Full OneDrive root HTML goes here

This ZIP does **not** contain the actual complete user-saved OneDrive root HTML
from GitHub Codespaces. To independently re-run that test, obtain the
hash-verified saved Censys HTTP **response body** and place it here as:

`140_150_232_108_port5000_root.html`

Expected SHA-256 (recorded by Censys and independently reported in Codespaces):
`069d914aec2d313fb9e65e4b21aa9ef17b97718da3e0fbb3fb612a3c081cb76a`

Use `python scripts/import_onedrive.py PATH_TO_FILE` from the repository root.
Do not substitute a reconstructed or shortened HTML snippet for this file.
