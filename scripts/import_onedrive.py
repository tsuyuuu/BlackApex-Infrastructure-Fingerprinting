#!/usr/bin/env python3
"""Copy a known, byte-identical saved Censys HTTP root response into the evidence tree."""
from __future__ import annotations
import argparse,hashlib,shutil
from pathlib import Path
REPO=Path(__file__).resolve().parents[1]
DEST=REPO/'experiments/structural/heldout/140_150_232_108_port5000_root.html'
EXPECTED='069d914aec2d313fb9e65e4b21aa9ef17b97718da3e0fbb3fb612a3c081cb76a'

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('source',type=Path,help='Existing full root HTML saved from Censys in your Codespaces')
    args=ap.parse_args()
    if not args.source.is_file(): ap.error(f'File not found: {args.source}')
    data=args.source.read_bytes()
    actual=hashlib.sha256(data).hexdigest()
    if actual!=EXPECTED:
        ap.error(f'SHA-256 mismatch. Expected {EXPECTED}, got {actual}. This file is not the byte-identical archived response.')
    DEST.parent.mkdir(parents=True,exist_ok=True)
    if args.source.resolve()!=DEST.resolve(): DEST.write_bytes(data)
    print('Verified SHA-256:',actual)
    print('Copied to:',DEST)
    print('Note: .gitignore excludes the root HTML; review source content before intentional public commit.')
if __name__=='__main__': main()
