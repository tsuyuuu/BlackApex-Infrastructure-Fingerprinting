#!/usr/bin/env python3
"""Run all fully packaged experiments offline; flag missing held-out response."""
from __future__ import annotations
import hashlib, json, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
EXPECTED='069d914aec2d313fb9e65e4b21aa9ef17b97718da3e0fbb3fb612a3c081cb76a'

def call(script):
    print('\n>>>', script.relative_to(ROOT),flush=True)
    subprocess.run([sys.executable,str(script)],check=True,cwd=script.parent)

def main():
    call(ROOT/'experiments/indicator_overlap/Component7_Offline_Evaluation.py')
    call(ROOT/'experiments/structural/structural_detector.py')
    root=ROOT/'experiments/structural'
    heldout=root/'heldout/140_150_232_108_port5000_root.html'
    if heldout.exists():
        actual=hashlib.sha256(heldout.read_bytes()).hexdigest()
        if actual != EXPECTED:
            raise SystemExit(f'ERROR: OneDrive HTML SHA-256 mismatch. Expected {EXPECTED}; got {actual}. Refusing to label sample verified.')
        print('\nFull OneDrive HTML: SHA-256 MATCHES Censys recorded hash.',flush=True)
    else:
        print('\nFull OneDrive HTML is absent: held-out source evaluation will be NOT_TESTED.\n'
              'See experiments/structural/heldout/README.md.',flush=True)
    call(root/'heldout_validation.py')
    result=json.loads((root/'heldout_results.json').read_text(encoding='utf-8'))
    test=result['heldout_onedrive_root']
    if heldout.exists():
        if not (test['configurable_rule'] and all(test['features'].values()) and test['sha256_of_saved_transcript']==EXPECTED):
            raise SystemExit('ERROR: OneDrive held-out response did not reproduce the reported five-feature positive result.')
        print('\nDONE: all packaged experiments passed, and the OneDrive source-based check passed.')
    else:
        print('\nDONE: original indicator and static-template checks passed; OneDrive source-based check NOT TESTED (source file absent).')

if __name__=='__main__': main()
