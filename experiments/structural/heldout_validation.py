#!/usr/bin/env python3
"""Read-only follow-up assessment. No network; not a malware classifier."""
from pathlib import Path
import json, hashlib, re
from structural_detector import js_features, normalize_resource
ROOT=Path(__file__).resolve().parent
SAMPLES=ROOT/'samples'
OUT=ROOT/'heldout_results.json'

def digest(b): return hashlib.sha256(b).hexdigest()

def features(content):
    t=content.decode('utf-8','replace')
    # Client-side variant inspection. This is distinct from the previously tested vesta-io rule.
    # Avoid treating a bare Turnstile word as evidence; require three separate features.
    return {
        'landing_paths_api': '/api/landing-paths/active' in t,
        'verification_post': bool(re.search(r'''(?:fetch\s*\(\s*['\"]/verify-turnstile['\"]|['\"]/?verify-turnstile['\"])''',t)),
        'token_field': bool(re.search(r'\bturnstile_token\b',t)),
        'redirect_keys': ('loader_url' in t or 'redirect_url' in t),
        'account_aware': bool(re.search(r'\b(?:acct|email)\b',t)),
    }

def evaluate():
    ref_s=(SAMPLES/'192_166_82_111_https443_sitemap.xml').read_bytes()
    ref_r=(SAMPLES/'192_166_82_111_port5000_robots.txt').read_bytes()
    cand_s=(SAMPLES/'140_150_232_108_reconstructed_sitemap.xml').read_bytes()
    cand_r=(SAMPLES/'140_150_232_108_reconstructed_robots.txt').read_bytes()
    expected={'sitemap.xml':'84c27062a2361d21f0800e392603de3a687d155ab12891d1143d544f763f817e', 'robots.txt':'3badb5b0b4ca9a261a19463465b3f4dad425820d00be40a0f4692ef0bfc4ea73'}
    static=[]
    for kind,ref,cand in [('sitemap.xml',ref_s,cand_s),('robots.txt',ref_r,cand_r)]:
        static.append({'resource':kind,'source':'reconstructed candidate bytes, compared with independently reported Censys SHA-256','substitution_reproduces_candidate_hash':digest(ref.replace(b'centralstructure.online',b'confmic.us'))==expected[kind],'normalized_equal': normalize_resource(ref,kind)==normalize_resource(cand,kind)})
    test=[]
    for name in ['143_110_222_169_port5000_vesta_excerpt.html','108_186_202_36_port5000_vesta_excerpt.html','18_198_139_163_https443_moneyflex_login.html','192_166_82_111_https443_root.html']:
        b=(SAMPLES/name).read_bytes(); f=js_features(b); v=features(b)
        test.append({'name':name,'source':'previously available transcript, NOT held-out labeled ground truth','vesta_rule':f['distinctive_verification_workflow'],'configurable_variant_features':v,'configurable_rule':all(v.values())})
    # Synthetic controls are robustness tests only, not observational evidence.
    controls={
       'just_the_keyword':'<!-- verifyTurnstile --> Cloudflare Turnstile',
       'comment_only_endpoint':'<!-- /api/landing-paths/active /verify-turnstile turnstile_token loader_url acct -->',
       'minimal_configurable_fixture':"<script>fetch('/api/landing-paths/active'); fetch('/verify-turnstile'); const payload={turnstile_token:token,acct:acct}; const redirect_url=data.redirect_url;</script>",
    }
    synthetic=[]
    for label,s in controls.items():
        f=features(s.encode()); synthetic.append({'name':label,'features':f,'configurable_rule':all(f.values()),'synthetic':True})
    heldout=ROOT/'heldout'/'140_150_232_108_port5000_root.html'
    if heldout.exists():
        h=heldout.read_bytes(); f=features(h)
        one={'status':'TESTED_FROM_USER_SUPPLIED_FILE','path':str(heldout.relative_to(ROOT)),'sha256_of_saved_transcript':digest(h),'features':f,'configurable_rule':all(f.values()),'note':'Presence of client-side feature pattern only, not proof of maliciousness; file provenance must be independently documented.'}
    else:
        one={'status':'NOT_TESTED','reason':'Archived full OneDrive-themed root HTML not present; no invented/transcribed proxy used.'}
    report={'method':'offline limited validation of static templates and source features','static_reproduction':static,'existing_transcript_checks':test,'synthetic_robustness_controls':synthetic,'heldout_onedrive_root':one,'interpretation':'Zero population-level performance claims. Synthetic controls do not measure false-positive rates. Static reconstruction was previously examined and is not independent holdout evidence.'}
    OUT.write_text(json.dumps(report,indent=2)+'\n')
    print('STATIC REPRODUCTION:', 'PASS' if all(x['substitution_reproduces_candidate_hash'] and x['normalized_equal'] for x in static) else 'FAIL')
    print('OneDrive root held-out test:',one['status'])
    print('Existing MoneyFlex configurable-rule match:',next(x['configurable_rule'] for x in test if 'moneyflex' in x['name']))
    print('Synthetic comment-only configurable-rule match:',next(x['configurable_rule'] for x in synthetic if x['name']=='comment_only_endpoint'))
    print('Saved',OUT)
    return 0
if __name__=='__main__': raise SystemExit(evaluate())
