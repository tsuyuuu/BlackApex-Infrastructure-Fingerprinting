#!/usr/bin/env python3
"""Reproducible *offline* CTI indicator comparison for the BlackApex capstone.
Reads local CSVs only. No networking, no scanning, no service interaction.
No inference of maliciousness or accuracy from search-result matches.
"""
import csv
import collections
import json
import pathlib

HERE = pathlib.Path(__file__).resolve().parent

def read_csv(name):
    with (HERE / name).open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

def category(row):
    a = row["sitemap_hash_A"] == "Yes"
    b = row["robots_hash_B"] == "Yes"
    c = row["javascript_text_C"] == "Yes"
    if a and b:
        return "Both static hashes (with or without JS)"
    if (a or b) and c:
        return "One static hash plus JS search"
    if a or b:
        return "One static hash only"
    if c:
        return "JS search only"
    return "No indicator"

def workflow_match(row):
    """Only client-side *structural similarity*, not proof of device-code phishing."""
    return all(row[k] == "Yes" for k in
        ("verifyTurnstile_function", "post_to_verify_turnstile", "json_turnstile_token"))

def evaluate():
    rows = read_csv("Component7_BlackApex_Indicator_Matrix.csv")
    reviews = read_csv("Component7_BlackApex_Manual_Reviews.csv")
    assert len(rows) == len(set(r["ip"] for r in rows)) == 170
    tiers = collections.Counter(category(r) for r in rows)
    iocs_by_tier = collections.Counter(category(r) for r in rows
                                       if r["published_ioc"] == "Yes")
    A = {r["ip"] for r in rows if r["sitemap_hash_A"] == "Yes"}
    B = {r["ip"] for r in rows if r["robots_hash_B"] == "Yes"}
    C = {r["ip"] for r in rows if r["javascript_text_C"] == "Yes"}
    iocs = {r["ip"] for r in rows if r["published_ioc"] == "Yes"}
    c_only = [r for r in rows if r["javascript_text_C"] == "Yes"
              and r["sitemap_hash_A"] == "No" and r["robots_hash_B"] == "No"]
    summary = {
        "dataset_scope": "recovered Censys result IPs, 11-12 Nov 2026",
        "A_sitemap_recovered": len(A),
        "B_robots_recovered": len(B),
        "C_js_recovered": len(C),
        "union": len(A | B | C),
        "A_and_B": len(A & B),
        "A_or_B": len(A | B),
        "C_only": len(c_only),
        "C_only_exact_function_snippet": sum(r["exact_function_snippet"] == "Yes" for r in c_only),
        "C_only_not_function_snippet": sum(r["exact_function_snippet"] == "No" for r in c_only),
        "published_ioc_union": len(iocs),
        "published_ioc_A": len(iocs & A),
        "published_ioc_A_or_B": len(iocs & (A | B)),
        "published_ioc_A_or_B_or_C": len(iocs & (A | B | C)),
        "reference_ioc_list_size": 66,
        "indicator_tiers": dict(tiers),
        "published_reference_matches_by_tier": dict(iocs_by_tier),
        "manually_reviewed_cases": len(reviews),
        "manual_workflow_matches": sum(workflow_match(r) for r in reviews),
        "manual_dissimilar_comparisons": sum(not workflow_match(r) for r in reviews),
        "interpretation": (
          "These are search-result overlap and selected-case structural checks, "
          "NOT precision, sensitivity, specificity, false-positive rate, or device-code compromise proof."
        )
    }
    assert (len(A),len(B),len(C),len(A|B|C),len(A&B),len(A|B)) == (100,99,100,170,71,128)
    assert (len(iocs),len(iocs&A),len(iocs&(A|B))) == (31,27,31)
    assert tiers["Both static hashes (with or without JS)"] == 71
    assert tiers["One static hash plus JS search"] == 32
    assert tiers["One static hash only"] == 25
    assert tiers["JS search only"] == 42
    assert summary["manual_workflow_matches"] == 5
    print(json.dumps(summary, indent=2, sort_keys=True))
    (HERE / "Component7_Offline_Evaluation_Results.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True)+"\n", encoding="utf-8")

if __name__ == "__main__":
    evaluate()
