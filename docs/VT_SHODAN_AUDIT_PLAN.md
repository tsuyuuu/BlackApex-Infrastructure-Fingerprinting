# VirusTotal and Shodan: evidence audit plan (NOT additional findings)

These were considered during early collection. Do **not** remove them from a
source list by default; first check whether preserved Shodan/VirusTotal records
support a concrete contribution to the investigation. The repository does not
claim new findings from these services.

Possible useful questions:
- Can timestamped Shodan service history independently corroborate Censys
  observation periods, ports, response titles or hosting changes? Avoid
  treating scan visibility as proof of campaign continuity.
- Do VirusTotal's available domain/IP reports document independently submitted
  malicious URLs, linked infrastructure, or historical detections tied to a
  *specific examined host*? Vendor scores alone do not establish malice.
- Did the source reveal an inconsistency or important limitation? A documented
  negative or unavailable result may be informative if accurately described.

For every retained claim, record: host/domain; source URL or local evidence file;
collection/observation time; exact observed artifact; contribution to a
finding; limitations and alternative explanations. Use
`ENRICHMENT_EVIDENCE_TEMPLATE.csv`.

Avoid attributing live status, actor ownership, or confirmed maliciousness to
unlisted hosts based solely on a Shodan or VirusTotal result.
