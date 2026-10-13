# easm - External Attack Surface Monitoring CLI

    pip install -e .
    easm doctor                                   # which optional tools/keys are present
    easm run -d slkgroup.com -d slksoftware.com -k slk --org SLK
    easm run --domains-file domains.txt -k slk -k avo
    easm run --repeat last                        # next month: same inputs, diff vs last run
    easm run ... --skip ports --skip leaks        # skip stages: discovery dns ports web leaks
    easm run --resume easm-runs/<run folder>      # continue an interrupted run
    easm report easm-runs/<run folder>            # rebuild xlsx from saved data

Optional tools (used if on PATH): nmap, nuclei, subfinder, theHarvester, dnsrecon, dnstwist.
Optional key: `export HIBP_KEY=...` (domain must be verified in your HIBP dashboard).
Run as root for nmap `-O`. Output per run: `easm-runs/<org>_<timestamp>/` with `EASM_Report_<Mon-YYYY>.xlsx`,
`raw/` (theHarvester/nmap/dnsrecon/Active_Domains.txt evidence), `data/` (stage cache), `findings.json`.
Only scan assets you are authorized to test.
