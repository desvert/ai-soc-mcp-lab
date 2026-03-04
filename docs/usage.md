## Evidence directory model

All investigation data lives in:
```
/srv/evidence/soc/cases/<case>/
```

Structure:
```
raw/
derived/
reports/
```

The MCP containers mount /srv/evidence read-only.

---

## Human-in-the-loop design

The LLM:
- summarizes findings
- proposes hypotheses
- recommends investigation steps

Deterministic tools:
- parse PCAP
- extract DNS/HTTP activity
- return structured evidence

Security boundaries
- MCP servers run inside Docker containers
- Containers run with:
- read-only evidence mounts
- no network access
- non-root user