# AI-Assisted SOC Triage Lab (Claude + MCP + Docker)

This project explores a simple idea:

Use an LLM as a junior analyst, but rely on deterministic tools for evidence.

Instead of asking an AI to “analyze a PCAP”, this lab exposes a set of network analysis tools via the Model Context Protocol (MCP). Claude can call those tools, inspect the results, and then write a triage note.

The goal is not full automation. The goal is assisted investigation with verifiable evidence.


## Architecture
```
Claude Code
   ↓
MCP tools (netparse)
   ↓
Docker container
   ↓
tshark / parsers
   ↓
Evidence directory (`/srv/evidence`)
```

Key principles:

- Deterministic parsing (tshark) for packet analysis
- LLM for reasoning and reporting
- Containerized tools for isolation and reproducibility
- Read-only evidence access


## Project Goals

This lab is intended to demonstrate:

- A practical use of the Model Context Protocol
- How AI can assist SOC triage workflows
- How to keep investigations evidence-driven
- A repeatable architecture for AI + security tooling


## Evidence Directory Structure

All investigation data lives under:
```
/srv/evidence/soc/cases/<case>/
```

Example:
```
/srv/evidence/soc/cases/testcase/
├── raw/
│ └── capture.pcap
├── derived/
└── reports/
```

The MCP container mounts the evidence directory read-only.


## MCP Tools

The `netparse` server currently exposes the following tools:

### Packet analysis tools

| Tool | Description |
|-----|-------------|
| `pcap_triage_overview` | One-call PCAP triage summary |
| `pcap_dns_summary` | Top DNS queries and responses |
| `pcap_http_hosts` | Top HTTP host headers |
| `pcap_conversations` | TCP conversation summary |
| `pcap_extract_fields` | Generic tshark field extraction |

### IDS analysis

| Tool | Description |
|-----|-------------|
| `suricata_alerts` | Parse Suricata `eve.json` alerts |

These tools return structured JSON which Claude can analyze.


## Example Workflow
1. Drop PCAP into `/srv/evidence/soc/cases/testcase/raw`

2. Ask Claude to triage:

```
Run pcap_triage_overview on /evidence/soc/cases/testcase
and generate a triage note.
```

3. Claude will:

- call the MCP tool
- analyze the results
- produce a structured triage report


## Example Output

Example triage notes include:

- summary of network activity
- notable DNS queries
- unusual IP conversations
- potential indicators of compromise
- suggested next steps

Each finding references the tool output used as evidence.


## Security Boundaries

The MCP server runs inside a Docker container with:

- read-only evidence mounts
- network disabled
- non-root user

This prevents the LLM from directly interacting with the host system.


## Why This Approach

Packet analysis requires deterministic parsing.

LLMs are useful for:

- summarization
- hypothesis generation
- investigation guidance

But they should not replace the underlying tools.

This architecture keeps the AI focused on reasoning while leaving parsing to tools designed for it.


## Future Work

Planned improvements include:

- TLS SNI analysis
- JA3 fingerprint summaries
- Zeek log ingestion
- Suricata integration with full alert filtering
- OT protocol analysis tools


## Motivation

This project is part of my broader exploration of:

- SOC workflows
- incident investigation
- AI-assisted tooling
- OT / critical infrastructure security

The goal is to understand how these systems actually work in practice, not just conceptually.


