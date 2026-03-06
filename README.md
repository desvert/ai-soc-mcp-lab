# AI-Assisted SOC Triage Lab (Claude + MCP + Docker)

This lab explores a simple idea: use an LLM as a junior analyst, but rely on deterministic tools for the actual evidence.

Instead of asking an AI to "analyze a PCAP," this project exposes a set of network analysis tools via the Model Context Protocol (MCP). Claude Code calls those tools, inspects the structured results, and writes a triage note grounded in real tool output.

The goal is not full automation. It is assisted investigation with verifiable evidence.

For the full writeup and background on why this was built this way, see the [blog post](https://desvert.github.io/blog/2026/03/04/building-an-ai-assisted-soc-triage-lab.html).

---

## Architecture

```
Claude Code
   ↓
MCP tools (netparse)
   ↓
Docker container (network disabled, non-root, read-only mounts)
   ↓
tshark / parsers
   ↓
/srv/evidence (read-only)
```

Key design principles:

- **tshark** does the deterministic packet parsing
- **MCP tools** wrap tshark output into structured JSON
- **Claude** reasons over that JSON and writes the triage note
- The container has no network access and cannot write back to evidence

---

## Requirements

- Docker and Docker Compose
- Claude Code (with MCP support)
- Evidence directory at `/srv/evidence` (or adjust the volume mount in `docker-compose.yml`)

---

## Setup

**1. Clone the repository**

```bash
git clone https://github.com/desvert/ai-soc-mcp-lab
cd ai-soc-mcp-lab
```

**2. Build the container**

```bash
docker compose build
```

**3. Create a case directory and drop in a PCAP**

```bash
mkdir -p /srv/evidence/soc/cases/testcase/raw
cp your-capture.pcap /srv/evidence/soc/cases/testcase/raw/
```

**4. Register the MCP server with Claude Code**

Add the following to your Claude Code MCP configuration:

```json
{
  "mcpServers": {
    "netparse": {
      "command": "docker",
      "args": [
        "compose", "-f", "/path/to/ai-soc-mcp-lab/docker-compose.yml",
        "run", "--rm", "-i", "netparse"
      ]
    }
  }
}
```

**5. Run a triage**

In Claude Code, ask:

```
Run pcap_triage_overview on /evidence/soc/cases/testcase and write a triage note.
```

---

## Evidence Directory Structure

All case data lives under a single root:

```
/srv/evidence/soc/cases/<case>/
├── raw/            # Original evidence (PCAP, eve.json) — never modified
├── derived/        # Outputs from tool processing
└── reports/        # Triage notes and analyst reports
```

The container mounts `/srv/evidence` read-only. Nothing the model does can modify original evidence.

---

## MCP Tools

The `netparse` server exposes the following tools. All tools return structured JSON.

### Packet analysis

| Tool | Description |
|------|-------------|
| `pcap_triage_overview` | Runs DNS, HTTP, and conversation analysis in a single call. Main entry point for triage. |
| `pcap_dns_summary` | Top queried DNS names and top A-record responses with counts |
| `pcap_http_hosts` | Top HTTP Host header values with counts |
| `pcap_conversations` | TCP conversation summary (tshark conv,tcp output) |
| `pcap_extract_fields` | Generic tshark field extractor with display filter support |

### IDS / alert analysis

| Tool | Description |
|------|-------------|
| `suricata_alerts` | Parse Suricata `eve.json`; supports filtering by signature substring and minimum severity |

### Tool notes

- All tools accept a `case_dir` path and operate on the first `.pcap` or `.pcapng` found in `<case_dir>/raw/`.
- All paths are validated against the evidence root to prevent traversal.
- `pcap_extract_fields` accepts arbitrary tshark display filters and field names, making it useful for follow-up pivots after an initial triage.

---

## Example: `pcap_extract_fields`

For targeted follow-up after a triage overview, use `pcap_extract_fields` to pull specific fields:

```
Extract fields frame.time, ip.src, ip.dst, dns.qry.name, dns.a
from case /evidence/soc/cases/testcase
using display filter: dns.a == "10.90.90.90"
```

This is how you would, for example, enumerate every domain name that resolved to a suspicious internal IP.

---

## Example Output

See [`examples/testcase/triage-note-example.md`](examples/testcase/triage-note-example.md) for a full sample triage note generated from a real PCAP.

That example covers a Windows AD environment with an active RDP scan from an external IP, suspicious DNS patterns, anomalous internal traffic, and five graded hypotheses with suggested investigation steps.

---

## Security Boundaries

The container is locked down deliberately:

```yaml
network_mode: "none"      # no outbound or inbound network
user: "1000:1000"         # non-root
volumes:
  - /srv/evidence:/evidence:ro   # read-only evidence mount
```

The model has no path to the host filesystem and cannot make network calls. If a capture file contains embedded prompt injection attempts, the blast radius is limited to the container context.

---

## Repository Structure

```
.
├── docker-compose.yml
├── docker/
│   └── netparse/
│       ├── Dockerfile
│       ├── requirements.txt
│       └── server.py          # MCP server (FastMCP + tshark wrappers)
├── examples/
│   └── testcase/
│       └── triage-note-example.md
└── docs/
    ├── architecture.md
    ├── triage-workflow.md
    └── usage.md
```

---

## Future Work

- TLS SNI analysis (`tls.handshake.extensions_server_name`)
- JA3 fingerprint extraction
- Zeek log ingestion
- Suricata integration with full alert filtering
- OT protocol analysis tools (Modbus, BACnet, DNP3)

---

## Related

- [Blog post](https://desvert.github.io/blog/2026/03/04/building-an-ai-assisted-soc-triage-lab.html) — background, design decisions, and lessons learned
