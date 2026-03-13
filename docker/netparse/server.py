import json
import os
import glob
import subprocess
from typing import Any, Dict, List

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("netparse")

EVIDENCE_ROOT = "/evidence"

def _run_tshark(args: List[str]) -> subprocess.CompletedProcess:
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"tshark failed: {proc.stderr.strip()}")
    return proc

def _first_pcap_in_case(case_dir: str) -> str:
    raw = _find_case_raw(case_dir)
    pcaps = sorted(glob.glob(os.path.join(raw, "*.pcap"))) + sorted(glob.glob(os.path.join(raw, "*.pcapng")))
    if not pcaps:
        raise FileNotFoundError(f"No PCAPs found in: {raw}")
    return _safe_join(pcaps[0])

def _safe_join(path: str) -> str:
    real = os.path.realpath(path)
    root = os.path.realpath(EVIDENCE_ROOT) + os.sep
    if not real.startswith(root):
        raise ValueError(f"Path outside evidence root: {path}")
    return real

def _find_case_raw(case_dir: str) -> str:
    case_dir = _safe_join(case_dir)
    raw = os.path.join(case_dir, "raw")
    if not os.path.isdir(raw):
        raise FileNotFoundError(f"No raw/ folder found at: {raw}")
    return raw

@mcp.tool()
def suricata_alerts(
    case_dir: str,
    limit: int = 50,
    contains: str = "",
    severity_min: int = 0
) -> Dict[str, Any]:
    """
    Read Suricata eve.json from <case_dir>/raw/eve.json and return recent alert events.

    Optional filters:
      - contains: substring match against alert.signature and alert.category (case-insensitive)
      - severity_min: keep alerts with alert.severity >= severity_min
    """
    raw = _find_case_raw(case_dir)
    eve_path = _safe_join(os.path.join(raw, "eve.json"))

    if not os.path.isfile(eve_path):
        raise FileNotFoundError(f"Missing eve.json at: {eve_path}")

    needle = (contains or "").strip().lower()
    sev_min = int(severity_min or 0)

    alerts: List[Dict[str, Any]] = []
    total_alert_events = 0

    with open(eve_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue

            if evt.get("event_type") != "alert":
                continue

            total_alert_events += 1
            alert = evt.get("alert") or {}

            # severity filter
            sev = alert.get("severity")
            try:
                sev_int = int(sev) if sev is not None else 0
            except Exception:
                sev_int = 0
            if sev_int < sev_min:
                continue

            # contains filter
            if needle:
                sig = str(alert.get("signature") or "").lower()
                cat = str(alert.get("category") or "").lower()
                if needle not in sig and needle not in cat:
                    continue

            alerts.append(evt)

    # keep latest matching alerts
    alerts = alerts[-max(1, int(limit or 50)):]

    return {
        "case_dir": case_dir,
        "eve_path": eve_path,
        "filters": {"contains": contains, "severity_min": sev_min, "limit": limit},
        "total_alert_events": total_alert_events,
        "returned": len(alerts),
        "alerts": alerts,
    }

@mcp.tool()
def pcap_conversations(case_dir: str) -> Dict[str, Any]:
    raw = _find_case_raw(case_dir)
    pcaps = sorted(glob.glob(os.path.join(raw, "*.pcap"))) + sorted(glob.glob(os.path.join(raw, "*.pcapng")))
    if not pcaps:
        raise FileNotFoundError(f"No PCAPs found in: {raw}")

    pcap_path = _safe_join(pcaps[0])

    # TCP conversations summary
    cmd = ["tshark", "-r", pcap_path, "-q", "-z", "conv,tcp"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"tshark failed: {proc.stderr.strip()}")

    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    
    return {
        "case_dir": case_dir,
        "pcap_path": pcap_path,
        "command": " ".join(cmd),
        "output_lines": lines,
    }

@mcp.tool()
def pcap_dns_summary(case_dir: str, limit: int = 30) -> Dict[str, Any]:
    """
    Summarize DNS activity from the first PCAP in <case_dir>/raw:
    - top queried names (dns.qry.name)
    - top responders (dns.a)
    Returns structured JSON.
    """
    case_dir = _safe_join(case_dir)
    pcap_path = _first_pcap_in_case(case_dir)

    # Extract queried names
    cmd_q = [
        "tshark", "-r", pcap_path,
        "-Y", "dns.qry.name",
        "-T", "fields",
        "-e", "dns.qry.name"
    ]
    out_q = _run_tshark(cmd_q).stdout.splitlines()

    # Extract A record answers (responders)
    cmd_a = [
        "tshark", "-r", pcap_path,
        "-Y", "dns.a",
        "-T", "fields",
        "-e", "dns.a"
    ]
    out_a = _run_tshark(cmd_a).stdout.splitlines()

    def top_counts(lines: List[str], n: int) -> List[Dict[str, Any]]:
        counts: Dict[str, int] = {}
        for ln in lines:
            ln = ln.strip()
            if not ln:
                continue
            # tshark may emit multiple values separated by commas in a single field
            for item in ln.split(","):
                item = item.strip()
                if not item:
                    continue
                counts[item] = counts.get(item, 0) + 1
        ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:max(1, n)]
        return [{"value": k, "count": v} for k, v in ranked]

    top_queries = top_counts(out_q, limit)
    top_answers = top_counts(out_a, limit)

    return {
        "case_dir": case_dir,
        "pcap_path": pcap_path,
        "limit": limit,
        "top_dns_queries": top_queries,
        "top_dns_a_records": top_answers,
        "provenance": {
            "query_command": " ".join(cmd_q),
            "a_record_command": " ".join(cmd_a),
            "total_query_rows": len(out_q),
            "total_a_record_rows": len(out_a),
        }
    }

@mcp.tool()
def pcap_http_hosts(case_dir: str, limit: int = 30) -> Dict[str, Any]:
    """
    Summarize HTTP Host header values from the first PCAP in <case_dir>/raw.
    Returns structured JSON: top hosts and counts.
    """
    case_dir = _safe_join(case_dir)
    pcap_path = _first_pcap_in_case(case_dir)

    cmd = [
        "tshark", "-r", pcap_path,
        "-Y", "http.host",
        "-T", "fields",
        "-e", "http.host"
    ]
    out = _run_tshark(cmd).stdout.splitlines()

    counts: Dict[str, int] = {}
    for ln in out:
        ln = ln.strip()
        if not ln:
            continue
        # some packets can have multiple values; split defensively
        for item in ln.split(","):
            item = item.strip()
            if not item:
                continue
            counts[item] = counts.get(item, 0) + 1

    ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:max(1, limit)]

    return {
        "case_dir": case_dir,
        "pcap_path": pcap_path,
        "limit": limit,
        "top_http_hosts": [{"host": k, "count": v} for k, v in ranked],
        "provenance": {
            "command": " ".join(cmd),
            "total_rows": len(out),
        }
    }

@mcp.tool()
def pcap_extract_fields(
    case_dir: str,
    display_filter: str,
    fields: List[str],
    limit: int = 200
) -> Dict[str, Any]:
    """
    Extract arbitrary tshark fields from the first PCAP in <case_dir>/raw
    using a Wireshark display filter.

    Example:
      display_filter="dns"
      fields=["frame.time", "ip.src", "ip.dst", "dns.qry.name", "dns.a"]

    Returns structured JSON rows (list of dicts).
    """
    case_dir = _safe_join(case_dir)
    pcap_path = _first_pcap_in_case(case_dir)

    if not fields or any(not f.strip() for f in fields):
        raise ValueError("fields must be a non-empty list of tshark field names")

    # Build tshark command:
    # -Y <filter>
    # -T fields with a TAB separator for reliable parsing
    cmd = ["tshark", "-r", pcap_path, "-Y", display_filter, "-T", "fields", "-E", "separator=\t"]

    for f in fields:
        cmd += ["-e", f]

    proc = _run_tshark(cmd)

    rows: List[Dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        # tshark can return fewer columns if fields are missing
        row = {}
        for idx, field_name in enumerate(fields):
            row[field_name] = parts[idx] if idx < len(parts) else ""
        rows.append(row)
        if len(rows) >= max(1, limit):
            break

    return {
        "case_dir": case_dir,
        "pcap_path": pcap_path,
        "display_filter": display_filter,
        "fields": fields,
        "limit": limit,
        "count": len(rows),
        "rows": rows,
        "provenance": {
            "command": " ".join(cmd),
            "notes": "Rows are parsed from tshark -T fields output using TAB separator.",
        },
    }

@mcp.tool()
def pcap_triage_overview(
    case_dir: str,
    dns_limit: int = 30,
    http_limit: int = 30,
    extract_limit: int = 50
) -> Dict[str, Any]:
    """
    One-call PCAP triage overview.

    Runs:
      - pcap_conversations (TCP conv table tail)
      - pcap_dns_summary (top queries + top A records)
      - pcap_http_hosts (top HTTP Host headers)

    Also includes a couple of lightweight field extractions to help with pivots.
    Returns a single structured JSON object suitable for LLM summarization.
    """
    case_dir = _safe_join(case_dir)
    pcap_path = _first_pcap_in_case(case_dir)

    # Reuse existing tools (call the underlying Python functions directly)
    conv = pcap_conversations(case_dir)
    dns = pcap_dns_summary(case_dir, limit=dns_limit)
    http = pcap_http_hosts(case_dir, limit=http_limit)

    # Optional: a couple of quick extractions that are often useful
    # DNS rows with time/src/dst/name/a
    dns_rows = pcap_extract_fields(
        case_dir=case_dir,
        display_filter="dns",
        fields=["frame.time", "ip.src", "ip.dst", "dns.qry.name", "dns.a"],
        limit=extract_limit,
    )

    # HTTP rows with time/src/dst/host/uri (uri may not exist on every packet)
    http_rows = pcap_extract_fields(
        case_dir=case_dir,
        display_filter="http",
        fields=["frame.time", "ip.src", "ip.dst", "http.host", "http.request.uri"],
        limit=extract_limit,
    )

    return {
        "case_dir": case_dir,
        "pcap_path": pcap_path,
        "sections": {
            "conversations": conv,
            "dns_summary": dns,
            "http_hosts": http,
            "dns_sample_rows": dns_rows,
            "http_sample_rows": http_rows,
        },
        "notes": [
            "This overview is deterministic and offline (tshark-based).",
            "Not all PCAPs contain HTTP. Modern traffic may be mostly TLS.",
            "Use pcap_extract_fields for targeted pivots (dns.qry.name, tls.handshake.extensions_server_name, http.request.uri, etc).",
        ],
    }

if __name__ == "__main__":
    mcp.run()