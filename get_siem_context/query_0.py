import os
import json
import csv
import warnings
import elasticsearch
from elasticsearch import helpers
from datetime import datetime, timedelta
from dotenv import load_dotenv
import urllib3

load_dotenv()

ELASTIC_HOST = os.getenv("ELASTIC_HOST") or os.getenv("ELASTIC_BASE_URL")
ELASTIC_API_KEY = os.getenv("ELASTIC_API_KEY")
ELASTIC_COMPAT_VERSION = os.getenv("ELASTIC_COMPAT_VERSION", "8")
ELASTIC_VERIFY_CERTS = os.getenv("ELASTIC_VERIFY_CERTS", "false").lower() in {"1", "true", "yes"}
ELASTIC_CA_CERTS = os.getenv("ELASTIC_CA_CERTS")

# Force compatibility headers for older Elastic clusters (7.x/8.x)
ES_HEADERS = {
    "Accept": f"application/vnd.elasticsearch+json; compatible-with={ELASTIC_COMPAT_VERSION}",
    "Content-Type": f"application/vnd.elasticsearch+json; compatible-with={ELASTIC_COMPAT_VERSION}",
}

# Suppress warnings when verify_certs is disabled
if not ELASTIC_VERIFY_CERTS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    warnings.filterwarnings("ignore", message=".*verify_certs=False is insecure.*")
    try:
        from elastic_transport import SecurityWarning

        warnings.filterwarnings("ignore", category=SecurityWarning)
    except Exception:
        pass
    try:
        from elasticsearch import SecurityWarning as EsSecurityWarning

        warnings.filterwarnings("ignore", category=EsSecurityWarning)
    except Exception:
        pass

# Initialize client
client = elasticsearch.Elasticsearch(
    ELASTIC_HOST,
    api_key=ELASTIC_API_KEY,
    verify_certs=ELASTIC_VERIFY_CERTS,
    ca_certs=ELASTIC_CA_CERTS if ELASTIC_VERIFY_CERTS else None,
    headers=ES_HEADERS,
)


def _raw_http_scan(index_pattern: str, query: dict, max_logs: int) -> list[dict]:
    if not ELASTIC_HOST or not ELASTIC_API_KEY:
        raise ValueError("Elastic configuration missing. Set ELASTIC_HOST and ELASTIC_API_KEY.")

    cert_reqs = "CERT_REQUIRED" if ELASTIC_VERIFY_CERTS else "CERT_NONE"
    http = urllib3.PoolManager(cert_reqs=cert_reqs, ca_certs=ELASTIC_CA_CERTS if ELASTIC_VERIFY_CERTS else None)
    base_url = ELASTIC_HOST.rstrip("/")
    url = f"{base_url}/{index_pattern}/_search"
    headers = {
        "Accept": ES_HEADERS["Accept"],
        "Content-Type": ES_HEADERS["Content-Type"],
        "Authorization": f"ApiKey {ELASTIC_API_KEY}",
    }

    size = min(1000, max_logs) if max_logs > 0 else 1000
    payload = dict(query)
    payload["size"] = size
    payload.pop("track_total_hits", None)
    payload.setdefault("sort", ["_doc"])

    results = []
    response = http.request("POST", f"{url}?scroll=1m", body=json.dumps(payload), headers=headers)
    if response.status >= 400:
        raise ValueError(f"Elastic HTTP {response.status}: {response.data[:500]}")
    data = json.loads(response.data.decode("utf-8"))
    scroll_id = data.get("_scroll_id")
    hits = data.get("hits", {}).get("hits", [])
    while hits:
        for hit in hits:
            results.append(hit)
            if 0 < max_logs <= len(results):
                return results
        if not scroll_id:
            break
        scroll_body = {"scroll": "1m", "scroll_id": scroll_id}
        scroll_resp = http.request(
            "POST",
            f"{base_url}/_search/scroll",
            body=json.dumps(scroll_body),
            headers=headers,
        )
        if scroll_resp.status >= 400:
            raise ValueError(f"Elastic HTTP {scroll_resp.status}: {scroll_resp.data[:500]}")
        data = json.loads(scroll_resp.data.decode("utf-8"))
        scroll_id = data.get("_scroll_id")
        hits = data.get("hits", {}).get("hits", [])
    return results

def get_field(data, path):
    """
    Helper to extract fields from nested or flat Elastic JSON.
    """
    if path in data:
        return data[path]
    keys = path.split('.')
    temp = data
    for key in keys:
        if isinstance(temp, dict) and key in temp:
            temp = temp.get(key)
        else:
            return None
    return temp


def _build_host_query(hostname: str, start_time: str, end_time: str) -> dict:
    host_should = [
        {"term": {"host.name.keyword": hostname}},
        {"match": {"host.name": hostname}},
        {"term": {"host.hostname.keyword": hostname}},
        {"match": {"host.hostname": hostname}},
        {"term": {"agent.name.keyword": hostname}},
        {"match": {"agent.name": hostname}},
        {"term": {"winlog.computer_name.keyword": hostname}},
        {"match": {"winlog.computer_name": hostname}},
        {"term": {"host.id": hostname}},
        {"match": {"host.id": hostname}},
    ]
    return {
        "query": {
            "bool": {
                "should": host_should,
                "minimum_should_match": 1,
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": start_time,
                                "lte": end_time,
                            }
                        }
                    }
                ],
            }
        },
        "_source": [
            "@timestamp", "host.name", "host.hostname", "winlog.computer_name", "agent.name",
            "user.name", "winlog.user.name", "user.id", "winlog.event_data.TargetUserName",
            "event.code", "winlog.event_id", "event.action", "winlog.task", "message",
            "process.name", "process.pid", "process.command_line", "process.executable",
            "process.parent.name", "process.parent.pid", "process.parent.command_line",
            "process.args",
            "winlog.process.pid", "winlog.event_data.ParentProcessId",
            "winlog.event_data.CommandLine", "winlog.event_data.ProcessCommandLine",
            "source.ip", "destination.ip", "destination.port", "network.protocol",
            "process.hash.sha256", "file.path", "file.hash.sha256",
            "powershell.file.script_block_text", "winlog.event_data.ScriptBlockText",
        ],
    }


def _build_time_query(start_time: str, end_time: str) -> dict:
    return {
        "query": {
            "bool": {
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": start_time,
                                "lte": end_time,
                            }
                        }
                    }
                ]
            }
        },
        "_source": [
            "@timestamp", "host.name", "host.hostname", "winlog.computer_name", "agent.name",
            "user.name", "winlog.user.name", "user.id", "winlog.event_data.TargetUserName",
            "event.code", "winlog.event_id", "event.action", "winlog.task", "message",
            "process.name", "process.pid", "process.command_line", "process.executable",
            "process.parent.name", "process.parent.pid", "process.parent.command_line",
            "process.args",
            "winlog.process.pid", "winlog.event_data.ParentProcessId",
            "winlog.event_data.CommandLine", "winlog.event_data.ProcessCommandLine",
            "source.ip", "destination.ip", "destination.port", "network.protocol",
            "process.hash.sha256", "file.path", "file.hash.sha256",
            "powershell.file.script_block_text", "winlog.event_data.ScriptBlockText",
        ],
    }


def _build_host_only_query(hostname: str) -> dict:
    host_should = [
        {"term": {"host.name.keyword": hostname}},
        {"match": {"host.name": hostname}},
        {"term": {"host.hostname.keyword": hostname}},
        {"match": {"host.hostname": hostname}},
        {"term": {"agent.name.keyword": hostname}},
        {"match": {"agent.name": hostname}},
        {"term": {"winlog.computer_name.keyword": hostname}},
        {"match": {"winlog.computer_name": hostname}},
        {"term": {"host.id": hostname}},
        {"match": {"host.id": hostname}},
    ]
    return {
        "query": {
            "bool": {
                "should": host_should,
                "minimum_should_match": 1,
            }
        },
        "_source": [
            "@timestamp", "host.name", "host.hostname", "winlog.computer_name", "agent.name",
            "user.name", "winlog.user.name", "user.id", "winlog.event_data.TargetUserName",
            "event.code", "winlog.event_id", "event.action", "winlog.task", "message",
            "process.name", "process.pid", "process.command_line", "process.executable",
            "process.parent.name", "process.parent.pid", "process.parent.command_line",
            "process.args",
            "winlog.process.pid", "winlog.event_data.ParentProcessId",
            "winlog.event_data.CommandLine", "winlog.event_data.ProcessCommandLine",
            "source.ip", "destination.ip", "destination.port", "network.protocol",
            "process.hash.sha256", "file.path", "file.hash.sha256",
            "powershell.file.script_block_text", "winlog.event_data.ScriptBlockText",
        ],
    }


def _build_match_all_query() -> dict:
    return {
        "query": {"match_all": {}},
        "_source": [
            "@timestamp", "host.name", "host.hostname", "winlog.computer_name", "agent.name",
            "user.name", "winlog.user.name", "user.id", "winlog.event_data.TargetUserName",
            "event.code", "winlog.event_id", "event.action", "winlog.task", "message",
            "process.name", "process.pid", "process.command_line", "process.executable",
            "process.parent.name", "process.parent.pid", "process.parent.command_line",
            "process.args",
            "winlog.process.pid", "winlog.event_data.ParentProcessId",
            "winlog.event_data.CommandLine", "winlog.event_data.ProcessCommandLine",
            "source.ip", "destination.ip", "destination.port", "network.protocol",
            "process.hash.sha256", "file.path", "file.hash.sha256",
            "powershell.file.script_block_text", "winlog.event_data.ScriptBlockText",
        ],
    }

def query_0(max_logs=10000, output_path: str = "./get_siem_context/baseline_context.csv", index_pattern: str = "logs-*"):
    """
    Baseline query: Streams all logs from the alerted host within ±72 hours and
    normalizes them into a high-fidelity CSV for RLM consumption.
    Includes technical telemetry (Process, Network, Hashes, Registry).
    """
    # 1. Load the alert context
    try:
        with open("./Intake_Alert/normalized_alert.json", "r") as f:
            alert_data = json.load(f)
    except FileNotFoundError:
        print("Error: normalized_alert.json not found.")
        return

    hostname = alert_data.get("host.name")
    alert_time_str = alert_data.get("Timestamp")
    
    if not hostname or not alert_time_str:
        print("Error: Missing host.name or Timestamp in alert data.")
        return

    # 2. Calculate time window (±72 hours default)
    alert_time = datetime.fromisoformat(alert_time_str.replace("Z", "+00:00"))
    window_hours = int(os.getenv("RLM_ALERT_WINDOW_HOURS", "72"))
    start_time = (alert_time - timedelta(hours=window_hours)).isoformat()
    end_time = (alert_time + timedelta(hours=window_hours)).isoformat()
    
    print(f"[*] Starting Enriched Baseline Context Stream for host: {hostname}")
    print(f"[*] Window: {start_time} --> {end_time}")

    # 3. Build the query (broad host match + time range)
    baseline_query = _build_host_query(hostname, start_time, end_time)

    # 4. Define CSV Structure (High Fidelity Schema)
    fields = [
        "Timestamp", "Host", "User", "User_ID", "Event_Code", "Action", "Task",
        "Process_Name", "PID", "Command_Line", "Executable",
        "Parent_Process", "Parent_PID", "Parent_Command_Line",
        "Source_IP", "Dest_IP", "Dest_Port", 
        "SHA256", "File_Path",
        "Script_Block", "Message"
    ]

    count = 0
    try:
        with open(output_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fields)
            writer.writeheader()

            def _write_row(source: dict) -> None:
                nonlocal count
                row = {
                    "Timestamp": source.get("@timestamp"),
                    "Host": get_field(source, "host.name") or get_field(source, "host.hostname") or get_field(source, "winlog.computer_name") or get_field(source, "agent.name"),
                    "User": get_field(source, "user.name") or get_field(source, "winlog.user.name") or get_field(source, "winlog.event_data.TargetUserName"),
                    "User_ID": get_field(source, "user.id"),
                    "Event_Code": get_field(source, "event.code") or get_field(source, "winlog.event_id"),
                    "Action": get_field(source, "event.action"),
                    "Task": get_field(source, "winlog.task"),
                    "Process_Name": get_field(source, "process.name"),
                    "PID": get_field(source, "process.pid") or get_field(source, "winlog.process.pid"),
                    "Command_Line": get_field(source, "process.command_line") or get_field(source, "winlog.event_data.CommandLine") or get_field(source, "winlog.event_data.ProcessCommandLine"),
                    "Executable": get_field(source, "process.executable"),
                    "Parent_Process": get_field(source, "process.parent.name"),
                    "Parent_PID": get_field(source, "process.parent.pid") or get_field(source, "winlog.event_data.ParentProcessId"),
                    "Parent_Command_Line": get_field(source, "process.parent.command_line"),
                    "Source_IP": get_field(source, "source.ip"),
                    "Dest_IP": get_field(source, "destination.ip"),
                    "Dest_Port": get_field(source, "destination.port"),
                    "SHA256": get_field(source, "process.hash.sha256") or get_field(source, "file.hash.sha256"),
                    "File_Path": get_field(source, "file.path") or get_field(source, "process.executable"),
                    "Script_Block": get_field(source, "powershell.file.script_block_text") or get_field(source, "winlog.event_data.ScriptBlockText"),
                    "Message": get_field(source, "message")
                }
                writer.writerow(row)
                count += 1

            print("[*] Streaming logs from Elastic...")
            patterns = [p.strip() for p in str(index_pattern).split(",") if p.strip()]
            if not patterns:
                patterns = ["logs-*"]

            def _stream_hits(query: dict, pattern: str) -> None:
                try:
                    hits_iter = helpers.scan(client, index=pattern, query=query)
                    for hit in hits_iter:
                        _write_row(hit["_source"])
                        if count >= max_logs:
                            print(f"[!] Reached max log limit ({max_logs})")
                            return
                        if count % 1000 == 0:
                            print(f"    - Processed {count} logs...")
                except Exception as exc:
                    message = str(exc)
                    if "media_type_header_exception" not in message and "compatible-with=9" not in message:
                        raise
                    hits_iter = _raw_http_scan(pattern, query, max_logs - count)
                    for hit in hits_iter:
                        _write_row(hit["_source"])
                        if count >= max_logs:
                            print(f"[!] Reached max log limit ({max_logs})")
                            return
                        if count % 1000 == 0:
                            print(f"    - Processed {count} logs...")

            def _stream_for_patterns(query: dict) -> None:
                for pattern in patterns:
                    if count >= max_logs:
                        return
                    _stream_hits(query, pattern)

            _stream_for_patterns(baseline_query)
            if count == 0 and os.getenv("RLM_ALLOW_HOST_ONLY_FALLBACK", "1") == "1":
                print("[!] Host+time query returned 0 logs. Falling back to host-only.")
                baseline_query = _build_host_only_query(hostname)
                _stream_for_patterns(baseline_query)
            if count == 0 and os.getenv("RLM_ALLOW_HOST_FALLBACK", "1") == "1":
                print("[!] Host filter returned 0 logs. Falling back to time-range only.")
                baseline_query = _build_time_query(start_time, end_time)
                _stream_for_patterns(baseline_query)
            if count == 0 and os.getenv("RLM_ALLOW_INDEX_FALLBACK", "1") == "1":
                print("[!] Time-range query returned 0 logs. Falling back to match_all sample.")
                baseline_query = _build_match_all_query()
                _stream_for_patterns(baseline_query)

        print(f"[+] Success: Enriched {count} logs into {output_path}")

    except Exception as e:
        print(f"[-] Error during streaming/normalization: {e}")

if __name__ == "__main__":
    query_0(max_logs=10000)
