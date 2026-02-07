"""
Log Retrieval Query - JSON Output Version

Streams logs from Elastic SIEM within ±72 hours of an alert
and outputs to JSON format for REPL consumption.
"""

import os
import json
import elasticsearch
from elasticsearch import helpers
from datetime import datetime, timedelta
from dotenv import load_dotenv
import urllib3

# Suppress warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv()

ELASTIC_HOST = os.getenv("ELASTIC_HOST")
ELASTIC_API_KEY = os.getenv("ELASTIC_API_KEY")
ELASTIC_COMPAT_VERSION = os.getenv("ELASTIC_COMPAT_VERSION", "8")

# Force compatibility headers for older Elastic clusters (7.x/8.x)
ES_HEADERS = {
    "accept": f"application/vnd.elasticsearch+json; compatible-with={ELASTIC_COMPAT_VERSION}",
    "content-type": f"application/vnd.elasticsearch+json; compatible-with={ELASTIC_COMPAT_VERSION}",
}

# Initialize client
client = elasticsearch.Elasticsearch(
    ELASTIC_HOST,
    api_key=ELASTIC_API_KEY,
    verify_certs=False,
    headers=ES_HEADERS,
)


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


def query_logs_json(max_logs=10000, output_path="./get_siem_context/baseline_logs.json"):
    """
    Baseline query: Streams all logs from the alerted host within ±72 hours and
    outputs them as a JSON file for REPL consumption.
    
    Args:
        max_logs: Maximum number of logs to retrieve
        output_path: Path to output JSON file
        
    Returns:
        List of normalized log records
    """
    # 1. Load the alert context
    try:
        with open("./Intake_Alert/normalized_alert.json", "r") as f:
            alert_data = json.load(f)
    except FileNotFoundError:
        print("Error: normalized_alert.json not found.")
        return []

    hostname = alert_data.get("host.name")
    alert_time_str = alert_data.get("Timestamp")
    
    if not hostname or not alert_time_str:
        print("Error: Missing host.name or Timestamp in alert data.")
        return []

    # 2. Calculate time window (±72 hours)
    alert_time = datetime.fromisoformat(alert_time_str.replace("Z", "+00:00"))
    start_time = (alert_time - timedelta(hours=72)).isoformat()
    end_time = (alert_time + timedelta(hours=72)).isoformat()
    
    print(f"[*] Starting Log Retrieval for host: {hostname}")
    print(f"[*] Window: {start_time} --> {end_time}")

    # 3. Build the query
    baseline_query = {
        "query": {
            "bool": {
                "must": [
                    { "match": { "host.name": hostname } }
                ],
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": start_time,
                                "lte": end_time
                            }
                        }
                    }
                ]
            }
        },
        "_source": [
            "@timestamp", "host.name", "user.name", "winlog.user.name", "user.id",
            "event.code", "event.action", "winlog.task", "message",
            "process.name", "process.pid", "process.command_line", "process.executable",
            "process.parent.name", "process.parent.pid", "process.parent.command_line",
            "winlog.process.pid", "winlog.event_data.ParentProcessId",
            "source.ip", "destination.ip", "destination.port", "network.protocol",
            "process.hash.sha256", "file.path", "file.hash.sha256",
            "powershell.file.script_block_text"
        ]
    }

    # 4. Stream and normalize logs
    logs = []
    count = 0
    
    try:
        print("[*] Streaming logs from Elastic...")
        for hit in helpers.scan(client, index="logs-*", query=baseline_query):
            source = hit["_source"]
            
            # Normalize on the fly
            log = {
                "Timestamp": source.get("@timestamp"),
                "Host": get_field(source, "host.name"),
                "User": get_field(source, "user.name") or get_field(source, "winlog.user.name"),
                "User_ID": get_field(source, "user.id"),
                "Event_Code": get_field(source, "event.code"),
                "Action": get_field(source, "event.action"),
                "Task": get_field(source, "winlog.task"),
                "Process_Name": get_field(source, "process.name"),
                "PID": get_field(source, "process.pid") or get_field(source, "winlog.process.pid"),
                "Command_Line": get_field(source, "process.command_line"),
                "Executable": get_field(source, "process.executable"),
                "Parent_Process": get_field(source, "process.parent.name"),
                "Parent_PID": get_field(source, "process.parent.pid") or get_field(source, "winlog.event_data.ParentProcessId"),
                "Parent_Command_Line": get_field(source, "process.parent.command_line"),
                "Source_IP": get_field(source, "source.ip"),
                "Dest_IP": get_field(source, "destination.ip"),
                "Dest_Port": get_field(source, "destination.port"),
                "SHA256": get_field(source, "process.hash.sha256") or get_field(source, "file.hash.sha256"),
                "File_Path": get_field(source, "file.path"),
                "Script_Block": get_field(source, "powershell.file.script_block_text"),
                "Message": get_field(source, "message")
            }
            
            logs.append(log)
            count += 1
            
            if count >= max_logs:
                print(f"[!] Reached max log limit ({max_logs})")
                break
                
            if count % 1000 == 0:
                print(f"    - Retrieved {count} logs...")

        # 5. Save to JSON
        print(f"[*] Saving {len(logs)} logs to {output_path}...")
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=2)
        
        print(f"[+] Success: Retrieved {count} logs into {output_path}")
        return logs

    except Exception as e:
        print(f"[-] Error during streaming: {e}")
        return []


if __name__ == "__main__":
    query_logs_json(max_logs=10000)
