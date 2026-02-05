import os
import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from Intake_Alert.Intake_Elastic_logs import Elastic
import json

def get_field(data, path):
    """
    Retrieves a field from a dictionary. 
    1. Tries the literal path (e.g., 'event.code').
    2. Tries the nested path (e.g., 'winlog.task' -> data['winlog']['task']).
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

raw_alert_path = "./Intake_Alert/raw_alert.json"
if os.path.exists(raw_alert_path):
    with open(raw_alert_path, "r") as f:
        raw_alert = json.load(f)
else:
    raw_alert = Elastic.Alert()
    with open(raw_alert_path, "w") as f:
        json.dump(raw_alert, f, indent=4)

def normalize():
  
        
    normalized_alert = {
        "Timestamp": raw_alert.get("@timestamp"),
        
        # ===================== PROCESS FIELDS =====================
        "process.command_line": get_field(raw_alert, "process.command_line"),
        "process.args": get_field(raw_alert, "process.args"),
        "process.pid": get_field(raw_alert, "winlog.process.pid"), # Maps to winlog.process.pid in this event
        "winlog.process.pid": get_field(raw_alert, "winlog.process.pid"),
        "message": get_field(raw_alert, "message"),
        "Process.command.message": get_field(raw_alert, "message"),

        # ===================== EVENT METADATA =====================
        "event.created" : get_field(raw_alert, "event.created"),
        "event.code": get_field(raw_alert, "event.code"),
        "event.provider": get_field(raw_alert, "event.provider"),
        "event.category": get_field(raw_alert, "event.category"),

        # ===================== HOST + OS ATTRIBUTES =====================
        "host.name": get_field(raw_alert, "host.name"),
        "host.ip": get_field(raw_alert, "host.ip"),
        "host.mac": get_field(raw_alert, "host.mac"),
        "host.os.kernel": get_field(raw_alert, "host.os.kernel"),
        "host.os.name": get_field(raw_alert, "host.os.name"),
        "host.os.name.text": get_field(raw_alert, "host.os.name.text"),
        "host.os.platform": get_field(raw_alert, "host.os.platform"),

        # ===================== USER + IDENTITY =====================
        "user.id": get_field(raw_alert, "user.id"),
        "winlog.user.type": get_field(raw_alert, "winlog.user.type"),
        "winlog.user.name": get_field(raw_alert, "winlog.user.name"),

        # ===================== WINDOWS LOG SPECIFIC =====================
        "winlog.channel": get_field(raw_alert, "winlog.channel"),
        "winlog.task": get_field(raw_alert, "winlog.task"),
        "winlog.provider.thread.id": get_field(raw_alert, "winlog.process.thread.id"),

        # ===================== FILE ATTRIBUTES =====================
        "file.path": get_field(raw_alert, "file.path"),
        "file.name": get_field(raw_alert, "file.name"),
        "file.extension": get_field(raw_alert, "file.extension"),

        # ===================== ALERT / MESSAGE CONTEXT =====================
        "kibana.alert.reason.text": get_field(raw_alert, "kibana.alert.reason"),
                 
    }

    
    with open("./Intake_Alert/normalized_alert.json", "w") as f:
        json.dump(normalized_alert, f, indent=4)
    return normalized_alert
         
def alert_details_normalized():
    alert_details = {
        "rule_name": get_field(raw_alert, "kibana.alert.rule.name"),
        "rule_description": get_field(raw_alert, "kibana.alert.rule.description"),
        "severity": get_field(raw_alert, "kibana.alert.severity"),
        "risk_score": get_field(raw_alert, "kibana.alert.risk_score"),
        "reason": get_field(raw_alert, "kibana.alert.reason"),
        "rule_id": get_field(raw_alert, "kibana.alert.rule.rule_id"),
        "tags": get_field(raw_alert, "kibana.alert.rule.tags"),
        "query": get_field(raw_alert, "kibana.alert.rule.parameters.query"),
        "rule_references": get_field(raw_alert, "kibana.alert.rule.references"),
        "original_event_code": get_field(raw_alert, "kibana.alert.original_event.code"),
        "Detection_Rule": get_field(raw_alert, "kibana.alert.query")
    }
    with open("./Intake_Alert/alert_details.json", "w") as f:
        json.dump(alert_details, f, indent=4)
    return alert_details



alert_details_normalized()
normalize()
