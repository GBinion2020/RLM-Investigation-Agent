"""
RLM-SIEM Investigation Runner.

Main entry point for running RLM-based SIEM investigations.
This orchestrates the full pipeline from alert to report.
"""

import json
import os
import sys
from datetime import datetime
from string import Template

# Add project root to path if running directly
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from dotenv import load_dotenv

from rlm import RLM
from rlm.logger import RLMLogger

from rlm_siem.log_corpus import LogCorpus
from rlm_siem.helpers import (
    filter_logs,
    summarize_logs,
    get_chunk,
    timeline,
    list_chunk_summaries,
    corpus_stats,
    create_evidence,
    suggest_query,
    search_logs,
    regex_search_chunks,
)

from rlm_siem.prompts import (
    RLM_SIEM_SYSTEM_PROMPT,
    ROOT_INVESTIGATION_PROMPT,
    REPORT_TEMPLATE,
)


# Load environment
load_dotenv()


def _audit_log(output_dir: str, event: str, data: dict | None = None) -> None:
    """
    Append a JSONL audit record for transparency.
    """
    try:
        os.makedirs(output_dir, exist_ok=True)
        path = os.path.join(output_dir, "audit_log.jsonl")
        payload = {
            "event": event,
            "data": data or {},
            "timestamp": datetime.now().isoformat(),
        }
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, default=str) + "\n")
    except Exception:
        pass


def run_investigation(
    alert_path: str = "./Intake_Alert/normalized_alert.json",
    alert_details_path: str = "./Intake_Alert/alert_details.json",
    logs_path: str = "./get_siem_context/log_chunks.json",
    output_dir: str = "./get_siem_context",
    max_iterations: int = 6,
    max_depth: int = 2,
    verbose: bool = False,
    model_name: str = "gpt-5.2",
    fast_mode: bool = True,
) -> dict:
    """
    Run a full RLM-based SIEM investigation.
    
    Args:
        alert_path: Path to normalized_alert.json
        alert_details_path: Path to alert_details.json
        logs_path: Path to log corpus (JSON format)
        output_dir: Directory for output files
        max_iterations: Maximum RLM iterations
        max_depth: Maximum recursion depth (default: 2)
        verbose: Enable verbose output
        fast_mode: Use deterministic pipeline without root LLM loop
        
    Returns:
        Dict with investigation results
    """
    print("=" * 60)
    print("RLM-SIEM INVESTIGATION PIPELINE")
    print("=" * 60)
    
    # 1. Load Alert Metadata
    print("\n[1/5] Loading alert metadata...")
    if not os.path.exists(alert_path) or not os.path.exists(alert_details_path):
        print("  - Normalized alert files missing. Running normalization...")
        try:
            from Intake_Alert import Normalize  # noqa: F401
        except Exception as e:
            print(f"  - Normalization failed: {e}")
            return {"error": str(e)}
    try:
        with open(alert_path, "r") as f:
            alert_metadata = json.load(f)
        with open(alert_details_path, "r") as f:
            alert_details = json.load(f)
        _audit_log(
            output_dir,
            "alert_loaded",
            {"alert_path": alert_path, "details_path": alert_details_path},
        )
        print(f"  OK Alert: {alert_details.get('rule_name', 'Unknown')}")
        print(f"  OK Severity: {alert_details.get('severity', 'Unknown')}")
        print(f"  OK Host: {alert_metadata.get('host.name', 'Unknown')}")
        print(f"  OK Timestamp: {alert_metadata.get('Timestamp', 'Unknown')}")
    except FileNotFoundError as e:
        print(f"  ERROR Error loading alert: {e}")
        return {"error": str(e)}
    
    # 2. Initialize Log Corpus
    print("\n[2/5] Initializing log corpus...")
    try:
        corpus = LogCorpus(logs_path)
        corpus_info = corpus.stats()
        print(f"  OK Loaded {corpus_info['total_logs']:,} logs")
        print(f"  OK {corpus_info['total_chunks']} temporal chunks")
        if corpus_info.get('time_range', {}).get('start'):
            print(f"  OK Time range: {corpus_info['time_range']['start']} -> {corpus_info['time_range']['end']}")
        _audit_log(
            output_dir,
            "corpus_loaded",
            {
                "logs_path": logs_path,
                "total_logs": corpus_info.get("total_logs"),
                "total_chunks": corpus_info.get("total_chunks"),
                "time_range": corpus_info.get("time_range"),
            },
        )
    except Exception as e:
        print(f"  ERROR Error loading corpus: {e}")
        return {"error": str(e)}
    
    alert_timestamp = alert_metadata.get("Timestamp", "Unknown")

    # 3. Initialize Logger
    print("\n[3/5] Initializing RLM...")
    output_log_dir = os.path.join(output_dir, "rlm_logs")
    os.makedirs(output_log_dir, exist_ok=True)

    logger = RLMLogger(log_dir=output_log_dir)
    print(f"  - RLM logs will be saved to: {logger.log_file_path}")
    _audit_log(
        output_dir,
        "rlm_logger_ready",
        {"log_file_path": logger.log_file_path},
    )
    
    # 4. Build Setup Code for REPL
    # This code runs inside the REPL to load tools and data
    abs_logs_path = os.path.abspath(logs_path).replace("\\", "/")
    abs_output_dir = os.path.abspath(output_dir).replace("\\", "/")
    runtime_root = os.getcwd().replace("\\", "/")
    
    evidence_path = f"{abs_output_dir}/evidence.jsonl"
    queries_path = f"{abs_output_dir}/suggested_queries.jsonl"
    relevant_logs_path = f"{abs_output_dir}/relevant_logs.jsonl"
    
    # Initialize output files (clear previous run)
    for path in [evidence_path, queries_path, relevant_logs_path]:
        try:
            with open(path, "w") as f:
                pass
        except:
            pass

    alert_metadata_json = json.dumps(alert_metadata, ensure_ascii=True)
    alert_details_json = json.dumps(alert_details, ensure_ascii=True)

    def _escape_template(value: str) -> str:
        return value.replace("$", "$$")

    setup_code = Template(
        '''
import sys
import os
import json
import re
from datetime import datetime

# Ensure project root is in path
if "$PROJECT_ROOT" not in sys.path:
    sys.path.append("$PROJECT_ROOT")

# Configure output paths
os.environ["RLM_EVIDENCE_PATH"] = "$EVIDENCE_PATH"
os.environ["RLM_QUERIES_PATH"] = "$QUERIES_PATH"
os.environ["RLM_RELEVANT_LOGS_PATH"] = "$RELEVANT_LOGS_PATH"
os.environ["RLM_AUDIT_DIR"] = "$AUDIT_DIR"
os.environ.setdefault("RLM_MAX_CHUNKS_PER_KEYWORD", "12")
os.environ.setdefault("RLM_MAX_TOTAL_CHUNKS", "40")
os.environ.setdefault("RLM_MAX_TOTAL_LOGS", "120")
os.environ.setdefault("RLM_MAX_LOGS_PER_CHUNK", "40")
os.environ.setdefault("RLM_IOC_MAX_LOGS", "25")
os.environ.setdefault("RLM_IOC_MAX_CHARS", "60000")

def _audit_log(event, data=None):
    try:
        audit_dir = os.environ.get("RLM_AUDIT_DIR", ".")
        path = os.path.join(audit_dir, "audit_log.jsonl")
        payload = {
            "event": event,
            "data": data or {},
            "timestamp": datetime.now().isoformat(),
        }
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, default=str) + "\\n")
    except Exception:
        pass

from rlm_siem.log_corpus import LogCorpus
from rlm_siem.helpers import (
    filter_logs,
    summarize_logs,
    get_chunk,
    timeline,
    list_chunk_summaries,
    corpus_stats,
    create_evidence,
    suggest_query,
    search_logs,
    regex_search_chunks,
)
from rlm_siem.prompts import WORKER_CODE_PROMPT, IOC_EXTRACTION_PROMPT, REPORT_TEMPLATE

alert_metadata = json.loads($ALERT_METADATA_JSON)
alert_details = json.loads($ALERT_DETAILS_JSON)
alert_timestamp = "$ALERT_TIMESTAMP"

MAX_INITIAL_KEYWORDS = 5
MAX_PIVOT_KEYWORDS = 3
MAX_PIVOT_CYCLES = 1
pivot_cycles_used = 0
MAX_CHUNKS_PER_KEYWORD = int(os.getenv("RLM_MAX_CHUNKS_PER_KEYWORD", "12"))
MAX_TOTAL_CHUNKS = int(os.getenv("RLM_MAX_TOTAL_CHUNKS", "40"))
MAX_TOTAL_LOGS = int(os.getenv("RLM_MAX_TOTAL_LOGS", "120"))
MAX_LOGS_PER_CHUNK = int(os.getenv("RLM_MAX_LOGS_PER_CHUNK", "40"))


# Initialize corpus
print("[REPL] Initializing LogCorpus from $LOGS_PATH...")
try:
    corpus = LogCorpus("$LOGS_PATH")
    print(f"[REPL] Corpus loaded: {{corpus.total_logs}} logs")
    
    # Bind search_logs and regex_search_chunks to corpus
    _search_logs = search_logs
    search_logs = lambda keyword: _search_logs(corpus, keyword)
    
    _regex_search_chunks = regex_search_chunks
    regex_search_chunks = lambda pattern: _regex_search_chunks(corpus, pattern)

    _get_chunk = get_chunk
    get_chunk = lambda chunk_id: _get_chunk(corpus, chunk_id)
    
except Exception as e:
    print(f"[REPL] Error loading corpus: {{e}}")


def derive_keywords(min_keywords: int = MAX_INITIAL_KEYWORDS) -> list[str]:
    """
    Derive keyword pivots from alert metadata and details.
    Always returns exactly MAX_INITIAL_KEYWORDS or raises ValueError.
    """
    stopwords = {
        "the", "and", "or", "for", "with", "from", "this", "that", "rule", "alert",
        "event", "process", "user", "host", "name", "reason", "description", "query",
        "windows", "security", "log", "logs", "activity", "task", "created", "kibana"
    }

    priority_candidates: list[str] = []
    candidates: list[str] = []

    def add_value(value, target):
        if value is None:
            return
        text = str(value)
        # Extract IPs
        for ip in re.findall(r"\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b", text):
            target.append(ip)
        # Extract hashes (md5/sha1/sha256)
        for h in re.findall(r"\\b[a-fA-F0-9]{32,64}\\b", text):
            target.append(h.lower())
        # Tokenize general strings
        tokens = re.findall(r"[A-Za-z0-9_\\.\\-:/\\\\]{3,}", text)
        for tok in tokens:
            t = tok.lower()
            if t in stopwords:
                continue
            target.append(tok)

    def add_path_parts(value, target):
        if not value:
            return
        path = str(value)
        target.append(path)
        norm = path.replace("/", "\\\\")
        parts = [p for p in norm.split("\\\\") if p]
        if not parts:
            return
        basename = parts[-1]
        target.append(basename)
        if len(parts) >= 2:
            target.append("\\\\".join(parts[-2:]))
        if len(parts) >= 3:
            target.append("\\\\".join(parts[-3:]))
        parent = "\\\\".join(parts[:-1])
        if parent:
            target.append(parent)

    # Priority fields (file/command/message context first)
    add_path_parts(alert_metadata.get("file.path"), priority_candidates)
    add_value(alert_metadata.get("file.name"), priority_candidates)
    add_value(alert_metadata.get("file.extension"), priority_candidates)
    add_value(alert_metadata.get("process.command_line"), priority_candidates)
    add_value(alert_metadata.get("process.args"), priority_candidates)
    add_value(alert_metadata.get("message"), priority_candidates)
    add_value(alert_metadata.get("Process.command.message"), priority_candidates)

    # Secondary metadata values
    metadata_keys = [
        "process.pid",
        "winlog.process.pid",
        "event.code",
        "event.provider",
        "event.category",
        "user.id",
        "winlog.user.name",
        "winlog.channel",
        "winlog.task",
        "kibana.alert.reason.text",
    ]
    for key in metadata_keys:
        add_value(alert_metadata.get(key), candidates)

    # Pull values from alert details
    detail_keys = [
        "rule_name",
        "rule_description",
        "severity",
        "reason",
        "rule_id",
        "query",
        "original_event_code",
    ]
    for key in detail_keys:
        add_value(alert_details.get(key), candidates)

    # Exclude hostname to avoid noisy pivots
    host_name = alert_metadata.get("host.name")
    if host_name:
        priority_candidates = [
            c for c in priority_candidates if str(c).lower() != str(host_name).lower()
        ]
        candidates = [c for c in candidates if str(c).lower() != str(host_name).lower()]

    # Deduplicate preserving order (priority first)
    keywords: list[str] = []
    for c in priority_candidates + candidates:
        if c and c not in keywords:
            keywords.append(c)

    if len(keywords) < MAX_INITIAL_KEYWORDS:
        raise ValueError(
            f"Unable to derive {MAX_INITIAL_KEYWORDS} keywords from alert context. "
            f"Only derived {len(keywords)}."
        )

    # Enforce exactly MAX_INITIAL_KEYWORDS initial keywords
    return keywords[:MAX_INITIAL_KEYWORDS]


def discover_chunks(keywords: list[str], max_chunks_per_keyword: int = MAX_CHUNKS_PER_KEYWORD) -> dict:
    """
    Search chunk IDs by keyword using regex (case-insensitive), fallback to keyword search.
    Returns dict with per-keyword chunks and combined unique chunk list.
    """
    per_keyword: dict[str, list[str]] = {}
    all_chunks = set()

    for kw in keywords:
        pattern = re.escape(str(kw))
        chunk_ids = regex_search_chunks(pattern)
        if not chunk_ids:
            chunk_ids = search_logs(str(kw))
        if max_chunks_per_keyword > 0:
            chunk_ids = chunk_ids[:max_chunks_per_keyword]
        per_keyword[str(kw)] = chunk_ids
        for cid in chunk_ids:
            all_chunks.add(cid)

    all_chunk_ids = sorted(list(all_chunks))
    if MAX_TOTAL_CHUNKS > 0 and len(all_chunk_ids) > MAX_TOTAL_CHUNKS:
        all_chunk_ids = all_chunk_ids[:MAX_TOTAL_CHUNKS]
        allowed = set(all_chunk_ids)
        per_keyword = {
            kw: [cid for cid in cids if cid in allowed]
            for kw, cids in per_keyword.items()
        }

    return {
        "by_keyword": per_keyword,
        "all_chunk_ids": all_chunk_ids,
    }


def get_chunk_metadata(chunk_ids: list[str]) -> dict:
    """
    Return metadata for chunks without raw logs.
    """
    metadata = {}
    for cid in chunk_ids:
        chunk = get_chunk(cid)
        if not chunk:
            continue
        metadata[cid] = {
            "chunk_id": chunk.get("chunk_id"),
            "start_time": chunk.get("start_time"),
            "end_time": chunk.get("end_time"),
            "event_count": chunk.get("event_count"),
            "summary": chunk.get("summary"),
            "users": chunk.get("users"),
        }
    return metadata


def extract_code_block(text: str) -> str:
    matches = re.findall(r"```(?:python|repl)\\s*\\n(.*?)\\n```", text, re.DOTALL)
    if not matches:
        raise ValueError("Worker did not return a python code block.")
    return matches[0].strip()


def save_relevant_logs(logs: list[dict]) -> str:
    path = os.environ.get("RLM_RELEVANT_LOGS_PATH")
    if not path:
        raise ValueError("RLM_RELEVANT_LOGS_PATH is not set.")
    with open(path, "w", encoding="utf-8") as f:
        for item in logs:
            f.write(json.dumps(item, default=str) + "\\n")
    return path


def load_relevant_logs() -> list[dict]:
    path = os.environ.get("RLM_RELEVANT_LOGS_PATH")
    if not path:
        raise ValueError("RLM_RELEVANT_LOGS_PATH is not set.")
    logs: list[dict] = []
    if not os.path.exists(path):
        return logs
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            logs.append(json.loads(line))
    return logs


def run_worker_stage(
    task_description: str,
    keywords: list[str],
    chunk_ids: list[str],
    max_total_logs: int = MAX_TOTAL_LOGS,
    max_logs_per_chunk: int = MAX_LOGS_PER_CHUNK,
) -> dict:
    """
    Ask sub-LLM to write code that filters logs, then execute it in the REPL.
    Returns summary only (no raw logs).
    """
    chunk_metadata = get_chunk_metadata(chunk_ids)
    _audit_log(
        "worker_stage_start",
        {"chunk_count": len(chunk_ids), "keyword_count": len(keywords)},
    )

    prompt = WORKER_CODE_PROMPT.format(
        task_description=task_description,
        alert_metadata=json.dumps(alert_metadata, indent=2, default=str),
        alert_details=json.dumps(alert_details, indent=2, default=str),
        keywords=json.dumps(keywords),
        chunk_ids=json.dumps(chunk_ids),
        chunk_metadata=json.dumps(chunk_metadata, indent=2, default=str),
        max_total_logs=max_total_logs,
        max_logs_per_chunk=max_logs_per_chunk,
    )

    worker_response = llm_query(prompt)
    _audit_log(
        "worker_llm_response",
        {"response_len": len(worker_response)},
    )
    code = extract_code_block(worker_response)

    preamble_parts = [
        f"keywords = {json.dumps(keywords)}",
        f"target_chunk_ids = {json.dumps(chunk_ids)}",
        f"chunk_metadata = {json.dumps(chunk_metadata)}",
        f"max_total_logs = {max_total_logs}",
        f"max_logs_per_chunk = {max_logs_per_chunk}",
    ]
    preamble = "\\n".join(preamble_parts) + "\\n"

    import builtins as _builtins
    builtins_snapshot = _builtins.__dict__.copy()
    worker_failed = False
    filtered_logs = []
    log_references = []
    worker_summary = ""
    additional_keywords = []

    exec_globals = {
        "__builtins__": _builtins.__dict__.copy(),
        "__name__": "__worker_exec__",
        "get_chunk": get_chunk,
        "filter_logs": filter_logs,
        "summarize_logs": summarize_logs,
        "alert_metadata": alert_metadata,
        "alert_details": alert_details,
        "keywords": keywords,
        "target_chunk_ids": chunk_ids,
        "chunk_metadata": chunk_metadata,
        "max_total_logs": max_total_logs,
        "max_logs_per_chunk": max_logs_per_chunk,
        "json": json,
        "re": re,
    }

    try:
        _builtins.exec(preamble + code, exec_globals, exec_globals)
        if "filtered_logs" not in exec_globals:
            raise ValueError("Worker code did not define filtered_logs.")

        filtered_logs = exec_globals.get("filtered_logs", [])
        log_references = exec_globals.get("log_references", [])
        worker_summary = exec_globals.get("worker_summary", "")
        additional_keywords = exec_globals.get("additional_keywords", [])

        filtered_logs = _normalize_filtered_logs(filtered_logs)
    except Exception as exc:
        worker_failed = True
        worker_summary = f"Worker exec failed: {exc}. Using fallback filter."
        _audit_log(
            "worker_exec_error",
            {"error": str(exc)},
        )
    finally:
        _builtins.__dict__.clear()
        _builtins.__dict__.update(builtins_snapshot)

    if not isinstance(filtered_logs, list):
        raise ValueError("filtered_logs must be a list.")

    if worker_failed or len(filtered_logs) == 0:
        fallback = _fallback_filter_logs(chunk_ids, keywords, max_total_logs, max_logs_per_chunk)
        filtered_logs = fallback["filtered_logs"]
        log_references = fallback["log_references"]
        if fallback["worker_summary"]:
            if worker_summary:
                worker_summary = f"{worker_summary} {fallback['worker_summary']}"
            else:
                worker_summary = fallback["worker_summary"]
        _audit_log(
            "worker_fallback_used",
            {"filtered_log_count": len(filtered_logs)},
        )

    if isinstance(additional_keywords, list):
        additional_keywords = additional_keywords[:MAX_PIVOT_KEYWORDS]

    save_relevant_logs(filtered_logs)

    return {
        "filtered_log_count": len(filtered_logs),
        "log_references": log_references,
        "worker_summary": worker_summary,
        "additional_keywords": additional_keywords,
    }


def _normalize_filtered_logs(filtered_logs: list) -> list[dict]:
    normalized: list[dict] = []

    for entry in filtered_logs:
        if isinstance(entry, (list, tuple)) and len(entry) == 3:
            chunk_id, log_index, log = entry
            normalized.append(
                {"chunk_id": chunk_id, "log_index": log_index, "log": log}
            )
            continue

        if isinstance(entry, dict):
            if '"chunk_id"' in entry:
                entry["chunk_id"] = entry.pop('"chunk_id"')
            if '"log_index"' in entry:
                entry["log_index"] = entry.pop('"log_index"')
            if '"log"' in entry:
                entry["log"] = entry.pop('"log"')

            if "chunk_id" in entry and "log_index" in entry and "log" in entry:
                normalized.append(entry)
                continue

        # If we reach here, the entry is malformed
        raise ValueError(
            "filtered_logs entries must include keys: chunk_id, log_index, log"
        )

    return normalized


def _fallback_filter_logs(
    chunk_ids: list[str],
    keywords: list[str],
    max_total_logs: int,
    max_logs_per_chunk: int,
) -> dict:
    """
    Deterministic fallback: scan chunks for keyword matches and correlate within chunk.
    """
    keyword_lower = [str(k).lower() for k in keywords if k]
    filtered_logs: list[dict] = []
    log_references: list[str] = []

    for chunk_id in chunk_ids:
        chunk = get_chunk(chunk_id)
        if not chunk:
            continue

        logs = chunk.get("normalized_logs") or chunk.get("raw_logs") or []
        matched_indices = set()

        for idx, log in enumerate(logs):
            for val in log.values():
                if isinstance(val, str):
                    text = val.lower()
                    if any(k in text for k in keyword_lower):
                        matched_indices.add(idx)
                        break
                elif val is not None:
                    text = str(val).lower()
                    if any(k in text for k in keyword_lower):
                        matched_indices.add(idx)
                        break

        correlated_indices = set(matched_indices)
        if matched_indices:
            pivots = {
                "Process_Name": set(),
                "User": set(),
                "Command_Line": set(),
                "Event_Code": set(),
            }
            for idx in matched_indices:
                log = logs[idx]
                for key in pivots:
                    if log.get(key):
                        pivots[key].add(str(log.get(key)))

            for idx, log in enumerate(logs):
                if idx in correlated_indices:
                    continue
                if any(str(log.get(k, "")) in pivots[k] for k in pivots):
                    correlated_indices.add(idx)

        for idx in sorted(correlated_indices):
            if len(filtered_logs) >= max_total_logs:
                break
            entry = {"chunk_id": chunk_id, "log_index": idx, "log": logs[idx]}
            filtered_logs.append(entry)
            log_references.append(f"{chunk_id}:{idx}")

        if max_logs_per_chunk and len(filtered_logs) >= max_total_logs:
            break

    summary = (
        "Fallback filter used: keyword and correlation scan across matched chunks."
        if filtered_logs
        else "Fallback filter used but no logs matched keywords."
    )
    return {
        "filtered_logs": filtered_logs,
        "log_references": log_references,
        "worker_summary": summary,
    }


def _truncate_log_fields(entry: dict) -> dict:
    log = entry.get("log", {})
    truncated = {}
    for key, value in log.items():
        if isinstance(value, str):
            if key in {"Script_Block", "script_block", "ScriptBlock"} and len(value) > 500:
                value = value[:500] + "... [TRUNCATED]"
            elif key in {"Message", "message"} and len(value) > 1000:
                value = value[:1000] + "... [TRUNCATED]"
            elif len(value) > 500:
                value = value[:500] + "... [TRUNCATED]"
        truncated[key] = value
    return {
        "chunk_id": entry.get("chunk_id"),
        "log_index": entry.get("log_index"),
        "log": truncated,
    }


def run_ioc_stage(task_description: str, keywords: list[str], max_logs: int | None = None) -> dict:
    """
    Ask sub-LLM to extract IOCs from filtered logs with references.
    """
    global pivot_cycles_used
    logs = load_relevant_logs()
    _audit_log(
        "ioc_stage_start",
        {"log_count": len(logs), "keyword_count": len(keywords)},
    )

    if max_logs is None:
        max_logs = int(os.getenv("RLM_IOC_MAX_LOGS", "60"))

    max_chars = int(os.getenv("RLM_IOC_MAX_CHARS", "100000"))

    if max_logs > 0:
        logs = logs[:max_logs]

    logs = [_truncate_log_fields(entry) for entry in logs]

    while len(json.dumps(logs, default=str)) > max_chars and len(logs) > 1:
        logs = logs[: max(1, len(logs) // 2)]

    prompt_parts = [
        IOC_EXTRACTION_PROMPT.format(task_description=task_description),
        "ALERT_METADATA:",
        json.dumps(alert_metadata, indent=2, default=str),
        "ALERT_DETAILS:",
        json.dumps(alert_details, indent=2, default=str),
        "KEYWORDS:",
        json.dumps(keywords),
        "FILTERED_LOGS:",
        json.dumps(logs, indent=2, default=str),
    ]
    prompt = "\\n\\n".join(prompt_parts)

    response = llm_query(prompt)
    _audit_log(
        "ioc_llm_response",
        {"response_len": len(response)},
    )

    # Attempt to parse JSON
    try:
        start = response.find("{")
        end = response.rfind("}")
        if start == -1 or end == -1:
            raise ValueError("No JSON object found in response.")
        result = json.loads(response[start : end + 1])
        if "summary" not in result:
            result["summary"] = ""
        additional_keywords = result.get("additional_keywords", [])
        if isinstance(additional_keywords, list):
            if pivot_cycles_used >= MAX_PIVOT_CYCLES:
                result["additional_keywords"] = []
            else:
                additional_keywords = additional_keywords[:MAX_PIVOT_KEYWORDS]
                result["additional_keywords"] = additional_keywords
                if additional_keywords:
                    pivot_cycles_used += 1
        else:
            result["additional_keywords"] = []
        return result
    except Exception:
        return {
            "summary": "Failed to parse IOC JSON. See raw response.",
            "iocs": [],
            "additional_keywords": [],
            "raw_response": response,
        }


def format_report(
    ioc_results: dict,
    worker_summary: str,
    alert_name: str,
    severity: str,
    initial_keywords: list[str],
    pivot_keywords: list[str],
    chunk_ids: list[str],
) -> str:
    iocs = ioc_results.get("iocs", [])
    summary = ioc_results.get("summary", "")
    additional_keywords = ioc_results.get("additional_keywords", [])

    ioc_rows = []
    command_rows = []
    for ioc in iocs:
        ioc_rows.append(
            f"| {ioc.get('type','')} | {ioc.get('value','')} | {ioc.get('references', [])} | {ioc.get('reason','')} |"
        )
        if ioc.get("type") in {"command_line", "script_block"}:
            command_rows.append(
                f"| {ioc.get('type','')} | {ioc.get('value','')} | {ioc.get('references', [])} |"
            )

    ioc_table = (
        "| Type | Value | References | Reason |\\n|---|---|---|---|\\n"
        + ("\\n".join(ioc_rows) if ioc_rows else "| - | - | - | - |")
    )
    command_table = (
        "| Type | Value | References |\\n|---|---|---|\\n"
        + ("\\n".join(command_rows) if command_rows else "| - | - | - |")
    )

    return REPORT_TEMPLATE.format(
        alert_name=alert_name,
        alert_timestamp=alert_timestamp,
        severity=severity,
        initial_keywords=", ".join(initial_keywords),
        pivot_keywords=", ".join(pivot_keywords),
        chunk_ids=", ".join(chunk_ids),
        ioc_summary=summary,
        ioc_table=ioc_table,
        command_table=command_table,
        analyst_notes=worker_summary,
        next_pivots=", ".join(additional_keywords),
    )
'''
    ).substitute(
        PROJECT_ROOT=_escape_template(runtime_root),
        EVIDENCE_PATH=_escape_template(evidence_path),
        QUERIES_PATH=_escape_template(queries_path),
        RELEVANT_LOGS_PATH=_escape_template(relevant_logs_path),
        AUDIT_DIR=_escape_template(abs_output_dir),
        LOGS_PATH=_escape_template(abs_logs_path),
        ALERT_METADATA_JSON=_escape_template(repr(alert_metadata_json)),
        ALERT_DETAILS_JSON=_escape_template(repr(alert_details_json)),
        ALERT_TIMESTAMP=_escape_template(alert_timestamp),
    )


    # 5. Initialize RLM with SIEM-specific configuration
    print(f"\n[4/5] Initializing RLM (max_iterations={max_iterations})...")
    _audit_log(
        output_dir,
        "rlm_init",
        {
            "backend": "openai",
            "model_name": model_name,
            "max_iterations": max_iterations,
            "max_depth": max_depth,
        },
    )
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY is not set. Set it in your environment or .env file.")

    rlm = RLM(
        backend="openai",
        backend_kwargs={
            "model_name": model_name,
            "api_key": api_key,
        },
        environment="local",
        environment_kwargs={"setup_code": setup_code},
        custom_system_prompt=RLM_SIEM_SYSTEM_PROMPT,
        max_iterations=max_iterations,
        max_depth=max_depth,
        logger=logger,
        verbose=verbose,
    )
    
    # 6. Build Root Prompt
    alert_timestamp = alert_metadata.get("Timestamp", "Unknown")
    
    root_prompt = ROOT_INVESTIGATION_PROMPT.format(
        alert_name=alert_details.get('rule_name', 'Unknown'),
        alert_metadata=json.dumps(alert_metadata, indent=2, default=str),
        alert_details=json.dumps(alert_details, indent=2, default=str),
        alert_timestamp=alert_timestamp,
    )

    
    # 7. Execute Investigation
    print("\n[5/5] Starting RLM investigation loop (Hunter Protocol)...")
    print("-" * 60)
    _audit_log(
        output_dir,
        "investigation_start",
        {"root_prompt_len": len(root_prompt), "fast_mode": fast_mode},
    )

    try:
        if fast_mode:
            result_response = run_fast_pipeline(rlm, alert_details, alert_metadata)
            result_iterations = None
        else:
            # Pass a simple start message as the prompt
            result = rlm.completion("Begin recursive hunting.", root_prompt=root_prompt)
            result_response = result.response
            result_iterations = getattr(result, "iterations", None)

        _audit_log(
            output_dir,
            "investigation_complete",
            {"response_len": len(result_response)},
        )

        print("-" * 60)
        print("\n" + "=" * 60)
        print("INVESTIGATION COMPLETE")
        print("=" * 60)

        # 8. Save Evidence Package
        report_path = os.path.join(output_dir, "evidence_discovery_package.md")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("# RLM Evidence Discovery Package\n\n")
            f.write(f"**Alert**: {alert_details.get('rule_name', 'Unknown')}\n")
            f.write(f"**Collection Date**: {datetime.now().isoformat()}\n\n")
            f.write("---\n\n")
            f.write(result_response)
        print(f"\nOK Evidence package saved to: {report_path}")
        if os.path.exists(relevant_logs_path):
            print(f"  - Relevant logs saved to: {relevant_logs_path}")

        # Return structured result
        return {
            "success": True,
            "report_path": report_path,
            "log_path": logger.log_file_path,
            "response": result_response,
            "iterations": result_iterations,
        }

    except Exception as e:
        print(f"\nERROR Investigation failed: {e}")
        _audit_log(output_dir, "investigation_error", {"error": str(e)})
        return {"success": False, "error": str(e)}


def run_fast_pipeline(rlm: RLM, alert_details: dict, alert_metadata: dict) -> str:
    task_description = (
        f"Evidence harvesting for alert: {alert_details.get('rule_name', 'Unknown')}"
    )
    fast_code = f"""
task_description = {task_description!r}

def _coerce_chunk_ids(chunk_map):
    if isinstance(chunk_map, dict):
        ids = chunk_map.get("all_chunk_ids", [])
        if isinstance(ids, list):
            return [str(cid) for cid in ids]
    return []

keywords = derive_keywords(min_keywords=5)
chunk_map = discover_chunks(keywords)
chunk_ids = _coerce_chunk_ids(chunk_map)

worker_result = run_worker_stage(task_description, keywords, chunk_ids)
ioc_result = run_ioc_stage(task_description, keywords)

pivot_keywords = ioc_result.get("additional_keywords", [])
pivot_chunk_ids = []
pivot_worker_summary = ""

if pivot_keywords:
    pivot_chunk_map = discover_chunks(pivot_keywords)
    pivot_chunk_ids = _coerce_chunk_ids(pivot_chunk_map)
    pivot_worker = run_worker_stage(task_description, pivot_keywords, pivot_chunk_ids)
    pivot_worker_summary = pivot_worker.get("worker_summary", "")
    pivot_ioc = run_ioc_stage(task_description, pivot_keywords)
    combined_iocs = []
    if isinstance(ioc_result.get("iocs"), list):
        combined_iocs.extend(ioc_result.get("iocs"))
    if isinstance(pivot_ioc.get("iocs"), list):
        combined_iocs.extend(pivot_ioc.get("iocs"))
    combined_summary = "Initial IOC summary:\\n" + str(ioc_result.get("summary", ""))
    combined_summary += "\\nPivot IOC summary:\\n" + str(pivot_ioc.get("summary", ""))
    ioc_result = {{
        "summary": combined_summary,
        "iocs": combined_iocs,
        "additional_keywords": [],
    }}

worker_summary = worker_result.get("worker_summary", "")
if pivot_worker_summary:
    worker_summary = worker_summary + "\\nPivot worker summary:\\n" + pivot_worker_summary

final_chunk_ids = chunk_ids + [cid for cid in pivot_chunk_ids if cid not in chunk_ids]

final_report = format_report(
    ioc_result,
    worker_summary,
    alert_details.get("rule_name", "Unknown"),
    alert_details.get("severity", "Unknown"),
    keywords,
    pivot_keywords,
    final_chunk_ids,
)
"""

    with rlm._spawn_completion_context("fast_pipeline") as (_, environment):
        result = environment.execute_code(fast_code)
        if result.stderr:
            _audit_log(
                os.getenv("RLM_AUDIT_DIR", "."),
                "fast_pipeline_error",
                {"stderr": result.stderr.strip()[:2000]},
            )

        final_report = result.locals.get("final_report")
        if final_report:
            return final_report

        keywords = result.locals.get("keywords", [])
        pivot_keywords = result.locals.get("pivot_keywords", [])
        chunk_ids = result.locals.get("final_chunk_ids", result.locals.get("chunk_ids", []))
        error_summary = result.stderr.strip() if result.stderr else "Fast pipeline did not produce a report."

        ioc_table = "| Type | Value | References | Reason |\\n|---|---|---|---|\\n| - | - | - | - |"
        command_table = "| Type | Value | References |\\n|---|---|---|\\n| - | - | - |"

        return REPORT_TEMPLATE.format(
            alert_name=alert_details.get("rule_name", "Unknown"),
            alert_timestamp=alert_metadata.get("Timestamp", "Unknown"),
            severity=alert_details.get("severity", "Unknown"),
            initial_keywords=", ".join([str(k) for k in keywords]) if keywords else "N/A",
            pivot_keywords=", ".join([str(k) for k in pivot_keywords]) if pivot_keywords else "N/A",
            chunk_ids=", ".join([str(c) for c in chunk_ids]) if chunk_ids else "N/A",
            ioc_summary=error_summary,
            ioc_table=ioc_table,
            command_table=command_table,
            analyst_notes="Fast pipeline failed before producing evidence. See audit_log.jsonl for details.",
            next_pivots="N/A",
        )

def main():
    """CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="RLM-SIEM Investigation Pipeline")
    parser.add_argument("--alert", default="./Intake_Alert/normalized_alert.json",
                       help="Path to normalized alert JSON")
    parser.add_argument("--details", default="./Intake_Alert/alert_details.json",
                       help="Path to alert details JSON")
    parser.add_argument("--logs", default="./get_siem_context/log_chunks.json",
                       help="Path to log corpus JSON")
    parser.add_argument("--output", default="./get_siem_context",
                       help="Output directory for reports")
    parser.add_argument("--model", default=os.getenv("RLM_MODEL", "gpt-5.2"),
                       help="OpenAI model name (default: gpt-5.2)")
    parser.add_argument("--max-iterations", type=int, default=6,
                       help="Maximum RLM iterations")
    parser.add_argument("--max-depth", type=int, default=2,
                       help="Maximum recursion depth")
    parser.add_argument("--no-fast", action="store_true",
                       help="Disable fast deterministic pipeline and use root RLM loop")
    parser.add_argument("--verbose", action="store_true",
                       help="Enable verbose terminal output (Rich)")
    parser.add_argument("--quiet", action="store_true",
                       help="Disable verbose output (overrides --verbose)")
    
    args = parser.parse_args()
    
    verbose = False
    if args.verbose and not args.quiet:
        verbose = True

    result = run_investigation(
        alert_path=args.alert,
        alert_details_path=args.details,
        logs_path=args.logs,
        output_dir=args.output,
        max_iterations=args.max_iterations,
        max_depth=args.max_depth,
        verbose=verbose,
        model_name=args.model,
        fast_mode=not args.no_fast,
    )
    
    if result.get("success"):
        print("\nOK Investigation completed successfully!")
    else:
        print(f"\nERROR Investigation failed: {result.get('error', 'Unknown error')}")
        exit(1)


if __name__ == "__main__":
    main()
