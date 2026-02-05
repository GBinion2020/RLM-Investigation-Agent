"""
REPL Helper Functions for RLM-SIEM Investigation.

These functions are injected into the REPL environment and called by the LLM
during investigation. They operate on the LogCorpus stored in the REPL namespace.
"""

import json
from datetime import datetime
from typing import Any


def filter_logs(corpus, **conditions) -> list[dict]:
    """
    Filter logs from the corpus by field conditions.
    
    This is a convenience wrapper around corpus.query() that also formats
    the output for LLM consumption.
    
    Args:
        corpus: The LogCorpus instance
        **conditions: Field=value pairs to filter by
        
    Returns:
        List of matching log records
        
    Example:
        filtered = filter_logs(corpus, User="gabri", Event_Code="4104")
    """
    results = corpus.query(**conditions)
    print(f"[filter_logs] Found {len(results)} logs matching {conditions}")
    return results


def search_logs(corpus, keyword: str) -> list[str]:
    """
    Search for a keyword in the inverted index.
    
    Args:
        corpus: The LogCorpus instance
        keyword: The search term (e.g. "4104", "gabri")
        
    Returns:
        List of Chunk IDs containing the keyword
    """
    chunk_ids = corpus.search_keywords(keyword)
    print(f"[search_logs] Found {len(chunk_ids)} chunks containing '{keyword}'")
    return chunk_ids


def regex_search_chunks(corpus, pattern: str) -> list[str]:
    """
    Search for a regex pattern in the corpus.
    
    Args:
        corpus: The LogCorpus instance
        pattern: Regex pattern
        
    Returns:
        List of Chunk IDs matching the pattern
    """
    chunk_ids = corpus.regex_search_chunks(pattern)
    print(f"[regex_search_chunks] Found {len(chunk_ids)} chunks matching '{pattern}'")
    return chunk_ids



def summarize_logs(logs: list[dict], max_display: int = 10) -> str:
    """
    Generate a human-readable summary of a log subset.
    
    This creates a narrative summary suitable for LLM consumption without
    passing raw logs into the context.
    
    Args:
        logs: List of log records to summarize
        max_display: Max number of sample logs to include
        
    Returns:
        Narrative summary string
    """
    if isinstance(logs, str):
        print(f"Error: summarize_logs expects a list of logs, but received a string: {logs[:50]}...")
        return f"Error: summarize_logs expects a list of logs, but received a string. Did you mean to pass a variable containing logs?"
    
    if not logs:
        print("No logs to summarize.")
        return "No logs to summarize."
    
    # Extract key fields
    timestamps = [l.get("Timestamp") for l in logs if l.get("Timestamp")]
    users = set(l.get("User") for l in logs if l.get("User"))
    event_codes = set(str(l.get("Event_Code")) for l in logs if l.get("Event_Code"))
    processes = set(l.get("Process_Name") for l in logs if l.get("Process_Name"))
    
    # Build summary
    parts = [
        f"**Log Summary ({len(logs)} events)**",
        "",
    ]
    
    if timestamps:
        parts.append(f"- Time Range: {min(timestamps)} → {max(timestamps)}")
    
    if users:
        parts.append(f"- Users: {', '.join(users)}")
    
    if event_codes:
        parts.append(f"- Event Codes: {', '.join(event_codes)}")
    
    if processes:
        process_list = list(processes)[:5]
        parts.append(f"- Processes: {', '.join(process_list)}")
    
    # Sample logs
    if logs and max_display > 0:
        parts.append("")
        parts.append(f"**Sample Events (showing {min(len(logs), max_display)}):**")
        for log in logs[:max_display]:
            ts = log.get("Timestamp", "?")
            user = log.get("User", "?")
            event = log.get("Event_Code", "?")
            proc = log.get("Process_Name", "?")
            parts.append(f"  [{ts}] User={user} Event={event} Process={proc}")
    
    result = "\n".join(parts)
    print(result)
    return result


def get_chunk(corpus, chunk_id: str) -> dict | None:
    """
    Retrieve a specific temporal chunk by ID.
    
    Args:
        corpus: The LogCorpus instance
        chunk_id: The chunk identifier (e.g., "20260129_0630")
        
    Returns:
        Chunk dict with summary, metadata, and raw_logs
    """
    chunk = corpus.get_chunk(chunk_id)
    if chunk:
        print(f"[get_chunk] Retrieved chunk {chunk_id} with {chunk.get('event_count', 0)} events")
    else:
        print(f"[get_chunk] Chunk {chunk_id} not found")
    return chunk


def timeline(corpus, entity_field: str, entity_value: str, hours: int = 24) -> str:
    """
    Build a chronological timeline for an entity.
    
    Args:
        corpus: The LogCorpus instance
        entity_field: Field to match (e.g., "User", "Host", "Process_Name")
        entity_value: Value to match
        hours: Time window (for display purposes)
        
    Returns:
        Formatted timeline string
    """
    events = corpus.timeline(entity_field, entity_value, hours)
    
    if not events:
        return f"No events found for {entity_field}={entity_value}"
    
    parts = [
        f"**Timeline for {entity_field}={entity_value}** ({len(events)} events)",
        "",
    ]
    
    for event in events[:50]:  # Limit display
        ts = event.get("Timestamp", "?")
        action = event.get("Action") or event.get("Task") or event.get("Event_Code", "?")
        process = event.get("Process_Name", "")
        cmd = event.get("Command_Line", "")[:80] if event.get("Command_Line") else ""
        
        line = f"[{ts}] {action}"
        if process:
            line += f" | {process}"
        if cmd:
            line += f" | {cmd}..."
        parts.append(line)
    
    if len(events) > 50:
        parts.append(f"... and {len(events) - 50} more events")
    
    result = "\n".join(parts)
    print(result)
    return result


def list_chunk_summaries(corpus) -> str:
    """
    List all chunk summaries for quick orientation.
    
    Args:
        corpus: The LogCorpus instance
        
    Returns:
        Formatted chunk summary list
    """
    summaries = corpus.get_chunk_summaries()
    
    if not summaries:
        return "No pre-computed chunks available."
    
    parts = [
        f"**Available Chunks ({len(summaries)} total)**",
        "",
    ]
    
    for chunk in summaries:
        chunk_id = chunk.get("chunk_id", "?")
        event_count = chunk.get("event_count", 0)
        users = chunk.get("users", [])
        risk_flags = chunk.get("risk_flags", {})
        
        # Highlight risky chunks
        flags = []
        if risk_flags.get("powershell_activity"):
            flags.append("🔴 PowerShell")
        if risk_flags.get("encoded_commands"):
            flags.append("🔴 Encoded")
        if risk_flags.get("network_connections"):
            flags.append("🟡 Network")
        
        flag_str = " | ".join(flags) if flags else "✅ Normal"
        user_str = ", ".join(users[:3]) if users else "?"
        
        parts.append(f"- **{chunk_id}**: {event_count} events | Users: {user_str} | {flag_str}")
    
    result = "\n".join(parts)
    print(result)
    return result


def corpus_stats(corpus) -> str:
    """
    Get high-level corpus statistics.
    
    Args:
        corpus: The LogCorpus instance
        
    Returns:
        Formatted statistics string
    """
    stats = corpus.stats()
    
    parts = [
        "**Corpus Statistics**",
        "",
        f"- Total Logs: {stats.get('total_logs', 0):,}",
        f"- Total Chunks: {stats.get('total_chunks', 0)}",
    ]
    
    time_range = stats.get("time_range", {})
    if time_range.get("start"):
        parts.append(f"- Time Range: {time_range['start']} → {time_range['end']}")
    
    users = stats.get("unique_users", [])
    if users:
        parts.append(f"- Unique Users: {len(users)} ({', '.join(users[:5])}...)")
    
    event_codes = stats.get("unique_event_codes", [])
    if event_codes:
        parts.append(f"- Event Codes: {len(event_codes)} unique")
    
    result = "\n".join(parts)
    print(result)
    return result


# Evidence model for structured output
def create_evidence(
    entity: str,
    time_window: str,
    signals: list[str],
    supporting_logs: list[str],
    confidence: float
) -> dict:
    """
    Create a structured evidence object and persist it.
    
    Args:
        entity: The entity this evidence pertains to
        time_window: Time window of the evidence
        signals: List of observed suspicious signals
        supporting_logs: List of log IDs or timestamps
        confidence: Confidence score (0.0 - 1.0)
        
    Returns:
        Structured evidence dict
    """
    evidence = {
        "entity": entity,
        "time_window": time_window,
        "signals": signals,
        "supporting_logs": supporting_logs,
        "confidence": confidence,
        "timestamp": datetime.now().isoformat()
    }
    
    # Persist if configured
    import os
    
    path = os.environ.get("RLM_EVIDENCE_PATH")
    if path:
        try:
            # Append as JSONL
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(evidence) + "\n")
            print(f"[create_evidence] Saved to {path}")
        except Exception as e:
            print(f"[create_evidence] Failed to save: {e}")
            
    return evidence


def suggest_query(
    description: str,
    target_index: str = "logs-*",
    filters: dict | None = None
) -> dict:
    """
    Create a suggested SIEM query and persist it.
    
    Args:
        description: Human-readable description
        target_index: SIEM index to query
        filters: Key filter conditions
        
    Returns:
        Structured query suggestion
    """
    query = {
        "description": description,
        "target_index": target_index,
        "filters": filters or {},
        "timestamp": datetime.now().isoformat()
    }
    
    # Persist if configured
    import os
    
    path = os.environ.get("RLM_QUERIES_PATH")
    if path:
        try:
            # Append as JSONL
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(query) + "\n")
            print(f"[suggest_query] Saved to {path}")
        except Exception as e:
            print(f"[suggest_query] Failed to save: {e}")
            
    return query
