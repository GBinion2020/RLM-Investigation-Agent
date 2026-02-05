import json
import os
import re
from datetime import datetime, timedelta
from typing import Iterator, Any
from rlm_siem.normalization import LogNormalizer


class LogCorpus:
    """
    Log corpus manager for RLM-SIEM investigations.
    
    Logs are stored externally and accessed via code execution in the REPL.
    This follows the RLM paper principle: "Logs never enter the LM context directly."
    
    Usage in REPL:
        corpus = LogCorpus("./logs/baseline.json")
        relevant = corpus.query(user="gabri", event_code="4104")
        for chunk in corpus.iterator(batch_size=100):
            # Process chunk
    """
    
    def __init__(self, source: str, indexed_fields: list[str] | None = None):
        """
        Initialize LogCorpus from a JSON file.
        
        Args:
            source: Path to JSON file containing log records
            indexed_fields: Fields to index for fast filtering
        """
        self.source = source
        self.indexed_fields = indexed_fields or [
            "Timestamp", "Host", "User", "Event_Code", "Process_Name"
        ]
        
        self._logs: list[dict] = []
        self._chunks: list[dict] = []
        self._load()
        
    def _load(self):
        """Load logs from source file."""
        if not os.path.exists(self.source):
            raise FileNotFoundError(f"Log source not found: {self.source}")
            
        with open(self.source, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        # Handle both flat log list and chunked format
        if isinstance(data, list):
            if len(data) > 0 and "raw_logs" in data[0]:
                # Chunked format (from chunk_logs.py) with normalization support
                self._chunks = data
                self._logs = []
                for chunk in data:
                    # Normalize logs in chunk if not already normalized or if we want to ensure schema
                    raw_logs = chunk.get("normalized_logs") or chunk.get("raw_logs", [])
                    normalized_logs = [LogNormalizer.normalize(log) for log in raw_logs]
                    chunk["normalized_logs"] = normalized_logs
                    self._logs.extend(normalized_logs)
            else:
                # Flat log list
                self._logs = [LogNormalizer.normalize(log) for log in data]
                self._chunks = []
        else:
            raise ValueError("Expected JSON array of logs or chunks")
            
        # LOAD INVERTED INDEX if available
        index_path = self.source.replace("log_chunks.json", "inverted_index.json")
        self.inverted_index = {}
        if os.path.exists(index_path):
            with open(index_path, "r", encoding="utf-8") as f:
                self.inverted_index = json.load(f)
            print(f"[LogCorpus] Loaded Inverted Index from {index_path} ({len(self.inverted_index)} keywords)")
        else:
             print(f"[LogCorpus] Warning: Inverted Index not found. Building in-memory index...")
             self._build_index()
            
        print(f"[LogCorpus] Loaded {len(self._logs)} logs from {self.source}")
        if self._chunks:
            print(f"[LogCorpus] Found {len(self._chunks)} pre-computed chunks")

    def _build_index(self):
        """Build an inverted index from memory-loaded logs and chunks."""
        from collections import defaultdict
        import re
        
        self.inverted_index = defaultdict(set)
        
        # Index chunks
        if self._chunks:
            for chunk in self._chunks:
                cid = chunk.get("chunk_id")
                if not cid: continue
                
                # Index metadata
                text_to_index = f"{chunk.get('summary', '')} {chunk.get('host', '')} {' '.join(chunk.get('users', []))}"
                words = re.findall(r'\w+', text_to_index.lower())
                for word in words:
                    self.inverted_index[word].add(cid)
                
                # Index logs inside chunk
                logs = chunk.get("normalized_logs") or chunk.get("raw_logs", [])
                for log in logs:
                    for val in log.values():
                        if isinstance(val, str):
                            words = re.findall(r'\w+', val.lower())
                            for word in words:
                                self.inverted_index[word].add(cid)
                        elif val is not None:
                            self.inverted_index[str(val).lower()].add(cid)
        
        # Convert sets to lists
        self.inverted_index = {k: list(v) for k, v in self.inverted_index.items()}
        print(f"[LogCorpus] In-memory index built: {len(self.inverted_index)} keywords")

    def search_keywords(self, query: str) -> list[str]:
        """
        Search for a keyword in the inverted index.
        Returns a list of Chunk IDs that contain the keyword.
        """
        query = str(query).lower().strip()
        
        # 1. Exact match in index
        chunk_ids = set(self.inverted_index.get(query, []))
        
        # 2. Substring match fallback (if query is long enough)
        if not chunk_ids and len(query) > 2:
            for kw, ids in self.inverted_index.items():
                if query in kw:
                    chunk_ids.update(ids)
        
        print(f"[LogCorpus] Keyword '{query}' found in {len(chunk_ids)} chunks.")
        return sorted(list(chunk_ids))

    def regex_search_chunks(self, pattern: str) -> list[str]:
        """
        Search for a regex pattern across all logs in chunks.
        Returns a list of Chunk IDs that have a match.
        """
        import re
        regex = re.compile(pattern, re.IGNORECASE)
        matching_chunks = set()
        
        for chunk in self._chunks:
            cid = chunk.get("chunk_id")
            if not cid: continue
            
            # Search in normalized logs
            logs = chunk.get("normalized_logs") or []
            for log in logs:
                found = False
                for val in log.values():
                    if val and regex.search(str(val)):
                        matching_chunks.add(cid)
                        found = True
                        break
                if found: break
                
        print(f"[LogCorpus] Regex '{pattern}' found in {len(matching_chunks)} chunks.")
        return sorted(list(matching_chunks))

    
    @property
    def total_logs(self) -> int:
        """Total number of logs in corpus."""
        return len(self._logs)
    
    @property
    def total_chunks(self) -> int:
        """Total number of pre-computed chunks."""
        return len(self._chunks)
    
    def query(self, **filters) -> list[dict]:
        """
        Filter logs by field values.
        
        Args:
            **filters: Field=value pairs to filter by
            
        Returns:
            List of matching log records
            
        Example:
            corpus.query(User="gabri", Event_Code="4104")
        """
        results = []
        for log in self._logs:
            match = True
            for field, value in filters.items():
                # Case-insensitive key lookup
                log_value = None
                if field in log:
                    log_value = log[field]
                else:
                    # Try to find matching key case-insensitively
                    for k in log.keys():
                        if k.lower() == field.lower():
                            log_value = log[k]
                            break
                
                if log_value is None:
                    match = False
                    break

                # String contains check for flexibility
                if isinstance(value, str) and isinstance(log_value, str):
                    if value.lower() not in log_value.lower():
                        match = False
                        break
                elif log_value != value:
                    match = False
                    break
            if match:
                results.append(log)
        print(f"[LogCorpus] Query returned {len(results)} logs matching {filters}")
        return results
    
    def slice(self, start_time: str, end_time: str) -> list[dict]:
        """
        Get logs within a time window.
        
        Args:
            start_time: ISO format start time
            end_time: ISO format end time
            
        Returns:
            List of logs within the time window
        """
        results = []
        for log in self._logs:
            ts = log.get("Timestamp")
            if ts and start_time <= ts <= end_time:
                results.append(log)
            if ts and start_time <= ts <= end_time:
                results.append(log)
        print(f"[LogCorpus] Slice returned {len(results)} logs between {start_time} and {end_time}")
        return results
    
    def group_by(self, field: str) -> dict[str, list[dict]]:
        """
        Group logs by a field value.
        
        Args:
            field: Field name to group by
            
        Returns:
            Dict mapping field values to lists of logs
        """
        groups: dict[str, list[dict]] = {}
        for log in self._logs:
            key = str(log.get(field, "Unknown"))
            if key not in groups:
                groups[key] = []
            groups[key].append(log)
        return groups
    
    def iterator(self, batch_size: int = 100) -> Iterator[list[dict]]:
        """
        Iterate over logs in batches.
        
        Args:
            batch_size: Number of logs per batch
            
        Yields:
            Batches of log records
        """
        for i in range(0, len(self._logs), batch_size):
            yield self._logs[i:i + batch_size]
    
    def get_chunk(self, chunk_id: str) -> dict | None:
        """
        Get a specific pre-computed chunk by ID.
        
        Args:
            chunk_id: The chunk identifier (e.g., "20260129_0630")
            
        Returns:
            Chunk dict with summary, metadata, and raw_logs
        """
        for chunk in self._chunks:
            if chunk.get("chunk_id") == chunk_id:
                return chunk
        return None
    
    def get_chunks_by_time(self, start_time: str, end_time: str) -> list[dict]:
        """
        Get all chunks overlapping a time window.
        
        Args:
            start_time: ISO format start time
            end_time: ISO format end time
            
        Returns:
            List of chunk dicts
        """
        results = []
        for chunk in self._chunks:
            chunk_start = chunk.get("start_time", "")
            chunk_end = chunk.get("end_time", "")
            # Check for overlap
            if chunk_start <= end_time and chunk_end >= start_time:
                results.append(chunk)
        return results
    
    def get_chunk_summaries(self) -> list[dict]:
        """
        Get summaries of all chunks (without raw_logs).
        
        Returns:
            List of chunk metadata dicts (no raw_logs, saves memory)
        """
        summaries = []
        for chunk in self._chunks:
            summary = {
                "chunk_id": chunk.get("chunk_id"),
                "start_time": chunk.get("start_time"),
                "end_time": chunk.get("end_time"),
                "host": chunk.get("host"),
                "event_count": chunk.get("event_count"),
                "users": chunk.get("users"),
                "summary": chunk.get("summary"),
                "risk_flags": chunk.get("risk_flags"),
            }
            summaries.append(summary)
        return summaries
    
    def timeline(self, entity_field: str, entity_value: str, hours: int = 1) -> list[dict]:
        """
        Build a timeline of events for a specific entity.
        
        Args:
            entity_field: Field to match (e.g., "User", "Host", "Process_Name")
            entity_value: Value to match
            hours: Time window in hours
            
        Returns:
            List of logs sorted chronologically
        """
        matches = self.query(**{entity_field: entity_value})
        # Sort by timestamp
        # Sort by timestamp
        sorted_logs = sorted(matches, key=lambda x: x.get("Timestamp", ""))
        print(f"[LogCorpus] Timeline found {len(sorted_logs)} events for {entity_field}={entity_value}")
        return sorted_logs
    
    def stats(self) -> dict:
        """
        Get corpus statistics.
        
        Returns:
            Dict with corpus statistics
        """
        if not self._logs:
            return {"total_logs": 0}
            
        timestamps = [l.get("Timestamp") for l in self._logs if l.get("Timestamp")]
        users = set(l.get("User") for l in self._logs if l.get("User"))
        event_codes = set(l.get("Event_Code") for l in self._logs if l.get("Event_Code"))
        
        return {
            "total_logs": len(self._logs),
            "total_chunks": len(self._chunks),
            "time_range": {
                "start": min(timestamps) if timestamps else None,
                "end": max(timestamps) if timestamps else None,
            },
            "unique_users": list(users),
            "unique_event_codes": list(event_codes),
        }
