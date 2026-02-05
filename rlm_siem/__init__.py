"""
RLM-SIEM: Recursive Language Model for SIEM Investigation

This module provides a complete pipeline for:
1. Alert ingestion and normalization
2. Log corpus management (external to LM context)
3. REPL-based investigation with recursive sub-LM calls
4. Evidence aggregation and report generation
"""

from rlm_siem.log_corpus import LogCorpus
from rlm_siem.helpers import filter_logs, summarize_logs, get_chunk, timeline
from rlm_siem.run_investigation import run_investigation

__all__ = [
    "LogCorpus",
    "filter_logs",
    "summarize_logs", 
    "get_chunk",
    "timeline",
    "run_investigation",
]
