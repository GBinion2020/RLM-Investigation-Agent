# RLM-SIEM Engineering Report (Research Grade)

## Abstract
This report documents the end-to-end design and implementation of the RLM Investigation Agent, a security-evidence harvesting pipeline built on Recursive Language Models (RLMs). The system demonstrates how RLMs can provide an effectively unbounded context window by delegating context-heavy reasoning to recursive sub-LLM calls inside a REPL environment, rather than stuffing all logs into a single prompt. The implementation targets SIEM workflows and focuses on evidence harvesting with strict auditability, avoiding any benign/malicious classification. The design is inspired by the RLM framework described by Zhang et al. and applied here to operational security telemetry. citeturn0search0

## Background: Recursive Language Models
RLMs are an inference strategy in which a root model interacts with an external environment (typically a REPL) that stores large context variables and can recursively call sub-LLMs for focused sub-tasks. This allows the root model to avoid direct exposure to large context windows and mitigates "context rot" by partitioning the problem at inference time. The reference implementation described by Zhang et al. uses a REPL environment where the root LM can execute code, inspect context variables, and invoke recursive sub-LLM calls on subsets of the context. This project follows the same blueprint and adapts it to SIEM evidence collection. citeturn0search0

## System Goals
- Provide an evidence-harvesting pipeline that is auditable and deterministic.
- Keep raw logs out of the root model prompt while still allowing targeted analysis.
- Use recursive sub-LLM calls to scale to large telemetry volumes.
- Emit a consistent report template with IOC references and relevant logs.

## System Overview
The system is composed of five layers:
1. **Alert ingestion and normalization** (Elastic alert -> normalized schema).
2. **SIEM log ingestion** (Elastic logs -> chunked corpus + inverted index).
3. **REPL environment** (helper functions + LogCorpus + sub-LLM calls).
4. **RLM orchestration** (root LM + sub-LLM worker/IOC stages).
5. **Evidence outputs** (report + relevant logs + audit trail).

## Data Sources and Artifacts
**Alert Intake**
- `Intake_Alert/Intake_Elastic_logs.py: Elastic.Alert()` pulls the latest Elastic alert.
- `Intake_Alert/Normalize.py: normalize()` produces `normalized_alert.json`.
- `Intake_Alert/Normalize.py: alert_details_normalized()` produces `alert_details.json`.

**SIEM Logs**
- `get_siem_context/query_0.py: query_0()` and `get_siem_context/query_json.py: query_json()` fetch logs from Elastic and normalize them.
- Outputs include `baseline_context.csv` and/or `log_chunks.json`.

**Corpus**
- `rlm_siem/log_corpus.py: LogCorpus()` loads `log_chunks.json`.
- Builds an inverted index for keyword and regex search.

## Normalization Layer
### Alert Normalization
Alert fields are normalized into a consistent schema including:
- `Timestamp`, `event.code`, `event.provider`, `host.name`, `user.id`.
- File and command context: `file.path`, `file.name`, `message`.

The explicit inclusion of `message` ensures command and script block content are available for keyword derivation and investigation context.

### Log Normalization
`rlm_siem/normalization.py: LogNormalizer.normalize()` standardizes log records into a stable schema:
- `Timestamp`, `User`, `Host`, `Event_Code`, `Process_Name`, `Command_Line`, `File_Path`, `Script_Block`, `Message`.
- Truncates long fields to control prompt size.

`LogNormalizer.get_keywords()` extracts tokens from command/message fields to populate the inverted index for retrieval.

## REPL Environment Architecture
The RLM runs inside a **Local REPL environment** (`rlm/environments/local_repl.py`), which:
- Provides safe builtins and disallows direct `exec/eval` in user scope.
- Injects `llm_query` and `llm_query_batched` for recursive sub-LLM calls.
- Executes a `setup_code` block that defines helper functions and loads the corpus.

**Key REPL helpers defined in `run_investigation.py` setup_code**
- `derive_keywords()`
- `discover_chunks()`
- `get_chunk_metadata()`
- `run_worker_stage()`
- `run_ioc_stage()`
- `format_report()`

The REPL keeps the large log corpus in memory, enabling targeted retrieval without passing raw logs into the root LM prompt.

## RLM Orchestration (Root and Sub-LLM Roles)
### Root Model (Depth = 0)
The root RLM orchestrates the investigation:
1. Derives exactly 5 keywords.
2. Discovers relevant chunk IDs via regex/keyword search.
3. Calls a **worker sub-LLM** to generate log-filtering code.
4. Calls an **IOC sub-LLM** to extract indicators.
5. Performs at most one pivot cycle with up to 3 pivot keywords.
6. Formats the final report using a fixed template.

### Sub-LLM Worker Stage
`run_worker_stage()`:
- Builds a prompt including alert metadata, chunk IDs, and chunk metadata.
- Requests Python code from a sub-LLM that filters logs inside the REPL.
- Executes returned code in a sandboxed scope.
- Normalizes worker output (`filtered_logs` must include `chunk_id`, `log_index`, `log`).
- Falls back to `_fallback_filter_logs()` if the worker output is invalid or empty.

### Sub-LLM IOC Stage
`run_ioc_stage()`:
- Loads `relevant_logs.jsonl` (saved by worker stage).
- Truncates log fields to control prompt size.
- Requests structured JSON output with IOC references.
- Enforces schema defaults and trims pivot keywords.

## Fast Mode (Deterministic Pipeline)
The system defaults to **fast mode** in `run_investigation()`:
- Executes the helper stages directly in the REPL (no long recursive loop).
- Ensures the pipeline completes in minutes rather than tens of minutes.
- Still uses sub-LLM calls for worker and IOC stages.

## Evidence Outputs
Generated outputs (ignored by default in Git):
- `get_siem_context/evidence_discovery_package.md`
- `get_siem_context/relevant_logs.jsonl`
- `get_siem_context/audit_log.jsonl`
- `get_siem_context/rlm_logs/*.jsonl`

## Auditability and Transparency
The pipeline is instrumented with `audit_log.jsonl` to capture:
- Alert loading
- Corpus loading
- Worker stage start and output
- IOC stage start and output
- Investigation start/complete

This creates a verifiable trail of the root RLM’s control flow without exposing raw logs in prompts.

## Privacy and Safety Considerations
- Root LM sees only chunk IDs and metadata, never raw logs.
- Raw logs are restricted to REPL execution and saved separately.
- Sensitive files are ignored by `.gitignore` to prevent leakage.
- Safe builtins prevent unauthorized system calls in the REPL scope.

## Performance Controls
The pipeline limits runtime and token usage via caps:
- `MAX_INITIAL_KEYWORDS = 5`
- `MAX_PIVOT_KEYWORDS = 3`
- `MAX_PIVOT_CYCLES = 1`
- `RLM_MAX_TOTAL_LOGS`, `RLM_IOC_MAX_LOGS`, `RLM_IOC_MAX_CHARS`

These settings trade breadth for predictable runtime, enabling iterative debugging and reproducible behavior.

## Limitations
- Worker stage relies on sub-LLM code quality; fallback is heuristic.
- Log chunking quality affects recall/precision.
- The system is not a classifier; it only harvests evidence.
- Deep recursive depth (>1) is not used, which may limit multi-hop reasoning over very large corpora.

## Future Work
- Introduce asynchronous sub-LLM calls to reduce latency.
- Add retrieval scoring beyond keyword/regex matches.
- Evaluate performance on multiple alert categories and datasets.
- Explore deeper recursion depth or specialized sub-LLM models.

## References
- Alex Zhang, MIT team. "Recursive Language Models" blog post, 2025. citeturn0search0
