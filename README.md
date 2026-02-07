# RLM Investigation Agent

**Security evidence harvesting with Recursive Language Models (RLM).**  
This pipeline ingests a SIEM alert, normalizes it, searches a local log corpus, and delegates focused log analysis to sub?LLMs. The result is a **structured evidence report** with IOCs and log references ? **no benign/malicious classification**.

## Acknowledgements
This project is inspired by the Recursive Language Models (RLM) work by **Alex Zhang and the MIT team**. Their research and open materials made this implementation possible and shaped the design choices throughout this repo.

## Why This Exists
This project explores **Recursive Language Models (RLMs)** as a way to achieve an *effectively infinite context window* without stuffing all logs into a single model call. A root model operates inside a REPL holding large context variables and can recursively call sub?LLMs to inspect bounded slices of that context. This keeps the root prompt small and focused while still accessing large datasets.

In this SIEM setting, the root RLM never sees the full log corpus in its prompt. It derives keywords, finds chunk IDs, and delegates filtering/IOC extraction to sub?LLMs operating over scoped data.

## At A Glance
| Category | What Happens |
|---|---|
| **Inputs** | Elastic alert + Elastic logs (`logs-*`) |
| **Core Actions** | Normalize alert ? build log corpus ? derive keywords ? discover chunk IDs ? worker filtering ? IOC extraction |
| **Outputs** | `evidence_discovery_package.md`, `relevant_logs.jsonl`, `audit_log.jsonl` |
| **Guarantees** | No classification, capped pivots, root never sees raw logs |

## Example Output (Sanitized)
The pipeline writes **`get_siem_context/evidence_discovery_package.md`** (ignored by default to avoid data leakage).  
Here?s a **sanitized example** you can share publicly:
- `docs/example_evidence_discovery_package.md`

## Simple Workflow (Conceptual)
![Simple Workflow Diagram](docs/rlm22.png)

## Pipeline Workflow (Detailed Data + Control Flow)
```mermaid
flowchart TD
    subgraph SIEM_Ingestion["SIEM Ingestion"]
        A["Elastic SIEM (logs-*)"] --> B["get_siem_context/query_0.py: query_0()"]
        A --> B2["get_siem_context/query_json.py: query_json()"]
        B --> C["baseline_context.csv"]
        B2 --> D["log_chunks.json"]
    end

    subgraph Alert_Ingestion["Alert Ingestion"]
        E["Intake_Alert/Intake_Elastic_logs.py: Elastic.Alert()"] --> F["Intake_Alert/Normalize.py: normalize()"]
        E --> G["Intake_Alert/Normalize.py: alert_details_normalized()"]
        F --> H["normalized_alert.json"]
        G --> I["alert_details.json"]
    end

    subgraph Runtime["RLM Runtime"]
        J["rlm_siem/run_investigation.py: run_investigation()"] --> K["RLM(...): local REPL"]
        D --> L["rlm_siem/log_corpus.py: LogCorpus()"]
        L --> K
        H --> J
        I --> J
        K --> M["setup_code: helper functions in REPL"]
        M --> N["Root RLM orchestration"]
    end

    subgraph LMHandler["LM Handler (Sub?LLMs)"]
        N --> O["run_worker_stage() -> llm_query()"]
        N --> P["run_ioc_stage() -> llm_query()"]
    end

    N --> Q["get_siem_context/evidence_discovery_package.md"]
    N --> R["get_siem_context/relevant_logs.jsonl"]
    N --> S["get_siem_context/audit_log.jsonl"]
```

## Process Notes (Mapped to Function Names)
- Alert ingestion uses `Elastic.Alert()` to pull the latest alert and `normalize()` to write `normalized_alert.json` plus `alert_details_normalized()` for `alert_details.json`.
- SIEM log pull is handled by `query_0()` or `query_json()` which write `baseline_context.csv` and/or `log_chunks.json`.
- Corpus load is performed by `LogCorpus()` which builds an inverted index for keyword and regex search.
- REPL injection is done by `run_investigation()` which provides helper functions inside the REPL scope (the `setup_code` block).
- Root orchestration uses `derive_keywords()`, `discover_chunks()`, `get_chunk_metadata()` before delegating to sub?LLMs.
- Worker stage calls `run_worker_stage()` which asks a sub?LLM to write filtering code, executes it, and falls back to `_fallback_filter_logs()` if needed.
- IOC stage calls `run_ioc_stage()` to extract indicators and pivot keywords from filtered logs.
- Reporting is performed by `format_report()` to produce `evidence_discovery_package.md` plus `relevant_logs.jsonl` and `audit_log.jsonl`.

## Architecture Details
**1) Alert Intake and Normalization**
- `Intake_Alert/Intake_Elastic_logs.py` pulls the latest Elastic alert.
- `Intake_Alert/Normalize.py` writes:
  - `normalized_alert.json`
  - `alert_details.json`
- The normalized alert includes `message`, file path, host, user, and event code fields so command text and script blocks are available for keyword derivation.

**2) Log Ingestion from SIEM**
- `get_siem_context/query_0.py` (or `query_json.py`) pulls logs from Elastic and normalizes them into a high?fidelity schema.
- Output is stored as `baseline_context.csv` and/or `log_chunks.json`.
- These files are considered sensitive and are ignored by default in `.gitignore`.

**3) Log Corpus**
- `rlm_siem/log_corpus.py` loads `get_siem_context/log_chunks.json`.
- It builds an inverted index of tokens for fast keyword and regex searches.
- The root model sees only chunk IDs and metadata, not raw logs.

**4) REPL Environment + RLM Orchestration**
- `rlm_siem/run_investigation.py` runs the pipeline.
- A REPL environment is created with helper functions:
  - `derive_keywords`
  - `discover_chunks`
  - `get_chunk_metadata`
  - `run_worker_stage`
  - `run_ioc_stage`
  - `format_report`
- The worker LLM writes log?filtering code, which is executed in a sandboxed scope.
- The IOC LLM extracts indicators with `chunk_id:log_index` references.

**5) Report and Evidence Output**
- `evidence_discovery_package.md` is formatted using a fixed template.
- `relevant_logs.jsonl` stores evidence logs for analyst review.
- `audit_log.jsonl` provides an audit trail of pipeline stages.

## Fast Mode (Default)
The pipeline runs in deterministic fast mode to avoid long recursive loops.
- It directly executes the helper stages once.
- It performs at most one pivot.
- It always emits a templated report.

Disable fast mode if you want the full recursive loop:
```
python rlm_siem/run_investigation.py --no-fast
```

## Constraints (By Design)
- Exactly 5 initial keywords.
- At most 3 pivot keywords.
- At most 1 pivot cycle.
- No benign/malicious classification.
- Root model never sees raw logs.

## Setup
1) Create a virtual environment and install deps.
2) Copy `.env.example` to `.env` and fill values.
3) Ensure your log corpus exists at `get_siem_context/log_chunks.json`.

Example:
```
copy .env.example .env
```

## Running the Pipeline
```
python Intake_Alert/Normalize.py
python rlm_siem/run_investigation.py
```

## Configuration
Key environment variables:
- `OPENAI_API_KEY`
- `ELASTIC_HOST`
- `ELASTIC_API_KEY`
- `ELASTIC_COMPAT_VERSION`
- `RLM_MODEL`
- `RLM_MAX_CHUNKS_PER_KEYWORD`
- `RLM_MAX_TOTAL_CHUNKS`
- `RLM_MAX_TOTAL_LOGS`
- `RLM_MAX_LOGS_PER_CHUNK`
- `RLM_IOC_MAX_LOGS`
- `RLM_IOC_MAX_CHARS`

## Outputs (Generated)
These are ignored by default in `.gitignore` because they can contain sensitive data:
- `get_siem_context/evidence_discovery_package.md`
- `get_siem_context/relevant_logs.jsonl`
- `get_siem_context/audit_log.jsonl`
- `get_siem_context/rlm_logs/*.jsonl`

## Docs
The following documents contain deeper technical details and internal prompt text. They are intended for maintainers and auditors, not end users.

- `docs/engineering_report.md` ? research-grade architecture and implementation report.
- `docs/prompts.md` ? full prompt text used by the RLM pipeline (sensitive by nature; review before sharing).
- `docs/diagram.md` ? detailed Mermaid diagrams used in this README.

## Troubleshooting
Common issues:
- Missing `message` in alerts: rerun `Intake_Alert/Normalize.py`.
- Worker exec errors: check `audit_log.jsonl` for `worker_exec_error`.
- Slow runs: lower `RLM_MAX_TOTAL_LOGS` and `RLM_IOC_MAX_LOGS`.
- Git push too large: remove artifacts and rewrite history (see engineering report).

## Disclaimer
This system is for evidence harvesting only. It does not decide whether an alert is benign or malicious.
