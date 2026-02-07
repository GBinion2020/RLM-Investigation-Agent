# RLM-SIEM Detailed Diagrams

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

    subgraph LMHandler["LM Handler (sub-LLMs)"]
        N --> O["run_worker_stage() -> llm_query()"]
        N --> P["run_ioc_stage() -> llm_query()"]
    end

    N --> Q["get_siem_context/evidence_discovery_package.md"]
    N --> R["get_siem_context/relevant_logs.jsonl"]
    N --> S["get_siem_context/audit_log.jsonl"]
```

## Investigation Workflow (Helper Functions + Control Loop)
```mermaid
flowchart TD
    A["derive_keywords()"] --> B["discover_chunks()"]
    B --> C["get_chunk_metadata()"]
    C --> D["run_worker_stage()"]
    D --> E{Worker Output OK?}
    E -- "Yes" --> F["save_relevant_logs()"]
    E -- "No" --> G["_fallback_filter_logs()"]
    G --> F

    F --> H["run_ioc_stage()"]
    H --> I{Pivot keywords?}
    I -- "Yes (max 1)" --> B
    I -- "No" --> J["format_report()"]
    J --> K["evidence_discovery_package.md"]
```

## Process Notes (Mapped to Function Names)
- Alert ingestion uses `Elastic.Alert()` to pull the latest alert and `normalize()` to write `normalized_alert.json` plus `alert_details_normalized()` for `alert_details.json`.
- SIEM log pull is handled by `query_0()` or `query_json()` which write `baseline_context.csv` and/or `log_chunks.json`.
- Corpus load is performed by `LogCorpus()` which builds an inverted index for keyword and regex search.
- REPL injection is done by `run_investigation()` which provides helper functions inside the REPL scope (the `setup_code` block).
- Root orchestration uses `derive_keywords()`, `discover_chunks()`, `get_chunk_metadata()` before delegating to sub-LLMs.
- Worker stage calls `run_worker_stage()` which asks a sub-LLM to write filtering code, executes it, and falls back to `_fallback_filter_logs()` if needed.
- IOC stage calls `run_ioc_stage()` to extract indicators and pivot keywords from filtered logs.
- Reporting is performed by `format_report()` to produce `evidence_discovery_package.md` plus `relevant_logs.jsonl` and `audit_log.jsonl`.
