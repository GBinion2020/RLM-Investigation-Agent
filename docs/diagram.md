# RLM-SIEM Diagram

```mermaid
flowchart TD
    A[Raw Elastic Alert] --> B[Normalize Alert]
    B --> C[normalized_alert.json]

    C --> D[run_investigation.py]
    D --> E[Load LogCorpus]
    D --> F[REPL Setup Code]

    F --> G[derive_keywords (5)]
    G --> H[discover_chunks]
    H --> I[get_chunk_metadata]

    I --> J[run_worker_stage]
    J --> K{Worker Output OK?}
    K -- Yes --> L[Save filtered logs]
    K -- No --> M[Fallback filter]
    M --> L

    L --> N[run_ioc_stage]
    N --> O{Pivot keywords?}
    O -- Yes (max 1) --> H
    O -- No --> P[format_report]

    P --> Q[evidence_discovery_package.md]
    L --> R[relevant_logs.jsonl]
    D --> S[audit_log.jsonl]

    subgraph LMHandler
      J --> J1[Worker LLM]
      N --> N1[IOC LLM]
    end
```
