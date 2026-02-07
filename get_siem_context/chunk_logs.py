import os
import json
import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict
from rlm_siem.normalization import LogNormalizer

def chunk_logs_by_time(csv_path, chunk_minutes=10):
    """
    Chunk SIEM logs into temporal windows with normalization and indexing.
    """
    print(f"[*] Loading logs from {csv_path}...")
    df = pd.read_csv(csv_path, low_memory=False)
    
    # Pre-clean string columns
    string_cols = ["Process_Name", "Command_Line", "Executable", "Parent_Process", 
                   "Parent_Command_Line", "Script_Block", "Message", "Host", "User"]
    for col in string_cols:
        if col in df.columns:
            df[col] = df[col].fillna("").astype(str)
    
    # Convert timestamp
    df['Timestamp'] = pd.to_datetime(df['Timestamp'])
    df = df.sort_values('Timestamp')
    
    print(f"[+] Loaded {len(df)} logs spanning {df['Timestamp'].min()} to {df['Timestamp'].max()}")
    
    chunks = []
    inverted_index = defaultdict(set) # keyword -> set(chunk_ids)
    
    start_time = df['Timestamp'].min()
    end_time = df['Timestamp'].max()
    current_window_start = start_time
    
    processed_count = 0
    
    while current_window_start < end_time:
        current_window_end = current_window_start + timedelta(minutes=chunk_minutes)
        
        # Filter logs in this window
        window_logs_df = df[(df['Timestamp'] >= current_window_start) & 
                         (df['Timestamp'] < current_window_end)]
        
        if len(window_logs_df) == 0:
            current_window_start = current_window_end
            continue
        
        chunk_id = f"{current_window_start.strftime('%Y%m%d_%H%M')}"
        
        # --- NORMALIZATION & INDEXING ---
        normalized_logs = []
        raw_records = window_logs_df.to_dict('records')
        
        processed_count += len(raw_records)
        for raw in raw_records:
            # Normalize
            norm = LogNormalizer.normalize(raw)
            normalized_logs.append(norm)
            
            # Indexing
            keywords = LogNormalizer.get_keywords(norm)
            for kw in keywords:
                inverted_index[kw].add(chunk_id)
        
        # Generate Narrative Summary using NORMALIZED data
        summary_parts = []
        hosts = set(l[LogNormalizer.HOST] for l in normalized_logs if l[LogNormalizer.HOST])
        users = set(l[LogNormalizer.USER] for l in normalized_logs if l[LogNormalizer.USER])
        events = [l[LogNormalizer.EVENT_CODE] for l in normalized_logs]
        
        # 1. Basics
        summary_parts.append(f"Time: {current_window_start.strftime('%H:%M')}-{current_window_end.strftime('%H:%M')}.")
        summary_parts.append(f"Events: {len(normalized_logs)}.")
        if hosts: summary_parts.append(f"Hosts: {', '.join(list(hosts)[:3])}.")
        if users: summary_parts.append(f"Users: {', '.join(list(users)[:5])}.")
        
        # 2. Top Events
        from collections import Counter
        top_evs = Counter(events).most_common(3)
        ev_str = ", ".join([f"{code} ({cnt})" for code, cnt in top_evs])
        summary_parts.append(f"Top Events: {ev_str}.")
        
        # 3. Risk Indicators (Powershell)
        pwsh_logs = [l for l in normalized_logs if l[LogNormalizer.EVENT_CODE] == '4104']
        if pwsh_logs:
            summary_parts.append(f"ALERT: {len(pwsh_logs)} PowerShell Block logs (4104) detected.")
            # Add a snippet of the first script
            snippet = pwsh_logs[0][LogNormalizer.SCRIPT_BLOCK][:100]
            summary_parts.append(f"Sample Script: {snippet}...")

        chunk = {
            "chunk_id": chunk_id,
            "start_time": current_window_start.isoformat(),
            "end_time": current_window_end.isoformat(),
            "event_count": len(normalized_logs),
            "summary": " ".join(summary_parts),
            "normalized_logs": normalized_logs # Store NORMALIZED logs
        }
        
        chunks.append(chunk)
        current_window_start = current_window_end
    
    # Convert sets to lists for JSON serialization
    serialized_index = {k: list(v) for k, v in inverted_index.items()}
    
    print(f"[+] Processed {processed_count} logs into {len(chunks)} chunks.")
    return chunks, serialized_index

def main():
    csv_path = "./get_siem_context/baseline_context.csv"
    output_path = "./get_siem_context/log_chunks.json"
    index_path = "./get_siem_context/inverted_index.json"
    
    if not os.path.exists(csv_path):
        print(f"[-] Error: {csv_path} not found.")
        return
    
    chunks, index = chunk_logs_by_time(csv_path, chunk_minutes=10)
    
    print(f"[*] Saving chunks to {output_path}...")
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(chunks, f, indent=2)
        
    print(f"[*] Saving index to {index_path}...")
    with open(index_path, 'w', encoding='utf-8') as f:
        json.dump(index, f, indent=2)
        
    print("[+] Done.")

if __name__ == "__main__":
    main()

