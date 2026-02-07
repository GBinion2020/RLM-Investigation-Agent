
import json
import re

class LogNormalizer:
    """
    Standardizes logs into a consistent ECS-like schema.
    Eliminates field name ambiguity (user vs User) and truncates long fields.
    """
    
    # Standard Fields
    TIMESTAMP = "Timestamp"
    USER = "User"
    HOST = "Host"
    EVENT_CODE = "Event_Code"
    PROCESS_NAME = "Process_Name"
    COMMAND_LINE = "Command_Line"
    FILE_PATH = "File_Path"
    MESSAGE = "Message"
    SCRIPT_BLOCK = "Script_Block"
    
    @staticmethod
    def normalize(raw_log: dict) -> dict:
        """
        Convert a raw log dictionary (from CSV/Pandas) into a clean, normalized dict.
        """
        # Helper to safely get value from multiple potential keys
        def get_val(keys, default=""):
            for k in keys:
                if k in raw_log and raw_log[k] is not None:
                     # Handle NaN/None from pandas
                    val = raw_log[k]
                    if str(val).lower() == "nan":
                        continue
                    return str(val).strip()
            return default

        # Normalize Event Code (handle float/int/str)
        event_code = get_val(["Event_Code", "event_code", "EventID", "event.code"], "Unknown")
        if event_code.endswith(".0"): # Fix pandas float conversion (4104.0 -> 4104)
            event_code = event_code[:-2]

        normalized = {
            LogNormalizer.TIMESTAMP: get_val(["Timestamp", "@timestamp", "TimeCreated"]),
            LogNormalizer.HOST: get_val(["Host", "host.name", "ComputerName"]),
            LogNormalizer.USER: get_val(["User", "user.name", "SubjectUserName", "user.id"]),
            LogNormalizer.EVENT_CODE: event_code,
            LogNormalizer.PROCESS_NAME: get_val(["Process_Name", "process.name", "NewProcessName", "Image"]),
            LogNormalizer.COMMAND_LINE: get_val(["Command_Line", "process.command_line", "CommandLine"]),
            LogNormalizer.FILE_PATH: get_val(["File_Path", "file.path", "TargetFilename"]),
            LogNormalizer.SCRIPT_BLOCK: get_val(["Script_Block", "powershell.file.script_block_text"]),
            LogNormalizer.MESSAGE: get_val(["Message", "message", "EventData"]),
        }

        # If Message is empty, fall back to Command_Line to preserve raw commands
        if not normalized[LogNormalizer.MESSAGE] and normalized[LogNormalizer.COMMAND_LINE]:
            normalized[LogNormalizer.MESSAGE] = normalized[LogNormalizer.COMMAND_LINE]
        
        # Truncate long fields to prevent context window explosion
        if len(normalized[LogNormalizer.SCRIPT_BLOCK]) > 500:
             normalized[LogNormalizer.SCRIPT_BLOCK] = normalized[LogNormalizer.SCRIPT_BLOCK][:500] + "... [TRUNCATED]"
             
        if len(normalized[LogNormalizer.MESSAGE]) > 1000:
             normalized[LogNormalizer.MESSAGE] = normalized[LogNormalizer.MESSAGE][:1000] + "... [TRUNCATED]"

        return normalized

    @staticmethod
    def get_keywords(log: dict) -> list[str]:
        """
        Extract searchable keywords from a NORMALIZED log.
        Returns a list of lowercase tokens for the inverted index.
        """
        keywords: set[str] = set()

        def add_value(value: str) -> None:
            if not value:
                return
            text = str(value).strip()
            if not text:
                return
            if len(text) <= 160:
                keywords.add(text.lower())
            tokens = re.findall(r"[A-Za-z0-9_:\\/.\\-]{2,}", text)
            for tok in tokens:
                if 2 < len(tok) < 80:
                    keywords.add(tok.lower())

        # Add exact field values
        for field in [
            LogNormalizer.USER,
            LogNormalizer.HOST,
            LogNormalizer.EVENT_CODE,
            LogNormalizer.PROCESS_NAME,
        ]:
            val = log.get(field, "")
            if val and str(val).lower() not in {"unknown", "nan"}:
                add_value(val)

        # Include file path parts
        file_path = log.get(LogNormalizer.FILE_PATH, "")
        if file_path:
            add_value(file_path)
            parts = re.split(r"[\\\\/]+", file_path)
            parts = [p for p in parts if p]
            if parts:
                add_value(parts[-1])
                if len(parts) >= 2:
                    add_value("\\\\".join(parts[-2:]))
                if len(parts) >= 3:
                    add_value("\\\\".join(parts[-3:]))

        # Tokenize command line / message / script block
        text_fields = [
            log.get(LogNormalizer.COMMAND_LINE, ""),
            log.get(LogNormalizer.MESSAGE, ""),
            log.get(LogNormalizer.SCRIPT_BLOCK, ""),
        ]
        for text in text_fields:
            add_value(text)

        return list(keywords)
