
import json

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
        keywords = set()
        
        # Add exact field values
        for field in [LogNormalizer.USER, LogNormalizer.HOST, LogNormalizer.EVENT_CODE, LogNormalizer.PROCESS_NAME]:
            val = log.get(field, "").lower()
            if val and val != "unknown" and val != "nan":
                keywords.add(val)
                
        # Tokenize command line / message (simple split)
        text_fields = [log.get(LogNormalizer.COMMAND_LINE, ""), log.get(LogNormalizer.MESSAGE, "")]
        for text in text_fields:
            if not text: continue
            # specialized tokens for paths, etc
            tokens = str(text).replace("\\", " ").replace("/", " ").replace('"', " ").split()
            for t in tokens:
                if len(t) > 3 and len(t) < 50: # Filter noise
                    keywords.add(t.lower())
                    
        return list(keywords)
