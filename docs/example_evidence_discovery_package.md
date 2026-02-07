# RLM Evidence Discovery Package (Sanitized Example)

**Alert**: Example PowerShell Obfuscation
**Collection Date**: 2026-02-07T00:00:00Z

---

# RLM Evidence Discovery Report

## Alert Summary
- Alert Name: Example PowerShell Obfuscation
- Timestamp: 2026-02-04T07:58:46.089Z
- Severity: high

## Investigation Scope
- Initial Keywords: `example.ps1`, `4104`, `HOST-01`, `user.example`, `S-1-5-21-EXAMPLE`
- Pivot Keywords: `ScriptBlockText`, `-EncodedCommand`, `Invoke-Expression`
- Chunks Analyzed: `20260204_0725`, `20260204_0745`

## Evidence Summary
PowerShell Script Block Logging (Event ID 4104) captured execution of a script block
referencing `example.ps1` on host `HOST-01` under user `user.example`. The logs show
char-casting patterns and `Invoke-Expression`, consistent with an obfuscation-style
alert, but no external C2 or malware hash was observed in the filtered evidence.

## IOCs and Artifacts (with References)
| Type | Value | References | Reason |
|---|---|---|---|
| file | C:\Users\user\Tools\example.ps1 | ['20260204_0725:2'] | Script path referenced in the 4104 ScriptBlock event. |
| script_block | ScriptBlock ID: 00000000-0000-0000-0000-000000000000 | ['20260204_0725:2'] | ScriptBlock ID for pivot correlation. |
| user | user.example | ['20260204_0725:2'] | User context associated with the script block event. |
| host | HOST-01 | ['20260204_0725:2'] | Host where the script block was logged. |
| other | event.code:4104 | ['20260204_0725:2'] | PowerShell Script Block Logging event code. |
| other | Invoke-Expression | ['20260204_0725:2'] | Execution method present in script block content. |

## Key Commands and Script Blocks
| Type | Value | References |
|---|---|---|
| script_block | ScriptBlock ID: 00000000-0000-0000-0000-000000000000 | ['20260204_0725:2'] |
| command_line | powershell.exe -EncodedCommand ... | ['20260204_0745:0'] |

## Analyst Notes
Filtered to PowerShell ScriptBlock (Event ID 4104) activity on host/user pivots, focusing
on script content containing char-casting and `Invoke-Expression`. Related logs were
included when sharing process/command-line pivots with the matched ScriptBlock events.

## Next Pivots (if any)
- `FromBase64String`
- `Add-Type`
- `process.parent.command_line`
