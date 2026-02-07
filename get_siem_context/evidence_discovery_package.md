# RLM Evidence Discovery Package

**Alert**: APT29 PowerShell Obfuscation
**Collection Date**: 2026-02-07T00:24:41.690482

---


# RLM Evidence Discovery Report

## Alert Summary
- Alert Name: APT29 PowerShell Obfuscation
- Timestamp: 2026-02-04T07:58:46.089Z
- Severity: high

## Investigation Scope
- Initial Keywords: C:\Users\gabri\AppData\Local\Programs\Warp\pwsh.ps1, pwsh.ps1, 4104, Gabe, gabri
- Pivot Keywords: Microsoft-Windows-PowerShell/Operational, event.code:4104, Warp-Send-JsonMessage
- Chunks Analyzed: 20260201_0815, 20260201_0835, 20260201_0855, 20260201_0905, 20260201_0935, 20260201_0945, 20260201_0955, 20260201_1005, 20260201_1055, 20260201_1715, 20260201_1725, 20260201_1735, 20260204_0725, 20260204_0745, 20260204_0835, 20260204_1035, 20260204_1205, 20260205_0555, 20260205_0605, 20260205_0615, 20260205_0645, 20260205_0705, 20260205_0825, 20260205_0915, 20260206_1125, 20260207_0305

## Evidence Summary
Initial IOC summary:
PowerShell Script Block Logging (Event ID 4104) captured creation of a large script block from Warp terminal integration script (pwsh.ps1) on host Gabe under user gabri. The content includes char-casting (e.g., [char]0x1b/[char]0x07) and Invoke-Expression usage, which can trigger APT29-style obfuscation detections. No network indicators or file hashes are present in the provided filtered logs.
Pivot IOC summary:
PowerShell Script Block Logging (Event ID 4104) shows execution of Warp terminal PowerShell profile/module code from C:\Users\gabri\AppData\Local\Programs\Warp\pwsh.ps1 on host Gabe under user gabri. The content includes character casting ($([char]0x1b), $([char]0x07)), hex encoding, and Invoke-Expression usage (likely triggering the obfuscation rule), plus a long base64/certificate-like blob embedded in script blocks. No external IPs/domains/hashes are present in the provided logs.

## IOCs and Artifacts (with References)
| Type | Value | References | Reason |
|---|---|---|---|
| host | Gabe | ['20260204_0725:2', '20260204_0725:5', '20260204_0745:0'] | Host where the suspicious/flagged PowerShell script blocks were logged (4104) for Warp pwsh.ps1 content. |
| user | gabri | ['20260204_0725:2', '20260204_0725:10', '20260204_0745:0'] | User context executing the PowerShell script blocks that triggered the alert. |
| file | C:\Users\gabri\AppData\Local\Programs\Warp\pwsh.ps1 | ['20260204_0725:2', '20260204_0725:5', '20260204_0725:10', '20260204_0745:1'] | Script file path associated with the logged script blocks and alert context. |
| file | pwsh.ps1 | ['20260204_0725:2', '20260204_0725:5', '20260204_0745:1'] | PowerShell script name referenced repeatedly in 4104 script block logs (Warp profile/module script). |
| script_block | ScriptBlock ID: 6e532fbb-d762-47a2-ad88-0f3dd860fd07 | ['20260204_0725:10'] | Unique ScriptBlock ID tied to the logged content in the alert metadata (Warp pwsh.ps1). |
| process | PowerShell (event.code 4104 script block logging) | ['20260204_0725:0', '20260204_0725:5', '20260204_0725:10', '20260204_0745:0'] | Execution of PowerShell script blocks (4104) containing char-casting and encoding logic consistent with the detection rule category. |
| command_line | Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force | ['20260204_0725:0', '20260204_0745:0'] | Execution policy modification in the logged script block; can be used for follow-on execution of scripts. |
| command_line | Invoke-Expression | ['20260204_0725:10'] | Use of Invoke-Expression observed in the Warp script content; commonly abused and also referenced as suppressed warning in the logged script block. |
| other | $([char]0x1b)]9278; | ['20260204_0725:5', '20260204_0725:10', '20260204_0725:13'] | Char-casting sequence present in script blocks (escape sequence construction) contributing to obfuscation-style patterns. |
| other | $([char]0x07) | ['20260204_0725:5', '20260204_0725:10', '20260204_0725:13'] | Char-casting sequence used to build OSC end marker; contributes to obfuscation-like behavior detected by rule. |
| script_block | zmORCi2YsaTj6RZnCve00CCKgSKXmqKS5J4FfHViYBq9OHNlxhijy8huwhQvw | ['20260204_0725:3', '20260204_0725:6'] | Large encoded/blob-like content embedded in script block text (appears base64/certificate related); worth extracting for further decoding/verification. |
| script_block | RVNOOjdCMUEt | ['20260204_0745:1'] | Encoded/base64-like fragment present in script block text (7 of 7); could be part of a signature/certificate blob or embedded payload. |

## Key Commands and Script Blocks
| Type | Value | References |
|---|---|---|
| script_block | ScriptBlock ID: 6e532fbb-d762-47a2-ad88-0f3dd860fd07 | ['20260204_0725:10'] |
| command_line | Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned -Force | ['20260204_0725:0', '20260204_0745:0'] |
| command_line | Invoke-Expression | ['20260204_0725:10'] |
| script_block | zmORCi2YsaTj6RZnCve00CCKgSKXmqKS5J4FfHViYBq9OHNlxhijy8huwhQvw | ['20260204_0725:3', '20260204_0725:6'] |
| script_block | RVNOOjdCMUEt | ['20260204_0745:1'] |

## Analyst Notes
Filtered to PowerShell ScriptBlock logging (event.code 4104) on host 'Gabe' for user 'gabri'/SYSTEM and activity referencing Warp PowerShell profile script 'C:\Users\gabri\AppData\Local\Programs\Warp\pwsh.ps1' and associated ScriptBlock ID/patterns (char casting/hex encoding/Invoke-Expression) consistent with the alert pivots.
Pivot worker summary:
Filtered to PowerShell ScriptBlock (4104) events on host/user matching the alert, prioritizing entries referencing Warp pwsh.ps1 and Warp-* functions (Warp-Send-JsonMessage / hex encoding) and/or matching the alert ScriptBlock ID/file path, consistent with the obfuscation/char-casting technique the rule targets.

## Next Pivots (if any)

