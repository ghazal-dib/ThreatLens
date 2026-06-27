"""
Feature engineering for the APT29 Mordor dataset extracted from HELK.

Reads apt29_events.csv and builds detection-oriented features for:
  1. Logon analysis (Event ID 4624) - flags remote logon types
  2. Privilege escalation correlation (4624 <-> 4672)
  3. Process creation analysis (4688) - suspicious parent-child pairs
  4. Process duration (4688 <-> 4689)

Outputs two files: features_logons.csv and features_processes.csv
"""

import pandas as pd

df = pd.read_csv("apt29_events.csv", encoding="utf-8")
df['@timestamp'] = pd.to_datetime(df['@timestamp'])

# ---------------------------------------------------------------
# MOJIBAKE REPAIR
# The raw apt29_events.csv has a double-encoding bug baked into it: at
# least one CommandLine value contains a Unicode RTLO (right-to-left
# override, U+202E) character used by the attacker for filename spoofing.
# Somewhere upstream (likely the original Elasticsearch extraction) those
# UTF-8 bytes got misread as Windows-1252 and re-saved as UTF-8, turning
# U+202E into the 3-character garbage "â€®". This is a well-known,
# reversible pattern (encode as cp1252, decode as utf-8) - repair it here
# so the actual evasion technique is preserved correctly downstream
# instead of being hidden behind mangled text.
def _repair_mojibake(text):
    if not isinstance(text, str):
        return text
    try:
        return text.encode('cp1252').decode('utf-8')
    except (UnicodeDecodeError, UnicodeEncodeError):
        return text

df['CommandLine'] = df['CommandLine'].apply(_repair_mojibake)
df['ParentProcessName'] = df['ParentProcessName'].apply(_repair_mojibake)

# ---------------------------------------------------------------
# 1. LOGON ANALYSIS (Event ID 4624)
# ---------------------------------------------------------------
logons = df[df.EventID == 4624].copy()

# Logon Type 3 = network logon, 10 = RDP -> lateral movement indicators
logons['is_remote_logon'] = logons['LogonType'].isin([3, 10])

# ---------------------------------------------------------------
# 2. PRIVILEGE ESCALATION CORRELATION (4624 <-> 4672)
# ---------------------------------------------------------------
privs = df[df.EventID == 4672].copy()

# Set of LogonIds that were granted special/admin privileges
elevated_logon_ids = set(privs['SubjectLogonId'].dropna())

# Mark which logon sessions were later granted those privileges
logons['was_elevated'] = logons['TargetLogonId'].isin(elevated_logon_ids)

# ---------------------------------------------------------------
# 3. PROCESS CREATION ANALYSIS (4688)
# ---------------------------------------------------------------
proc = df[df.EventID == 4688].copy()

# CommandLine starts with the new process's full path, e.g.
# "C:\\windows\\system32\\svchost.exe -k LocalSystem" OR, when the path
# itself contains spaces (e.g. "C:\Program Files\..."), it's quoted:
# "C:\\Program Files\\SysinternalsSuite\\sdelete64.exe" /accepteula ...
# A plain .str.split() on whitespace breaks on the quoted case - it grabs
# just `"C:\Program` and mislabels every process under a spaced path as
# "program" (this hid 15 real events, including all 3 sdelete64.exe runs
# and 4 PsExec64.exe runs, behind a meaningless name). Use a regex that
# prefers a quoted path if present, falling back to the first whitespace
# token otherwise.
_path_pattern = proc['CommandLine'].str.strip().str.extract(r'^"([^"]+)"|^(\S+)')
proc['NewProcessPath'] = _path_pattern[0].fillna(_path_pattern[1])
proc['NewProcessName'] = proc['NewProcessPath'].str.split('\\').str[-1].str.lower().str.strip('"')
proc['ParentProcessNameOnly'] = proc['ParentProcessName'].str.split('\\').str[-1].str.lower()

# Scenario 1 from Chapter 5: Office app spawning a shell/scripting process
SUSPICIOUS_PARENTS = ['winword.exe', 'excel.exe', 'outlook.exe', 'powerpnt.exe']
SUSPICIOUS_CHILDREN = ['powershell.exe', 'cmd.exe', 'mshta.exe', 'rundll32.exe', 'wscript.exe', 'cscript.exe']

proc['suspicious_office_spawn'] = (
    proc['ParentProcessNameOnly'].isin(SUSPICIOUS_PARENTS) &
    proc['NewProcessName'].isin(SUSPICIOUS_CHILDREN)
)

# "Hiding in plain sight": svchost.exe should only be spawned by services.exe
proc['suspicious_svchost'] = (
    (proc['NewProcessName'] == 'svchost.exe') &
    (proc['ParentProcessNameOnly'] != 'services.exe')
)

# ---------------------------------------------------------------
# 4. PROCESS DURATION (4688 <-> 4689)
# ---------------------------------------------------------------
exits = df[df.EventID == 4689][['Hostname', 'ProcessId', '@timestamp']].copy()
exits = exits.rename(columns={'ProcessId': 'NewProcessId', '@timestamp': 'exit_time'})
# Drop duplicate PIDs on the same host (PIDs can be reused over time)
exits = exits.drop_duplicates(subset=['Hostname', 'NewProcessId'])

proc = proc.merge(exits, on=['Hostname', 'NewProcessId'], how='left')
proc['duration_seconds'] = (proc['exit_time'] - proc['@timestamp']).dt.total_seconds()
# IMPORTANT: do NOT drop rows here. Of 460 raw process-creation events, 130
# have no matching exit event in this dataset (process still running, or
# the exit just wasn't captured) and a further ~23 produce a negative
# duration from a reused PID matching the wrong exit. Previously this line
# dropped all of them outright (proc = proc[proc['duration_seconds'] >= 0]),
# which silently removed 153 events from EVERY downstream rule and the ML
# model - including the dataset's one obfuscated/encoded PowerShell command
# (no exit event was logged for it). Duration-based rules (Alert 2) already
# handle NaN/negative values safely via explicit >=0 comparisons, which
# evaluate to False on NaN, so this only changes behavior for rules that
# don't depend on duration.
proc.loc[proc['duration_seconds'] < 0, 'duration_seconds'] = pd.NA

# ---------------------------------------------------------------
# 5. OBFUSCATED/ENCODED COMMAND DETECTION
# Classic PowerShell obfuscation/staging indicators: encoded commands,
# hidden windows, or in-memory (gzip+base64) payloads. Presence-based,
# like suspicious_office_spawn/suspicious_svchost - does not depend on
# duration, so it still catches processes with no matched exit event.
# ---------------------------------------------------------------
OBFUSCATION_PATTERNS = r'-enc\b|-encodedcommand|frombase64string|-w(?:indowstyle)?\s+hidden|-nop\b'
proc['obfuscated_command'] = (
    proc['NewProcessName'].isin(['powershell.exe', 'powershell_ise.exe']) &
    proc['CommandLine'].str.contains(OBFUSCATION_PATTERNS, case=False, regex=True, na=False)
)

# ---------------------------------------------------------------
# SAVE RESULTS
# ---------------------------------------------------------------
logons.to_csv("features_logons.csv", index=False, encoding="utf-8")
proc.to_csv("features_processes.csv", index=False, encoding="utf-8")

print("=== Logon summary (Event ID 4624) ===")
print(f"Total logons: {len(logons)}")
print(f"Remote logons (type 3/10): {logons['is_remote_logon'].sum()}")
print(f"Elevated (admin) logon sessions: {logons['was_elevated'].sum()}")

print("\n=== Process summary (Event ID 4688) ===")
print(f"Total process creations: {len(proc)}")
print(f"Suspicious office->shell spawns: {proc['suspicious_office_spawn'].sum()}")
print(f"Suspicious svchost spawns: {proc['suspicious_svchost'].sum()}")
print(f"Obfuscated/encoded command executions: {proc['obfuscated_command'].sum()}")
print(f"Processes with matched, valid exit time: {proc['duration_seconds'].notna().sum()}")
print(f"Processes with no usable duration (excluded from duration-based rules only): {proc['duration_seconds'].isna().sum()}")

print("\nSaved features_logons.csv and features_processes.csv")
