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

df = pd.read_csv("apt29_events.csv")
df['@timestamp'] = pd.to_datetime(df['@timestamp'])

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
# "C:\\windows\\system32\\svchost.exe -k LocalSystem"
proc['NewProcessPath'] = proc['CommandLine'].str.split().str[0]
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
proc = proc[proc['duration_seconds'] >= 0] 

# ---------------------------------------------------------------
# SAVE RESULTS
# ---------------------------------------------------------------
logons.to_csv("features_logons.csv", index=False)
proc.to_csv("features_processes.csv", index=False)

print("=== Logon summary (Event ID 4624) ===")
print(f"Total logons: {len(logons)}")
print(f"Remote logons (type 3/10): {logons['is_remote_logon'].sum()}")
print(f"Elevated (admin) logon sessions: {logons['was_elevated'].sum()}")

print("\n=== Process summary (Event ID 4688) ===")
print(f"Total process creations: {len(proc)}")
print(f"Suspicious office->shell spawns: {proc['suspicious_office_spawn'].sum()}")
print(f"Suspicious svchost spawns: {proc['suspicious_svchost'].sum()}")
print(f"Processes with matched exit time: {proc['exit_time'].notna().sum()}")

print("\nSaved features_logons.csv and features_processes.csv")
