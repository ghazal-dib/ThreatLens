"""
Rule-based alert engine for the APT29 threat hunting project.

Reads the engineered feature CSVs and applies three detection rules,
each tied directly to a pattern from the book (Chapters 4-5):

  Alert 1 - Lateral Movement:
      A logon session that is BOTH remote (Type 3/10) AND was granted
      elevated privileges, excluding machine accounts ($) which always
      carry elevated tokens by design and are not attacker-controlled.

  Alert 2 - Suspicious Short-Lived Tool:
      A process that ran for under 1 second, excluding machine accounts,
      built-in service accounts, and conhost.exe (which is near-automatic
      noise spawned by almost any console tool, so excluding it lets
      genuinely interesting short-lived tools stand out).

  Alert 3 - Suspicious Spawn:
      A process creation matching the "weaponized Office document" or
      "svchost.exe hiding in plain sight" patterns from Chapter 5.

Outputs a single unified alerts.csv with columns:
  alert_type, account, timestamp, reason, severity
"""

import pandas as pd

logons = pd.read_csv("features_logons.csv")
proc = pd.read_csv("features_processes.csv")

# Tools where short execution is itself a meaningful signal (used to
# set High severity instead of the default Medium for Alert 2)
HIGH_SEVERITY_TOOLS = ['sdelete64.exe', 'sdelete.exe']

# ---------------------------------------------------------------
# ALERT 1: Lateral Movement
# Remote logon (Type 3/10) + elevated privileges, excluding machine accounts
# ---------------------------------------------------------------
alert1 = logons[
    (logons['is_remote_logon'] == True) &
    (logons['was_elevated'] == True) &
    (~logons['TargetUserName'].str.endswith('$'))
].copy()

print(f"Alert 1 - Lateral Movement: {len(alert1)} sessions")
print(alert1['TargetUserName'].value_counts())
print()

alert1_clean = pd.DataFrame({
    'alert_type': "Lateral Movement",
    'account': alert1['TargetUserName'],
    'timestamp': alert1['@timestamp'],
    'reason': "Remote logon with elevated privileges",
    'severity': "High"
})

# ---------------------------------------------------------------
# ALERT 2: Suspicious Short-Lived Tool
# Process ran < 1 second, excluding machine/service accounts and
# conhost.exe (expected noise alongside almost any console tool)
# ---------------------------------------------------------------
alert2 = proc[
    (proc['duration_seconds'] >= 0) &
    (proc['duration_seconds'] < 1) &
    (~proc['SubjectUserName'].str.endswith('$')) &
    (proc['SubjectUserName'] != 'LOCAL SERVICE') &
    (proc['NewProcessName'] != 'conhost.exe')
].copy()

print(f"Alert 2 - Suspicious Short-Lived Tool: {len(alert2)} processes")
print(alert2['SubjectUserName'].value_counts())
print()
print("Process names flagged:")
print(alert2['NewProcessName'].value_counts())
print()

alert2_clean = pd.DataFrame({
    'alert_type': "Suspicious Short-Lived Tool",
    'account': alert2['SubjectUserName'],
    'timestamp': alert2['@timestamp'],
    'reason': "Short-lived process execution: " + alert2['NewProcessName'],
    'severity': alert2['NewProcessName'].isin(HIGH_SEVERITY_TOOLS).map({True: 'High', False: 'Medium'})
})

# ---------------------------------------------------------------
# ALERT 3: Suspicious Spawn
# Office app -> shell, or svchost.exe with wrong parent (Chapter 5)
# ---------------------------------------------------------------
alert3 = proc[
    (proc['suspicious_office_spawn'] == True) |
    (proc['suspicious_svchost'] == True)
].copy()

print(f"Alert 3 - Suspicious Spawn: {len(alert3)} processes")
print()

alert3_clean = pd.DataFrame({
    'alert_type': "Suspicious Spawn",
    'account': alert3['SubjectUserName'],
    'timestamp': alert3['@timestamp'],
    'reason': "Suspicious process spawn pattern",
    'severity': "Medium"
})

# ---------------------------------------------------------------
# COMBINE AND SAVE
# ---------------------------------------------------------------
all_alerts = pd.concat([alert1_clean, alert2_clean, alert3_clean], ignore_index=True)
all_alerts = all_alerts.sort_values('timestamp').reset_index(drop=True)
all_alerts.to_csv("alerts.csv", index=False)

print("=== Final Alert Summary ===")
print(all_alerts['alert_type'].value_counts())
print()
print(all_alerts['severity'].value_counts())
print(f"\nTotal alerts saved: {len(all_alerts)}")
