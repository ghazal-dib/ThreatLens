"""
Rule-based alert engine for the APT29 threat hunting project.

Applies five detection rules, each tied directly to a known attacker
behavior pattern. Each rule is a standalone function that takes a
DataFrame and returns a DataFrame of alerts - this makes them unit
testable (see tests/test_alert_rules.py) independent of any CSV file
or dataset.

  Alert 1 - Lateral Movement:
      A logon session that is BOTH remote (Type 3/10) AND was granted
      elevated privileges, excluding machine accounts ($) which always
      carry elevated tokens by design and are not attacker-controlled.

  Alert 2 - Suspicious Short-Lived Tool:
      A process that ran for under 1 second, excluding machine accounts,
      built-in service accounts, and conhost.exe (which is near-automatic
      noise spawned by almost any console tool, so excluding it lets
      genuinely interesting short-lived tools stand out).

      NOTE on rar.exe: currently scored Medium, same as every other tool
      in this rule. rar.exe is sometimes used for data staging before
      exfiltration and some SOC teams would rate it High - left as
      Medium here since, on its own, archiving a file is far more
      commonly legitimate than e.g. running an anti-forensics tool.
      Bump ARCHIVE_TOOLS below into ANTI_FORENSICS_TOOLS-style High
      treatment if your environment's threat model calls for it.

  Alert 3 - Suspicious Spawn:
      A process creation matching the "weaponized Office document" or
      "svchost.exe hiding in plain sight" patterns from Chapter 5.

  Alert 4 - Anti-Forensics Tool:
      Presence of a known evidence-destruction tool (e.g. sdelete),
      regardless of how long it ran. This is intentionally NOT folded
      into Alert 2's duration filter: wiping a larger file legitimately
      takes longer than 1 second, but the tool's presence is the signal,
      not its speed. Gating this on duration previously caused several
      real sdelete64.exe runs to be missed or under-classified.

  Alert 5 - Obfuscated Command Execution:
      A PowerShell invocation using classic obfuscation/staging flags
      (-enc / -EncodedCommand, hidden window, FromBase64String, -nop).
      Presence-based like Alert 4 - this matters because the one
      obfuscated PowerShell command in this dataset has NO matching
      process-exit event, so it was previously invisible to every
      duration-dependent rule and the ML process model entirely.

SEVERITY RATIONALE (why some alerts are High vs Medium):
  High   = the behavior is dangerous on its own, with no need for extra
           context - a remote+elevated logon enables lateral movement
           regardless of who triggers it, and an anti-forensics tool
           running on ANY host means evidence is actively being
           destroyed, not "possibly suspicious."
  Medium = the behavior is unusual but only meaningful in combination
           with other evidence - a short-lived process or an odd parent
           process is a useful lead, not proof, on its own.

Running this file as a script reads features_logons.csv and
features_processes.csv, applies all five rules, and writes alerts.csv
with columns: alert_type, account, timestamp, reason, severity
"""

import pandas as pd

# Tools whose mere presence is a High-severity signal regardless of
# duration (anti-forensics / evidence destruction). Handled by Alert 4,
# not Alert 2, since duration is not a meaningful filter for these.
ANTI_FORENSICS_TOOLS = ['sdelete64.exe', 'sdelete.exe']

# Classic PowerShell obfuscation/staging indicators (Alert 5)
OBFUSCATION_PATTERNS = r'-enc\b|-encodedcommand|frombase64string|-w(?:indowstyle)?\s+hidden|-nop\b'


def detect_lateral_movement(logons: pd.DataFrame) -> pd.DataFrame:
    """Alert 1: remote + elevated logon, excluding machine accounts."""
    hits = logons[
        (logons['is_remote_logon'] == True) &
        (logons['was_elevated'] == True) &
        (~logons['TargetUserName'].str.endswith('$'))
    ].copy()
    return pd.DataFrame({
        'alert_type': "Lateral Movement",
        'account': hits['TargetUserName'],
        'timestamp': hits['@timestamp'],
        'reason': "Remote logon with elevated privileges",
        'severity': "High"
    })


def detect_short_lived_tool(proc: pd.DataFrame) -> pd.DataFrame:
    """Alert 2: process ran < 1s, excluding noise and anti-forensics tools
    (which Alert 4 handles without a duration gate)."""
    hits = proc[
        (proc['duration_seconds'] >= 0) &
        (proc['duration_seconds'] < 1) &
        (~proc['SubjectUserName'].str.endswith('$')) &
        (proc['SubjectUserName'] != 'LOCAL SERVICE') &
        (proc['NewProcessName'] != 'conhost.exe') &
        (~proc['NewProcessName'].isin(ANTI_FORENSICS_TOOLS))
    ].copy()
    return pd.DataFrame({
        'alert_type': "Suspicious Short-Lived Tool",
        'account': hits['SubjectUserName'],
        'timestamp': hits['@timestamp'],
        'reason': "Short-lived process execution: " + hits['NewProcessName'],
        'severity': "Medium"
    })


def detect_suspicious_spawn(proc: pd.DataFrame) -> pd.DataFrame:
    """Alert 3: Office app -> shell, or svchost.exe with the wrong parent."""
    hits = proc[
        (proc['suspicious_office_spawn'] == True) |
        (proc['suspicious_svchost'] == True)
    ].copy()
    reason = hits['suspicious_office_spawn'].map({
        True: "Office application spawned a shell/scripting process"
    }).fillna("svchost.exe spawned by a process other than services.exe")
    return pd.DataFrame({
        'alert_type': "Suspicious Spawn",
        'account': hits['SubjectUserName'],
        'timestamp': hits['@timestamp'],
        'reason': reason,
        'severity': "Medium"
    })


def detect_anti_forensics(proc: pd.DataFrame) -> pd.DataFrame:
    """Alert 4: presence of a known evidence-destruction tool, any duration."""
    hits = proc[proc['NewProcessName'].isin(ANTI_FORENSICS_TOOLS)].copy()
    return pd.DataFrame({
        'alert_type': "Anti-Forensics Tool",
        'account': hits['SubjectUserName'],
        'timestamp': hits['@timestamp'],
        'reason': "Evidence-destruction tool executed: " + hits['NewProcessName'],
        'severity': "High"
    })


def detect_obfuscated_command(proc: pd.DataFrame) -> pd.DataFrame:
    """Alert 5: PowerShell with encoding/staging flags, any duration.

    Expects an 'obfuscated_command' boolean column already computed by
    feature_engineering.py. If it isn't present, computes it inline so
    this function still works against a bare features_processes.csv.
    """
    if 'obfuscated_command' not in proc.columns:
        flagged = (
            proc['NewProcessName'].isin(['powershell.exe', 'powershell_ise.exe']) &
            proc['CommandLine'].str.contains(OBFUSCATION_PATTERNS, case=False, regex=True, na=False)
        )
    else:
        flagged = proc['obfuscated_command'] == True
    hits = proc[flagged].copy()
    return pd.DataFrame({
        'alert_type': "Obfuscated Command Execution",
        'account': hits['SubjectUserName'],
        'timestamp': hits['@timestamp'],
        'reason': "PowerShell launched with encoding/staging flags",
        'severity': "High"
    })


def run_all_rules(logons: pd.DataFrame, proc: pd.DataFrame) -> pd.DataFrame:
    """Apply all five rules and return one combined, time-sorted alert table."""
    all_alerts = pd.concat([
        detect_lateral_movement(logons),
        detect_short_lived_tool(proc),
        detect_suspicious_spawn(proc),
        detect_anti_forensics(proc),
        detect_obfuscated_command(proc),
    ], ignore_index=True)
    return all_alerts.sort_values('timestamp').reset_index(drop=True)


if __name__ == "__main__":
    logons = pd.read_csv("features_logons.csv")
    proc = pd.read_csv("features_processes.csv")

    all_alerts = run_all_rules(logons, proc)
    all_alerts.to_csv("alerts.csv", index=False, encoding="utf-8")

    print("=== Final Alert Summary ===")
    print(all_alerts['alert_type'].value_counts())
    print()
    print(all_alerts['severity'].value_counts())
    print(f"\nTotal alerts saved: {len(all_alerts)}")
