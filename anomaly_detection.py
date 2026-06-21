"""
Stage 5 - Isolation Forest anomaly detection for the APT29 threat hunting project.
 
Two separate models, matching the two event domains from Stages 1-4:
 
  Forest #1 (Logons): looks at LogonType, is_remote_logon, was_elevated
      to find logon sessions that are statistically unusual.
 
  Forest #2 (Processes): looks at duration_seconds, suspicious_office_spawn,
      suspicious_svchost, AND the new pair_frequency feature - how rare
      this process's (parent -> child) relationship is across the whole
      dataset. This gives the model a second real signal beyond duration,
      since the two suspicious_* flags are always 0 in this dataset slice
      and contribute no variance on their own.
 
Outputs:
  features_logons_scored.csv / features_processes_scored.csv - full data + anomaly_score
  ml_alerts.csv - just the flagged anomalies from both forests, combined
"""
 
import pandas as pd
from sklearn.ensemble import IsolationForest
 
# ---------------------------------------------------------------
# LOAD DATA
# ---------------------------------------------------------------
logons = pd.read_csv("features_logons.csv")
proc = pd.read_csv("features_processes.csv") 
# ---------------------------------------------------------------
# NEW FEATURE: pair_frequency
# How many times does this exact (parent -> child) process
# relationship occur across the whole dataset? Rare pairs (low count)
# are statistically unusual even when duration looks normal.
# ---------------------------------------------------------------
proc['pair_key'] = proc['ParentProcessNameOnly'] + ' -> ' + proc['NewProcessName']
pair_counts = proc['pair_key'].value_counts()
proc['pair_frequency'] = proc['pair_key'].map(pair_counts)
 
# ---------------------------------------------------------------
# FOREST #1: Logons
# ---------------------------------------------------------------
X_logons = logons[['LogonType', 'is_remote_logon', 'was_elevated']]
 
model_logons = IsolationForest(random_state=42)
logons['anomaly_score'] = model_logons.fit_predict(X_logons)
 
print("=== Forest #1: Logon Anomalies ===")
print(logons['anomaly_score'].value_counts())
print()
 
anomalous_logons = logons[logons['anomaly_score'] == -1].copy()
print("Flagged accounts (count):")
print(anomalous_logons['TargetUserName'].value_counts())
print()
print("Baseline share of all logons (for comparison):")
print(logons['TargetUserName'].value_counts(normalize=True).head(10))
print()
 
# ---------------------------------------------------------------
# FOREST #2: Processes
# Now using 4 features instead of 3 - pair_frequency adds real signal
# since the two suspicious_* flags have zero variance in this dataset
# ---------------------------------------------------------------
X_proc = proc[['duration_seconds', 'suspicious_office_spawn',
               'suspicious_svchost', 'pair_frequency']]
 
model_proc = IsolationForest(random_state=42)
proc['anomaly_score'] = model_proc.fit_predict(X_proc)
 
print("=== Forest #2: Process Anomalies ===")
print(proc['anomaly_score'].value_counts())
print()
 
anomalous_proc = proc[proc['anomaly_score'] == -1].copy()
print("Flagged accounts (count):")
print(anomalous_proc['SubjectUserName'].value_counts())
print()
print("Baseline share of all processes (for comparison):")
print(proc['SubjectUserName'].value_counts(normalize=True).head(10))
print()
 
print("Rarest flagged process pairs:")
print(anomalous_proc[['ParentProcessNameOnly', 'NewProcessName', 'pair_frequency', 'duration_seconds']]
      .sort_values('pair_frequency').head(10).to_string(index=False))
print()
 
# ---------------------------------------------------------------
# SAVE SCORED FULL DATASETS
# ---------------------------------------------------------------
logons.to_csv("features_logons_scored.csv", index=False)
proc.to_csv("features_processes_scored.csv", index=False)
 
# ---------------------------------------------------------------
# BUILD ml_alerts.csv
# ---------------------------------------------------------------
anomalous_logons['detection_source'] = 'logon_anomaly'
anomalous_proc['detection_source'] = 'proc_anomaly'
 
ml_alerts = pd.concat([anomalous_logons, anomalous_proc], ignore_index=True, sort=False)
ml_alerts.to_csv("ml_alerts.csv", index=False)
scr_alert = ml_alerts[ml_alerts['NewProcessName'] == 'â€®cod.3aka3.scr']
print(scr_alert.to_string())
print(f"Saved features_logons_scored.csv, features_processes_scored.csv, ml_alerts.csv")
print(f"Total ML-flagged anomalies: {len(ml_alerts)}")
 
