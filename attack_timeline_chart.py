"""
Builds attack_timeline.png - a single chart combining all four stages
of the pbeesly attack narrative onto one time axis:
  1. The RTLO-disguised screensaver execution (initial access)
  2. The 15 lateral movement logon alerts
  3. The 6 anti-forensics tool (sdelete64.exe) executions
  4. The 2 obfuscated/encoded PowerShell command executions
  (plus the 8 lower-signal suspicious short-lived tool alerts, shown
  as supporting noise rather than a separate narrative stage)

Run from the same folder as alerts.csv and features_processes_scored.csv.
"""

import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.dates as mdates

# ---------------------------------------------------------------
# LOAD DATA
# ---------------------------------------------------------------
alerts = pd.read_csv("alerts.csv")
alerts['timestamp'] = pd.to_datetime(alerts['timestamp'])

proc_scored = pd.read_csv("features_processes_scored.csv")
proc_scored['@timestamp'] = pd.to_datetime(proc_scored['@timestamp'])

# ---------------------------------------------------------------
# EVENT SETS
# ---------------------------------------------------------------
screensaver = proc_scored[
    proc_scored['NewProcessName'].str.contains('scr', case=False, na=False)
    & (proc_scored['SubjectUserName'] == 'pbeesly')
]

lateral_movement = alerts[alerts['alert_type'] == 'Lateral Movement']
suspicious_tools = alerts[alerts['alert_type'] == 'Suspicious Short-Lived Tool']
anti_forensics = alerts[alerts['alert_type'] == 'Anti-Forensics Tool']
obfuscated_cmd = alerts[alerts['alert_type'] == 'Obfuscated Command Execution']

# ---------------------------------------------------------------
# PLOT
# ---------------------------------------------------------------
fig, ax = plt.subplots(figsize=(13, 4.5))

ax.scatter(suspicious_tools['timestamp'], [1] * len(suspicious_tools),
           color='#ED7D31', s=90, zorder=2, marker='^', alpha=0.7,
           label=f'Suspicious Short-Lived Tool ({len(suspicious_tools)})')

ax.scatter(lateral_movement['timestamp'], [1] * len(lateral_movement),
           color='#C00000', s=110, zorder=3, label=f'Lateral Movement ({len(lateral_movement)})')

ax.scatter(anti_forensics['timestamp'], [1] * len(anti_forensics),
           color='#7030A0', s=130, zorder=3, marker='s',
           label=f'Anti-Forensics Tool ({len(anti_forensics)})')

ax.scatter(obfuscated_cmd['timestamp'], [1] * len(obfuscated_cmd),
           color='#1F77B4', s=150, zorder=4, marker='D',
           label=f'Obfuscated Command Execution ({len(obfuscated_cmd)})')

ax.scatter(screensaver['@timestamp'], [1] * len(screensaver),
           color='#000000', s=260, zorder=5, marker='*',
           label=f'Initial Access - RTLO Screensaver ({len(screensaver)})')

# Annotate the two single most important events specifically, since they
# shouldn't just look like "one more dot" among 31+ alerts
for _, row in screensaver.iterrows():
    ax.annotate(
        'Initial Access\nexplorer.exe -> [RTLO]cod.3aka3.scr',
        xy=(row['@timestamp'], 1),
        xytext=(0, 35), textcoords='offset points',
        ha='center', fontsize=9, fontweight='bold',
        arrowprops=dict(arrowstyle='->', color='black')
    )

if len(obfuscated_cmd) > 0:
    last_obf = obfuscated_cmd.sort_values('timestamp').iloc[-1]
    ax.annotate(
        'Fileless in-memory\nPowerShell loader',
        xy=(last_obf['timestamp'], 1),
        xytext=(15, -45), textcoords='offset points',
        ha='left', fontsize=9, fontweight='bold', color='#1F77B4',
        arrowprops=dict(arrowstyle='->', color='#1F77B4')
    )

ax.set_yticks([])
ax.set_ylim(0.55, 1.6)
ax.set_xlabel('Time (UTC) — 2020-05-02')
ax.set_title('pbeesly Attack Timeline: Initial Access -> Lateral Movement -> Anti-Forensics -> Obfuscated Execution',
             fontsize=12.5, fontweight='bold')

ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
plt.xticks(rotation=30)

ax.legend(loc='upper left', framealpha=0.95, fontsize=9)
ax.grid(axis='x', alpha=0.3)

plt.tight_layout()
plt.savefig('attack_timeline.png', dpi=150)
plt.close()

print(f"Screensaver events: {len(screensaver)}")
print(f"Lateral movement events: {len(lateral_movement)}")
print(f"Suspicious tool events: {len(suspicious_tools)}")
print(f"Anti-forensics events: {len(anti_forensics)}")
print(f"Obfuscated command events: {len(obfuscated_cmd)}")
print("Saved attack_timeline.png")
