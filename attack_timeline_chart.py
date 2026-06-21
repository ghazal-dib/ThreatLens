"""
Builds attack_timeline.png - a single chart combining all three stages
of the pbeesly attack narrative onto one time axis:
  1. The RTLO-disguised screensaver execution (initial access)
  2. The 15 lateral movement logon alerts
  3. The 13 suspicious short-lived tool execution alerts

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
# THREE EVENT SETS
# ---------------------------------------------------------------
screensaver = proc_scored[
    proc_scored['NewProcessName'].str.contains('scr', case=False, na=False)
    & (proc_scored['SubjectUserName'] == 'pbeesly')
]

lateral_movement = alerts[alerts['alert_type'] == 'Lateral Movement']
suspicious_tools = alerts[alerts['alert_type'] == 'Suspicious Short-Lived Tool']

# ---------------------------------------------------------------
# PLOT
# ---------------------------------------------------------------
fig, ax = plt.subplots(figsize=(12, 4.5))

ax.scatter(lateral_movement['timestamp'], [1] * len(lateral_movement),
           color='#C00000', s=110, zorder=3, label=f'Lateral Movement ({len(lateral_movement)})')

ax.scatter(suspicious_tools['timestamp'], [1] * len(suspicious_tools),
           color='#ED7D31', s=110, zorder=3, marker='^',
           label=f'Suspicious Short-Lived Tool ({len(suspicious_tools)})')

ax.scatter(screensaver['@timestamp'], [1] * len(screensaver),
           color='#000000', s=260, zorder=4, marker='*',
           label=f'Initial Access - RTLO Screensaver ({len(screensaver)})')

# Annotate the screensaver point specifically, since it's the single
# most important event and shouldn't just look like "one more dot"
for _, row in screensaver.iterrows():
    ax.annotate(
        'Initial Access\nexplorer.exe -> [RTLO]cod.3aka3.scr',
        xy=(row['@timestamp'], 1),
        xytext=(0, 35), textcoords='offset points',
        ha='center', fontsize=9, fontweight='bold',
        arrowprops=dict(arrowstyle='->', color='black')
    )

ax.set_yticks([])
ax.set_ylim(0.7, 1.6)
ax.set_xlabel('Time (UTC)')
ax.set_title('pbeesly Attack Timeline: Initial Access -> Lateral Movement -> Anti-Forensics',
             fontsize=13, fontweight='bold')

ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
plt.xticks(rotation=30)

ax.legend(loc='upper left', framealpha=0.95)
ax.grid(axis='x', alpha=0.3)

plt.tight_layout()
plt.savefig('attack_timeline.png', dpi=150)
plt.close()

print(f"Screensaver events: {len(screensaver)}")
print(f"Lateral movement events: {len(lateral_movement)}")
print(f"Suspicious tool events: {len(suspicious_tools)}")
print("Saved attack_timeline.png")
