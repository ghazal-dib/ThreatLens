"""
Exploratory Data Analysis for the APT29 threat hunting project.

Reads features_logons.csv and features_processes.csv and produces:
  1. logon_type_distribution.png - bar chart of logon types, split by elevated/not
  2. pbeesly_timeline.png        - timeline of the pbeesly account's logons
  3. process_duration_hist.png   - histogram of process durations (log scale)

Also prints a short text summary of key numbers for each chart.
"""

import pandas as pd
import matplotlib
matplotlib.use("Agg")  # write straight to file, no display window needed
import matplotlib.pyplot as plt

# ---------------------------------------------------------------
# LOAD DATA
# ---------------------------------------------------------------
logons = pd.read_csv("features_logons.csv")
proc = pd.read_csv("features_processes.csv")

logons['@timestamp'] = pd.to_datetime(logons['@timestamp'])
proc['@timestamp'] = pd.to_datetime(proc['@timestamp'])

# ---------------------------------------------------------------
# CHART 1: Logon type distribution, split by elevated / not elevated
# ---------------------------------------------------------------
counts = logons.groupby(['LogonType', 'was_elevated']).size().unstack(fill_value=0)

ax = counts.plot(kind='bar', stacked=True, figsize=(8, 5),
                  color=['#4472C4', '#C00000'])
ax.set_title('Logon Type Distribution (split by elevated privilege)')
ax.set_xlabel('Logon Type (3=Network, 5=Service, 2=Interactive, 10=RDP)')
ax.set_ylabel('Number of Logons')
ax.legend(['Not Elevated', 'Elevated'])
plt.tight_layout()
plt.savefig('logon_type_distribution.png', dpi=150)
plt.close()

print("=== Chart 1: Logon Type Distribution ===")
print(counts)
print()

# ---------------------------------------------------------------
# CHART 2: pbeesly logon timeline
# ---------------------------------------------------------------
pbeesly = logons[logons['TargetUserName'] == 'pbeesly'].sort_values('@timestamp')

if len(pbeesly) > 0:
    fig, ax = plt.subplots(figsize=(10, 4))
    colors = pbeesly['is_remote_logon'].map({True: '#C00000', False: '#4472C4'})
    ax.scatter(pbeesly['@timestamp'], [1] * len(pbeesly), c=colors, s=80, zorder=3)
    ax.set_yticks([])
    ax.set_title(f"pbeesly Logon Timeline ({len(pbeesly)} events) - red = remote logon")
    ax.set_xlabel('Time')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('pbeesly_timeline.png', dpi=150)
    plt.close()

    span = (pbeesly['@timestamp'].max() - pbeesly['@timestamp'].min()).total_seconds() / 60
    print("=== Chart 2: pbeesly Timeline ===")
    print(f"Total pbeesly logons: {len(pbeesly)}")
    print(f"Time span: {span:.1f} minutes")
    print(f"Remote logons: {pbeesly['is_remote_logon'].sum()}")
    print(f"Distinct source IPs: {pbeesly['IpAddress'].nunique()}")
    print(f"Source IP values: {pbeesly['IpAddress'].unique().tolist()}")
else:
    print("=== Chart 2: pbeesly Timeline ===")
    print("No pbeesly logons found.")
print()

# ---------------------------------------------------------------
# CHART 3: Process duration histogram
# ---------------------------------------------------------------
durations = proc['duration_seconds'].dropna()
durations = durations[durations >= 0]  # safety: drop any negative artifacts

fig, ax = plt.subplots(figsize=(8, 5))
ax.hist(durations, bins=30, color='#4472C4', edgecolor='white')
ax.set_title('Process Duration Distribution (Event ID 4688 -> 4689)')
ax.set_xlabel('Duration (seconds)')
ax.set_ylabel('Number of Processes')
plt.tight_layout()
plt.savefig('process_duration_hist.png', dpi=150)
plt.close()

print("=== Chart 3: Process Duration ===")
print(f"Processes with measured duration: {len(durations)}")
print(durations.describe())
print()
print("Shortest-lived processes (top 5):")
short = proc[(proc['duration_seconds'].notna()) & (proc['duration_seconds'] >= 0)].nsmallest(5, 'duration_seconds')
print(short[['NewProcessName', 'ParentProcessNameOnly', 'duration_seconds']].to_string(index=False))

print("\nSaved: logon_type_distribution.png, pbeesly_timeline.png, process_duration_hist.png")

# ---------------------------------------------------------------
# CHART 4: pbeesly logon type distribution (New Added Chart)
# ---------------------------------------------------------------
pbeesly_counts = logons[logons['TargetUserName'] == 'pbeesly']['LogonType'].value_counts()

if len(pbeesly_counts) > 0:
    fig, ax = plt.subplots(figsize=(6, 4))
    pbeesly_counts.plot(kind='bar', color='#C00000', ax=ax)
    ax.set_title('pbeesly Logon Type Distribution')
    ax.set_xlabel('Logon Type (3=Network, 2=Interactive, 10=RDP)')
    ax.set_ylabel('Count')
    plt.tight_layout()
    plt.savefig('pbeesly_logontype.png', dpi=150)
    plt.close()
    
    print("=== Chart 4: pbeesly Logon Type ===")
    print(pbeesly_counts)
    print()

print("\nSaved ALL: logon_type_distribution.png, pbeesly_timeline.png, process_duration_hist.png, pbeesly_logontype.png")
