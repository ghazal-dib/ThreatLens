
import pandas as pd
import streamlit as st

st.set_page_config(page_title="APT29 Threat Hunting & ML Detection Dashboard", layout="wide")

st.markdown("""
<style>
html, body, [class*="css"] { font-size: 20px; }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------
# DATA LOADING
# Split into two separate cached functions, each returning a single
# DataFrame. Uses @st.cache_data - the legacy @st.cache API used here
# previously was removed in current Streamlit releases, so this would
# have crashed on import for anyone running a modern `pip install streamlit`.
# ---------------------------------------------------------------
@st.cache
def load_alerts():
    return pd.read_csv("alerts.csv")

@st.cache
def load_ml_alerts():
    return pd.read_csv("ml_alerts.csv")

alerts_df = load_alerts()
ml_alerts_df = load_ml_alerts()

def style_severity(df):
    """Color-code rows by severity: red tint for High, orange tint for Medium."""
    def highlight(row):
        if row.get("severity") == "High":
            return ['background-color: #FFE0E0'] * len(row)
        elif row.get("severity") == "Medium":
            return ['background-color: #FFF3E0'] * len(row)
        return [''] * len(row)
    return df.style.apply(highlight, axis=1)

st.title("APT29 Threat Hunting & ML Detection Dashboard")
st.caption("Rule-based detection + Isolation Forest anomaly detection on the APT29 Mordor Day 1 dataset")

section = st.radio("Go to:", ["EDA", "Rule-Based Alerts", "ML Anomalies", "Key Finding"])

# ---------------------------------------------------------------
# SECTION: EDA
# ---------------------------------------------------------------
if section == "EDA":
    st.subheader("Exploratory Data Analysis")
    col1, col2 = st.columns(2)
    with col1:
        st.image("logon_type_distribution.png", caption="Logon Type Distribution")
        st.image("pbeesly_timeline.png", caption="pbeesly Logon Timeline")
    with col2:
        st.image("process_duration_hist.png", caption="Process Duration Distribution")
        st.image("pbeesly_logontype.png", caption="pbeesly Logon Type Distribution")

# ---------------------------------------------------------------
# SECTION: Rule-Based Alerts
# ---------------------------------------------------------------
elif section == "Rule-Based Alerts":
    st.subheader("Rule-Based Alerts")
    choice = st.selectbox("Filter by Severity", ["All", "High", "Medium"])
    if choice == "All":
        filtered = alerts_df
    else:
        filtered = alerts_df[alerts_df["severity"] == choice]
    st.write(f"Showing {len(filtered)} of {len(alerts_df)} alerts")
    st.dataframe(style_severity(filtered))

# ---------------------------------------------------------------
# SECTION: ML Anomalies
# ---------------------------------------------------------------
elif section == "ML Anomalies":
    st.subheader("ML-Flagged Anomalies (Isolation Forest)")
    st.write(f"Total anomalies across both models: {len(ml_alerts_df)}")

    # Split into two clean sub-tables instead of one merged table,
    # since logon and process anomalies have mostly different columns -
    # merging them produces a wide table full of <NA> values either way.
    logon_anom = ml_alerts_df[ml_alerts_df["detection_source"] == "logon_anomaly"]
    proc_anom = ml_alerts_df[ml_alerts_df["detection_source"] == "proc_anomaly"]

    LOGON_COLS = ["TargetUserName", "@timestamp", "LogonType", "is_remote_logon",
                  "was_elevated", "WorkstationName", "IpAddress", "anomaly_score"]
    PROC_COLS = ["SubjectUserName", "@timestamp", "NewProcessName", "ParentProcessNameOnly",
                 "duration_seconds", "pair_frequency", "anomaly_score"]

    st.markdown(f"**Logon Anomalies** ({len(logon_anom)})")
    st.dataframe(logon_anom[LOGON_COLS].sort_values("anomaly_score"))

    st.markdown(f"**Process Anomalies** ({len(proc_anom)})")
    st.dataframe(proc_anom[PROC_COLS].sort_values("anomaly_score"))

# ---------------------------------------------------------------
# SECTION: Key Finding
# ---------------------------------------------------------------
elif section == "Key Finding":
    st.image("attack_timeline.png", use_column_width=True)

    st.subheader("Logons")
    col1, col2 = st.columns(2)
    with col1:
        st.metric(label="% of all events", value="10.1%")
    with col2:
        st.metric(label="% of flagged anomalies", value="55.6%")

    st.subheader("Processes")
    col1, col2 = st.columns(2)
    with col1:
        st.metric(label="% of all events", value="16.0%")
    with col2:
        st.metric(label="% of flagged anomalies", value="21.3%")

    st.markdown("""
### The Discovery

At **02:55:57**, `explorer.exe` spawned a process disguised using a Unicode
**RIGHT-TO-LEFT OVERRIDE** character (U+202E) — a known technique ("RTLO
spoofing") that makes a malicious `.scr` executable visually appear to end
in a harmless extension. The process ran from a `ProgramData` directory
for 330 seconds.

This exact parent-child pairing — `explorer.exe` → `[RTLO]cod.3aka3.scr` —
occurred only **once** across all 307 measured process executions. No rule
was written to catch it; an Isolation Forest model flagged it anyway,
based purely on how rare that pairing was.

### The Lateral Movement Window

Between **03:04:05 and 03:20:49** (16.7 minutes), `pbeesly` generated
**30 logon events** across three logon types — Network, Interactive, and
RDP — from 4 distinct source locations, including `172.18.39.2`,
`10.0.1.4`, and `10.0.1.6`. Fifteen of these sessions were both remote
*and* privilege-elevated, triggering High-severity lateral movement alerts.

Interleaved with these logons, **13 short-lived processes** (each under
1 second) executed, including three runs of `sdelete64.exe`
(anti-forensics / secure deletion), paired runs of `sdclt.exe` and
`cvtres.exe`, and single executions of `control.exe`, `csc.exe`,
`powershell.exe`, and `rar.exe` — consistent with compile-on-target
execution followed by evidence destruction.

### Why This Matters

The Isolation Forest model was given no rules, labels, or knowledge of
which account to watch — only numeric features (logon type, remote/elevated
flags, process duration, and a custom "parent-child pairing rarity"
feature). It surfaced `pbeesly` as anomalous anyway, **before** any rule
existed to flag the RTLO technique specifically. That's the core argument
for running both detection layers together: rules give clear, auditable
reasoning; ML catches what the rules don't yet know to look for.
""")

    st.subheader("Detection Summary")
    results_summary = pd.DataFrame({
        "Metric": ["Rule-based alerts (total)", "— Lateral Movement", "— Suspicious Short-Lived Tool", "ML anomalies (total)"],
        "Count": [28, 15, 13, 107]
    })
    st.table(results_summary)

    st.subheader("Evidence: pbeesly Records")

    st.markdown("**Most significant alerts** (curated)")
    pbeesly_alerts_all = alerts_df[alerts_df["account"] == "pbeesly"]
    sdelete_rows = pbeesly_alerts_all[pbeesly_alerts_all["reason"].str.contains("sdelete64", na=False)]
    lateral_sample = pbeesly_alerts_all[pbeesly_alerts_all["alert_type"] == "Lateral Movement"].head(3)
    curated = pd.concat([sdelete_rows, lateral_sample]).sort_values("timestamp")
    st.dataframe(style_severity(curated))

    st.markdown("**All rule-based alerts for pbeesly**")
    st.dataframe(style_severity(pbeesly_alerts_all))

    st.markdown("**ML-flagged anomalies**")
    pbeesly_ml = ml_alerts_df[
        (ml_alerts_df["SubjectUserName"] == "pbeesly") |
        (ml_alerts_df["TargetUserName"] == "pbeesly")
    ]
    pbeesly_ml_logons = pbeesly_ml[pbeesly_ml["detection_source"] == "logon_anomaly"]
    pbeesly_ml_proc = pbeesly_ml[pbeesly_ml["detection_source"] == "proc_anomaly"]

    LOGON_COLS = ["TargetUserName", "@timestamp", "LogonType", "is_remote_logon",
                  "was_elevated", "WorkstationName", "IpAddress", "anomaly_score"]
    PROC_COLS = ["SubjectUserName", "@timestamp", "NewProcessName", "ParentProcessNameOnly",
                 "duration_seconds", "pair_frequency", "anomaly_score"]

    st.caption(f"Logon anomalies ({len(pbeesly_ml_logons)})")
    st.dataframe(pbeesly_ml_logons[LOGON_COLS])

    st.caption(f"Process anomalies ({len(pbeesly_ml_proc)})")
    st.dataframe(pbeesly_ml_proc[PROC_COLS])
