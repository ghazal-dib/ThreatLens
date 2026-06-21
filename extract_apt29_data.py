"""
Extract Windows Security Event Log data from HELK's Elasticsearch
for the APT29 Mordor dataset (logs-apt29* index).

Pulls events for the Event IDs relevant to account login tracking
and process tracking, and saves them to a CSV for analysis in pandas.
"""

from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan
import pandas as pd

# --- CONFIGURATION -------------------------------------------------------
ES_HOST = "http://172.18.0.8:9200"
INDEX = "logs-apt29*"

EVENT_IDS = [4624, 4625, 4672, 4688, 4689, 4720, 4728, 4732, 4740]

# Final field list - confirmed to exist in this dataset
FIELDS = [
    "@timestamp", "EventID",
    "SubjectUserName", "TargetUserName",
    "SubjectLogonId", "TargetLogonId",
    "LogonType", "IpAddress", "WorkstationName",
    "Hostname", "host",
    "ProcessName", "ParentProcessName", "CommandLine",
    "ProcessId", "NewProcessId",
    "PrivilegeList"
]

# --- CONNECT --------------------------------------------------------------
es = Elasticsearch(ES_HOST)

print("Connected. Cluster info:")
print(es.info())

# --- QUERY ------------------------------------------------------------------
query = {
    "query": {
        "terms": {"EventID": EVENT_IDS}
    },
    "_source": FIELDS
}

print(f"\nPulling events for EventIDs {EVENT_IDS} from index '{INDEX}'...")

records = []
for hit in scan(es, index=INDEX, query=query, size=1000):
    records.append(hit["_source"])

print(f"Retrieved {len(records)} events")

# --- SAVE ---------------------------------------------------------------------
df = pd.DataFrame(records)
df.to_csv("apt29_events.csv", index=False)

print("\nEvent counts by EventID:")
print(df["EventID"].value_counts())

print("\nSaved to apt29_events.csv")
