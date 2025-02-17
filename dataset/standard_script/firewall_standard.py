import os
import re
import numpy as np
import pandas as pd
from config import MITRE_MAPPING,MITRE_SIGNATURE_MAPPING,STANDARD_COLUMNS


#  Function: Convert Various Timestamp Formats to Epoch Time
def convert_to_epoch(series):
    """Converts timestamps into epoch time (seconds)."""
    def parse_time(value):
        if pd.isna(value) or value in ["", "null", "None"]:
            return np.nan
        if isinstance(value, (int, float)):
            return int(pd.to_datetime(value, unit="s", utc=True).timestamp())
        if isinstance(value, str):
            try:
                return int(pd.to_datetime(value, utc=True).timestamp())
            except Exception:
                return np.nan
        return np.nan
    return series.apply(parse_time)

#  Function: Extract Text Inside Double Quotes from `message`
def extract_quoted_text(text):
    """Extracts only the content between double quotes in a given text."""
    if not isinstance(text, str):
        return "Unknown"
    matches = re.findall(r'"(.*?)"', text)  
    return ", ".join(matches) if matches else "Unknown"

#  Function: Map Log Data to MITRE ATT&CK TTPs
def map_ttps_from_log(log_data):
    """Maps log data to MITRE ATT&CK TTPs using regex matching."""
    detected_ttps = set()
    if not isinstance(log_data, str):
        return "Unknown"
    for ttp, pattern in MITRE_MAPPING.items():
        if re.search(pattern, log_data, re.IGNORECASE):
            detected_ttps.add(ttp)
    return ",".join(detected_ttps) if detected_ttps else "Unknown"

#  Function: Map Signature-Based TTPs
def map_ttps_from_signature(signature):
    """Maps firewall signatures to MITRE ATT&CK TTPs."""
    detected_ttps = set()
    if not isinstance(signature, str):
        return "Unknown"
    for ttp, pattern in MITRE_SIGNATURE_MAPPING.items():
        if re.search(pattern, signature, re.IGNORECASE):
            detected_ttps.add(ttp)
    return ",".join(detected_ttps) if detected_ttps else "Unknown"

#  Function: Process Firewall Logs
def process_firewall_log(df):
    """Processes firewall logs to extract important features for attack detection."""
    required_columns = ["eventdate", "src_ip", "dst_ip", "src_port", "dst_port", "application",
                        "signature", "id_signature", "message", "src_user", "dst_user",
                        "src_zone", "dst_zone", "action", "log_type"]
    
    for col in required_columns:
        if col not in df.columns:
            df[col] = "Unknown"

    # Convert timestamp
    df["timestamp"] = convert_to_epoch(df["eventdate"])

    # Extract the text inside double quotes from `message`

    df["message"] = df["message"].apply(extract_quoted_text)
    df["threat_name"] = df["signature"].fillna(df["id_signature"]).fillna(df["message"])
    

    df["log_type"] = "firewall"
    df["source_ip"] = df["src_ip"]
    df["destination_ip"] = df["dst_ip"]
    df["action"] = df["action"]
    df["user"] = df["src_user"]
    df["protocol"] = df["application"]
    df["port"] = df["dst_port"]

    # Apply TTP Mapping
    df["ttp_from_log"] = df.apply(lambda row: map_ttps_from_log(row["protocol"] + " " + row["action"]), axis=1)
    df["ttp_from_signature"] = df["threat_name"].apply(map_ttps_from_signature)

    # Combine TTP detections
    df["ttp_detected"] = df.apply(
        lambda row: ",".join(set(filter(lambda x: x != "Unknown", [row["ttp_from_log"], row["ttp_from_signature"]])))
        if row["ttp_from_log"] != "Unknown" or row["ttp_from_signature"] != "Unknown"
        else "Unknown",
        axis=1
    )

    return df[STANDARD_COLUMNS]

#  Function: Process and Save Logs
def process_logs():
    directory = "Datasets/raw/firewall_attack_chunks"
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        try:
            df = pd.read_csv(filepath, low_memory=False).rename(columns=lambda x: x.strip())
            df = process_firewall_log(df)
            df.to_csv("Datasets/processed/firewall_logs.csv", index=False, mode="a")
        except Exception as e:
            print(f"Error processing {filename}: {e}")

#  Run Processing
if __name__ == "__main__":
    process_logs()
