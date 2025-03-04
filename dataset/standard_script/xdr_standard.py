import ast
import os
import re
import json
import pandas as pd
import numpy as np
from config import MITRE_XDR_MAPPING, STANDARD_COLUMNS

def convert_to_epoch(series):
    """Converts timestamps from various formats into epoch time (seconds)."""
    def parse_time(value):
        if pd.isna(value) or value in ["", "null", "None"]:
            return np.nan
        if isinstance(value, (int, float)):
            return int(value)
        if isinstance(value, str):
            try:
                return int(pd.to_datetime(value, utc=True).timestamp())
            except Exception:
                return np.nan
        return np.nan
    return series.apply(parse_time)

def extract_value(field, text):
    """
    Extracts a field value from JSON-like text. Handles integers, strings, and nested fields.
    """
    if not isinstance(text, str):
        return  "Unknown"
    try:
        data = json.loads(text.replace("'", "\"")) 
        return str(data.get(field, "Unknown"))
    except (json.JSONDecodeError, TypeError):
        pass  
    match = re.search(rf"'{field}':\s*(?:\[)?'([^']+)'", text)
    return match.group(1) if match else "Unknown"


def map_ttps_from_xdr(log_data):
    """Maps XDR log data to MITRE ATT&CK TTPs."""
    detected_ttps = set()
    if not isinstance(log_data, str):
        return "Unknown"
    for ttp, pattern in MITRE_XDR_MAPPING.items():
        if re.search(pattern, log_data, re.IGNORECASE):
            detected_ttps.add(ttp)
    return ",".join(detected_ttps) if detected_ttps else "Unknown"


def extract_xdr_fields(evento):
    """Extracts relevant fields from XDR logs."""
    if not isinstance(evento, str) or not evento.strip():
        return {
            "source_ip": "Unknown",
            "destination_ip": "Unknown",
            "user": "Unknown",
            "protocol": "Unknown",
            "port": None,
            "threat_name": "Unknown",
            "ttp_detected": "Unknown"
        }


    # Extract key fields
    source_ip = extract_value("host_ip", evento)
    if source_ip == "Unknown":
        source_ip = extract_value("host_name",evento)
    destination_ip = extract_value("action_remote_ip", evento)
    if destination_ip == "Unknown":
        destination_ip = extract_value("dst_agent_id",evento)
    user = extract_value("user_name", evento)
    protocol = extract_value("fw_app_id", evento)
    
    port = extract_value('action_local_port', evento) or extract_value('action_remote_port', evento)
    threat_name = extract_value("mitre_techniques_names", evento)
    if threat_name == "Unknown":
        threat_name = extract_value("mitre_tactics_names", evento)
    # mitre_tech = extract_value ("mitre_techniques", evento)
    # last_mitre_tech = extract_value ("", evento)
    # Extract MITRE ATT&CK TTPs
    # log_content = f"{mitre_tech} {action} {mitre_tactics} {threat_name}"
    # ttp_detected = map_ttps_from_xdr(log_content)

    return {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "user": user,
        "protocol": protocol,
        "port": port,
        "threat_name": threat_name
        # "ttp_detected": ttp_detected
    }


def parse_list(value):
    """
    Convert a value into a list.
    If it's already a list, return it.
    If it's a string representation of a list, use ast.literal_eval to parse it.
    Otherwise, wrap the value in a list.
    """
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        try:
            parsed = ast.literal_eval(value)
            if isinstance(parsed, list):
                return parsed
            else:
                return [parsed]
        except Exception:
            return [value]
    return []
    
def process_xdr_log(df):
    """Processes XDR logs and extracts critical features."""
    # Ensure required columns
    if "evento" not in df.columns or "_eventdate" not in df.columns:
        raise ValueError("Columns 'evento' or '_eventdate' are missing in the input DataFrame.")

    # Filter rows with non-null `_eventdate`
    df["_eventdate"].replace("", np.nan, inplace=True)
    df["action"].replace("", np.nan, inplace=True)
    df = df[df["_eventdate"].notna()].copy()
    df = df[df["action"].notna()].copy()

    # Extract fields
    extracted = df["evento"].apply(extract_xdr_fields)
    extracted_df = pd.DataFrame(extracted.tolist())

    df = df.reset_index(drop=True)
    extracted_df = extracted_df.reset_index(drop=True)
    # Combine extracted fields with the original DataFrame
    df = pd.concat([df, extracted_df], axis=1)


    # Convert timestamp to epoch
    df["timestamp"] = convert_to_epoch(df["_eventdate"])
    df["log_type"] = "xdr"
    
    # Concatenate MITRE-related columns into a list; if none exist, set to ["Unknown"]
    mitre_cols = ["mitre_techniques", "_last.mitre_techniques"]
    def concat_mitre(row):
        ttp_values = []
        for col in mitre_cols:
            if col in row and pd.notna(row[col]) and str(row[col]).strip() != "" and row[col] != "Unknown":
                values = parse_list(row[col])
                for v in values:
                    if v not in ttp_values:
                        ttp_values.append(v)
        return ttp_values if ttp_values else ["Unknown"]
    df["ttp_detected"] = df.apply(concat_mitre, axis=1)

 


    # Select and return standardized columns
    return df[STANDARD_COLUMNS]


def process_logs():
    """Processes all XDR logs in the specified directory."""
    directory = "Datasets/raw/xdr_alerts_attack_chunks"
    output_file = "Datasets/processed/xdr_logs.csv"

    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        try:
            df = pd.read_csv(filepath, low_memory=False).rename(columns=lambda x: x.strip())
            df = process_xdr_log(df)
            df.to_csv(output_file, index=False, mode="a")
            print(f"Processed {filename} successfully.")
        except Exception as e:
            print(f"Error processing {filename}: {e}")


if __name__ == "__main__":
    process_logs()
