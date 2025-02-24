import os
import re
import json
import pandas as pd
import numpy as np
from config import MITRE_PROXY_MAPPING, STANDARD_COLUMNS

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


# def map_ttps_from_proxy(log_data):
#     """Maps proxy log data to MITRE ATT&CK TTPs."""
#     detected_ttps = set()
#     if not isinstance(log_data, str):
#         return "Unknown"
#     for ttp, pattern in MITRE_PROXY_MAPPING.items():
#         if re.search(pattern, log_data, re.IGNORECASE):
#             detected_ttps.add(ttp)
#     return ",".join(detected_ttps) if detected_ttps else "Unknown"



def map_ttps_from_proxy(evento):
    """Maps proxy log data in the `evento` column to MITRE ATT&CK TTPs."""
    detected_ttps = set()

    # Ensure evento is a valid string
    if not isinstance(evento, str) or not evento.strip():
        return "Unknown"

    # try:
    #     # Parse the evento JSON string
    #     evento_data = json.loads(evento.replace("'", "\""))  # Handle single quotes if present
    # except json.JSONDecodeError:
    #     return "Unknown"

    # # Flatten the data into a single string for regex matching
    # log_content = " ".join([str(value) for value in evento_data.values() if value])

    # Check for each TTP in the log content
    for ttp, pattern in MITRE_PROXY_MAPPING.items():
        if re.search(pattern, evento, re.IGNORECASE):
            detected_ttps.add(ttp)

    return ",".join(detected_ttps) if detected_ttps else "Unknown"


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


def extract_proxy_fields(evento):
    """Extracts relevant fields from proxy logs."""
    if not isinstance(evento, str) or not evento.strip():
        return {
            "source_ip": "Unknown",
            "destination_ip": "Unknown",
            "user": "Unknown",
            "action": "Unknown",
            "protocol": "Unknown",
            "port": 443,
            "threat_name": "Unknown",
            "ttp_detected": "Unknown"
        }

    # Extract key fields
    source_ip =  extract_value("srcip",evento)
    destination_ip = extract_value("dstip", evento)
    user = extract_value("userip", evento)
    action = extract_value("action", evento)
    protocol = extract_value("protocol", evento)
    port = extract_value("dstport", evento)
    threat_name = extract_value("alert_name", evento) 
    if threat_name == "Unknown":
        threat_name = extract_value("category", evento)
    # Extract MITRE ATT&CK TTPs
    log_content = f"{user} {action} {protocol} {threat_name}"
    ttp_detected = map_ttps_from_proxy(evento)

    return {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "user": user,
        "action": action,
        "protocol": protocol,
        "port": port,
        "threat_name": threat_name,
        "ttp_detected": ttp_detected
    }


def process_proxy_log(df):
    """Processes proxy logs and extracts critical features."""
    # Ensure required columns
    if "evento" not in df.columns:
        raise ValueError("Column 'evento' is missing in the input DataFrame.")

    # Extract fields
    extracted = df["evento"].apply(extract_proxy_fields)
    extracted_df = pd.DataFrame(extracted.tolist())

    df = df.drop(columns=["user", "protocol", "port","action"], errors="ignore")
    # Combine extracted fields with the original DataFrame
    df = pd.concat([df, extracted_df], axis=1)
    # Convert timestamp to epoch
    df["timestamp"] = convert_to_epoch(df["timestamp"])
    df["log_type"] = "proxy"

    # Select and return standardized columns
    return df[STANDARD_COLUMNS]


def process_logs():
    """Processes all proxy logs in the specified directory."""
    directory = "Datasets/raw/proxy_attack_chunks"
    output_file = "Datasets/processed/proxy_logs.csv"

    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        try:
            df = pd.read_csv(filepath, low_memory=False).rename(columns=lambda x: x.strip())
            df = process_proxy_log(df)
            df.to_csv(output_file, index=False, mode="a")
            print(f"Processed {filename} successfully.")
        except Exception as e:
            print(f"Error processing {filename}: {e}")


if __name__ == "__main__":
    process_logs()
