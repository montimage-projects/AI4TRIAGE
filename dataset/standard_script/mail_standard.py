import os
import re
import json
import pandas as pd
import numpy as np
from config import  MITRE_MAIL_MAPPING, STANDARD_COLUMNS


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
    """Extracts a field value from structured text using regex."""
    match = re.search(rf"'{field}':\s*(?:\[)?'([^']+)'", text)
    return match.group(1) if match else "Unknown"

def extract_stat_value(field, text):
    """Extracts a field value from structured text using regex, supporting both single and double quotes."""
    if not isinstance(text, str):
        return "Unknown"
    
    # Match values enclosed in either single or double quotes
    match = re.search(rf"'{field}':\s*(?:\"|')([^\"']+)(?:\"|')", text)
    return match.group(1) if match else "Unknown"

def extract_ip_from_relay(relay_value):
    """Extracts the IP address or domain from a relay field."""
    if not isinstance(relay_value, str) or not relay_value.strip():
        return "Unknown"
    
    match = re.search(r"\[([\d\.]+)\]", relay_value)
    if match:
        return match.group(1) 
    return relay_value


def extract_ttp(log_data):
    """Maps email log data to MITRE ATT&CK TTPs."""
    detected_ttps = set()
    if not isinstance(log_data, str):
        return "Unknown"
    for ttp, pattern in MITRE_MAIL_MAPPING.items():
        if re.search(pattern, log_data, re.IGNORECASE):
            detected_ttps.add(ttp)
    return ",".join(detected_ttps) if detected_ttps else "Unknown"

def extract_mail_fields(evento):
    """Extracts fields from mail logs  for TTP mapping."""
    if not isinstance(evento, str) or not evento.strip():
        return {
            "source_ip": "Unknown",
            "destination_ip": "Unknown",
            "user": "Unknown",
            "action": "Unknown",
            "protocol": "SMTP",
            "threat_name": "Unknown",
            "port": 25,
            "ttp_detected": "Unknown"
        }

    protocol = "SMTP"
    threat_parts = []  

    #  Case 1: `msg`
    if "'msg':" in evento:
        from_email = extract_value("from", evento)
        to_email = extract_value("to", evento)
        subject = extract_value("subject", evento)
        source_ip = extract_value("ip", evento)
        action = extract_value("resolveStatus", evento) or "Delivered"
        attachment = extract_value("msgParts", evento)
        protocol = "SMTP"

        threat_parts.extend([subject, action, attachment if attachment else ""])

    #  Case 2: `metadata`
    elif "'metadata':" in evento:
        from_email = extract_value("from", evento) or "System Notification"
        to_email = extract_value("to", evento)
        subject = extract_stat_value("stat", evento) if extract_stat_value("stat", evento) != "Unknown" else extract_value("msgid", evento)
        source_ip = extract_ip_from_relay(extract_value("relay", evento))
        action = subject
        attachment = extract_value("sizeBytes", evento) or None
        protocol = "ESMTP"

        threat_parts.extend([
            extract_value("verify", evento),
            extract_value("version", evento),
            extract_value("cipher", evento),
            extract_value("relay", evento)
        ])

    #  Case 3: `messageTime`
    elif "'messageTime':" in evento:
        from_email = extract_value("fromAddress", evento)
        to_email = extract_value("toAddresses", evento)
        subject = extract_value("headerFrom", evento) or extract_value("subject", evento)
        source_ip = extract_value("senderIP", evento)
        action = subject
        attachment = extract_value("messageSize", evento)
        protocol = "ESMTP"

        threat_parts.extend([
            extract_value("quarantineRule", evento),
            extract_value("phishScore", evento),
            extract_value("threatUrl", evento),
            extract_value("threatStatus", evento)
        ])

    else:
        from_email, to_email, subject, source_ip, action, attachment = ["Unknown"] * 6

    threat_parts = [part for part in threat_parts if part and part != "Unknown"] 
    threat_info = ", ".join(threat_parts) if threat_parts else "Unknown"

    # **Mapping with MITRE_MAIL_MAPPING**
    ttp_subject = extract_ttp(threat_info)
    ttp_action = extract_ttp(action)
    ttp_attachment = extract_ttp(attachment) if attachment else None

    # Combine and remove duplicates, exclude "Unknown"
    ttp_detected = ",".join(set(filter(lambda x: x and x != "Unknown", [ttp_subject, ttp_action, ttp_attachment])))
    if not ttp_detected:
        ttp_detected = "Unknown"

    return {
        "source_ip": source_ip,
        "destination_ip": to_email,
        "user": from_email,
        "threat_name": subject,
        "action": action,
        "protocol": protocol,
        "port": 25,
        "ttp_detected": ttp_detected
    }


def process_mail_log(df):
    """Process Mail logs and extract critical features."""
    # Ensure required columns
    required_columns = ["ts", "evento","messageTime"]
    for col in required_columns:
        if col not in df.columns:
            df[col] = "Unknown"

    # Extract fields
    extracted = df["evento"].apply(extract_mail_fields) 
    extracted_df = pd.DataFrame(extracted.tolist())

    # Convert timestamp to epoch
    df["timestamp"] = df["ts"].combine_first(df["messageTime"]).pipe(convert_to_epoch)
    df["log_type"] = "mail"

    # Combine extracted fields with the original DataFrame
    df = pd.concat([df, extracted_df], axis=1)

    # Return standardized columns
    return df[STANDARD_COLUMNS]


def process_logs():
    """Process all mail logs in the directory."""
    directory = "Datasets/raw/mail_attack_chunks"
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        try:
            df = pd.read_csv(filepath, low_memory=False).rename(columns=lambda x: x.strip())
            df = process_mail_log(df)
            df.to_csv("Datasets/processed/mail_logs.csv", index=False, mode="a")
        except Exception as e:
            print(f"Error processing {filename}: {e}")


if __name__ == "__main__":
    process_logs()
