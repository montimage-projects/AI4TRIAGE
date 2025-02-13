import argparse
import os
import json
import re
import pandas as pd
import ast
# Define log directories
LOG_DIRECTORIES = {
    "proxy": "Datasets/raw/proxy_attack_chunks/",
    "firewall": "Datasets/raw/firewall_attack_chunks/",
    "xdr": "Datasets/raw/xdr_alerts_attack_chunks/",
    "mail": "Datasets/raw/mail_attack_chunks/",
}

# MITRE ATT&CK Mapping
MITRE_TTP_MAPPING = {
    #  Discovery Techniques
    "domain discovery": "T1082",
    "system information discovery": "T1082",
    "system network configuration discovery": "T1016",
    "file and directory discovery": "T1083",
    "active directory enumeration": "T1069",
    "ldap query": "T1018",
    "network sniffing": "T1040",
    "kerberoasting": "T1208",
    "certificate template discovery": "T1555.004",

    #  Execution Techniques
    "powershell script": "T1059.003",
    "wmi execution": "T1047",
    "cmd execution": "T1059.003",
    "scheduled task execution": "T1053.005",
    "rundll32 execution": "T1218.011",

    #  Credential Access
    "password spraying": "T1110.003",
    "brute force attack": "T1110",
    "mimikatz": "T1003.001",
    "lsass dumping": "T1003.001",
    "credential theft": "T1555.003",
    "credential harvesting": "T1110.001",

    #  Privilege Escalation
    "dll injection": "T1055.001",
    "process injection": "T1055",
    "user privilege escalation": "T1078.003",
    "scheduled task": "T1053.005",
    "service registry modification": "T1543.003",

    #  Defense Evasion
    "clearing logs": "T1070.001",
    "disabling security tools": "T1562.001",
    "file deletion": "T1070.004",
    "masquerading": "T1036",
    "parent process spoofing": "T1134.004",

    #  Command & Control
    "dns tunneling": "T1572",
    "http beaconing": "T1071.001",
    "reverse shell": "T1105",
    "download and execute": "T1105",
    "remote access tool": "T1219",
    "malware beaconing": "T1071.001",

    #  Exfiltration
    "data exfiltration": "T1041",
    "http exfiltration": "T1041",
    "dns exfiltration": "T1132.001",
    "sftp exfiltration": "T1048.002",
    "encrypted exfiltration": "T1573",

    #  Impact
    "ransomware encryption": "T1486",
    "service stop": "T1489",
    "disk wiping": "T1561",
    "recovery disabling": "T1490",

    # Phishing
    "phishing email": "T1566.002",
    "malicious attachment": "T1204.002",
    "spear phishing": "T1566.001",
    "password reset email": "T1566.002",
    "social engineering": "T1204",

    #  Lateral Movement
    "remote desktop protocol": "T1021.001",
    "pass-the-hash": "T1550.002",
    "remote powershell": "T1021.006",
    "remote command execution": "T1569.002",
}

#  Standardized column names
STANDARD_COLUMNS = [
    "timestamp", "log_type", "source_ip", "destination_ip", "action",
    "user", "protocol", "port", "threat_name", "ttp_detected"
]


def convert_to_timestamp(series):
    """
    Converts timestamps from various formats into a standardized UTC datetime.
    Supports:
    - ISO 8601 with timezones (e.g., "2024-08-29T08:17:17.536645+0200")
    - ISO 8601 with nanosecond precision (e.g., "2024-08-27T03:38:29.996266456+02:00")
    - Standard datetime format (e.g., "2024-08-29 00:00:02.844")
    - Epoch (e.g., 1724357989 for seconds, 1724357989000 for milliseconds)
    - Fallback for unknown formats (returns NaT)
    """
    def parse_time(value):
        if pd.isna(value) or value in ["", "null", "None"]:
            return pd.NaT  # Return Not-a-Time for null/empty values

        if isinstance(value, (int, float)):  # Handle Epoch timestamps
            if value > 10**10:  # Likely milliseconds
                return pd.to_datetime(value, unit='ms', utc=True)
            else:  # Likely seconds
                return pd.to_datetime(value, unit='s', utc=True)

        if isinstance(value, str):  # Handle string timestamps
            try:
                # Try parsing with default
                return pd.to_datetime(value, utc=True)
            except Exception:
                try:
                    # Handle ISO 8601 with timezone (e.g., "+0200" or "+02:00")
                    return pd.to_datetime(value, format="%Y-%m-%dT%H:%M:%S.%f%z")
                except Exception:
                    try:
                        # Handle standard datetime format
                        return pd.to_datetime(value, format="%Y-%m-%d %H:%M:%S.%f", utc=True)
                    except Exception:
                        return pd.NaT  # Return Not-a-Time for unrecognized formats

        return pd.NaT  # Unknown format

    return series.apply(parse_time)  # Apply to all rows


def extract_ttp(threat_name):
    """Maps extracted threat names to MITRE ATT&CK TTPs."""
    if not isinstance(threat_name, str):
        return None
    for keyword, ttp in MITRE_TTP_MAPPING.items():
        if keyword in threat_name.lower():
            return ttp
    return None

def extract_json_column(df, column, keys):
    """Extract multiple keys from a JSON column."""
    def extract_json_safe(value):
        if not isinstance(value, str):
            return {key: None for key in keys}
        try:
            return json.loads(value.replace("'", "\""))
        except (json.JSONDecodeError, TypeError):
            return {key: None for key in keys}
    
    extracted = df[column].apply(extract_json_safe)
    return pd.DataFrame(extracted.tolist(), index=df.index)[keys]

def extract_value(field, text):
    """Extracts a field value from structured text using regex."""
    match = re.search(rf"'{field}':\s*\[?'?([^'\]]+)'?\]?", text)
    return match.group(1) if match else "Unknown"

def process_firewall_log(df):
    df["timestamp"] = convert_to_timestamp(df["eventdate"])
    df["log_type"] = "firewall"
    df["source_ip"] = df.get("src_ip", "Unknown")
    df["destination_ip"] = df.get("dst_ip", "Unknown")
    df["action"] = df.get("action", "Unknown")
    df["user"] = df.get("src_user", "Unknown")
    df["protocol"] = df.get("protocol", "Unknown")
    df["port"] = df.get("dst_port", None)
    df["threat_name"] = df.get("signature", df.get("category", "Unknown"))
    df["ttp_detected"] = df["threat_name"].apply(extract_ttp)

    return df[STANDARD_COLUMNS]

def process_proxy_log(df):
    json_keys = ["userip", "dstip", "protocol", "action", "dstport", "alert_name"]
    extracted_df = extract_json_column(df, "evento", json_keys)
    
    df["timestamp"] = convert_to_timestamp(df["timestamp"])
    df["log_type"] = "proxy"
    df["source_ip"] = extracted_df["userip"]
    df["destination_ip"] = extracted_df["dstip"]
    df["protocol"] = extracted_df["protocol"]
    df["port"] = extracted_df["dstport"]
    df["action"] = extracted_df["action"]
    df["threat_name"] = df.get("other_categories", "Unknown")
    df["ttp_detected"] = df["threat_name"].apply(extract_ttp).astype(str) + "," + df["action"].apply(extract_ttp).astype(str)
    df["ttp_detected"] = df["ttp_detected"].str.replace("None,", "").str.replace(",None", "").str.replace("None", "")
    df["ttp_detected"] = df["ttp_detected"].apply(lambda x: ",".join(set(x.split(","))) if x else None)  # Remove duplicates

    return df[STANDARD_COLUMNS]


def process_mail_log(df):
    """Processes Mail logs using regex-based extraction for evento fields."""
    
    def extract_mail_fields(evento):
        if not isinstance(evento, str) or not evento.strip():
            return {
                "source_ip": "Unknown",
                "destination_ip": "Unknown",
                "user": "Unknown",
                "threat_name": "Unknown",
                "action": "Unknown",
                "protocol": "SMTP",
                "port": 25,
                "ttp_detected": None
            }

        # Case 1: Extract from `msg`
        if "'msg':" in evento:
            
            from_email = extract_value("from", evento)
            to_email = extract_value("to", evento)
            subject = extract_value("subject", evento)
            source_ip = extract_value("ip", evento)
            action = extract_value("resolveStatus", evento) or "Delivered"

        # Case 2: Extract from `metadata`
        elif "'metadata':" in evento:
            from_email = "System Notification"
            to_email = extract_value("to", evento)
            subject = extract_value("stat", evento)  # Status message as subject
            source_ip = extract_value("relay", evento)
            action = subject  # Status messages often act as actions

        else:
            from_email, to_email, subject, source_ip, action = ["Unknown"] * 5

        ttp_subject = extract_ttp(subject)
        ttp_action = extract_ttp(action)

        # Combine, remove None values, and ensure uniqueness
        ttp_detected = ",".join(set(filter(None, [ttp_subject, ttp_action])))
        return {
            "source_ip": source_ip,
            "destination_ip": to_email,
            "user": from_email,
            "threat_name": subject,
            "action": action,
            "protocol": "SMTP",
            "port": 25,
            "ttp_detected" :ttp_detected
        }

    # Apply regex-based extraction
    extracted = df["evento"].apply(extract_mail_fields)
    extracted_df = pd.DataFrame(extracted.tolist())

    df["timestamp"] = convert_to_timestamp(df["ts"])
    df["log_type"] = "mail"

    return pd.concat([df, extracted_df], axis=1)[STANDARD_COLUMNS]


def process_xdr_log(df):
    """Processes XDR logs using JSON parsing with robust error handling."""
    
    def extract_xdr_fields(evento):
        """Extracts fields from a JSON-structured XDR log safely."""
        if pd.isna(evento) or not isinstance(evento, str) or not evento.strip():
            return {
                "timestamp": pd.NaT,
                "log_type": "xdr",
                "source_ip": "Unknown",
                "destination_ip": "Unknown",
                "user": "Unknown",
                "threat_name": "Unknown",
                "action": "Unknown",
                "protocol": "Unknown",
                "port": "Unknown",
                "ttp_detected": "Unknown"
            }
        
        try:
            # Convert JSON string to dictionary
            event_data = json.loads(evento)

            # Extract timestamp and convert
            timestamp = event_data.get("_eventdate") or event_data.get("eventdate")
            timestamp = convert_to_timestamp(pd.Series([timestamp])).iloc[0]  # Convert to Pandas datetime

            # Extract TTP from mitre_techniques
            ttp_from_mitre = event_data.get("mitre_techniques", ["Unknown"])
            if isinstance(ttp_from_mitre, list):
                ttp_from_mitre = ttp_from_mitre[0] if ttp_from_mitre else "Unknown"

            # Extract TTP from threat_name & action
            ttp_from_threat = extract_ttp(event_data.get("name") or event_data.get("alert_type"))
            ttp_from_action = extract_ttp(event_data.get("action") or event_data.get("action_pretty"))

            # Combine, remove None values, and ensure uniqueness
            ttp_detected = list(set(filter(None, [ttp_from_mitre, ttp_from_threat, ttp_from_action])))
            ttp_detected_str = ",".join(ttp_detected) if ttp_detected else "Unknown"

            return {
                "timestamp": timestamp,
                "log_type": "xdr",
                "source_ip": event_data.get("host_ip", ["Unknown"])[0] if isinstance(event_data.get("host_ip"), list) else event_data.get("host_ip"),
                "destination_ip": event_data.get("action_remote_ip"),
                "user": event_data.get("user_name") or event_data.get("users"),
                "threat_name": event_data.get("name") or event_data.get("alert_type"),
                "action": event_data.get("action") or event_data.get("action_pretty"),
                "protocol": event_data.get("fw_app_id"),
                "port": f"{event_data.get('action_local_port', 'Unknown')}->{event_data.get('action_remote_port', 'Unknown')}",
                "ttp_detected": ttp_detected_str
            }
        
        except json.JSONDecodeError:
            return {
                "timestamp": pd.NaT,
                "log_type": "xdr",
                "source_ip": "Unknown",
                "destination_ip": "Unknown",
                "user": "Unknown",
                "threat_name": "Unknown",
                "action": "Unknown",
                "protocol": "Unknown",
                "port": "Unknown",
                "ttp_detected": "Unknown"
            }

    # Apply extraction function safely
    if "evento" not in df.columns:
        raise ValueError(" Missing 'evento' column in XDR log file!")

    extracted = df["evento"].dropna().astype(str).apply(extract_xdr_fields)
    extracted_df = pd.DataFrame(extracted.tolist())

    # Convert timestamp column to proper datetime format
    extracted_df["timestamp"] = pd.to_datetime(extracted_df["timestamp"], errors="coerce", utc=True)
    
    return extracted_df

def process_logs(log_type):
    if log_type not in LOG_DIRECTORIES and log_type != "all":
        print(f" Invalid log type: {log_type}. Choose from: firewall, proxy, xdr, mail, all")
        return
    
    all_logs = []
    directories = [log_type] if log_type != "all" else LOG_DIRECTORIES.keys()

    for log in directories:
        directory = LOG_DIRECTORIES[log]
        for filename in os.listdir(directory):
            filepath = os.path.join(directory, filename)
            try:
                df = pd.read_csv(filepath, low_memory=False).rename(columns=lambda x: x.strip())

                if log == "firewall":
                    df = process_firewall_log(df)
                elif log == "proxy":
                    df = process_proxy_log(df)
                elif log == "xdr":
                    df = process_xdr_log(df)
                elif log == "mail":
                    df = process_mail_log(df)

                df.to_csv(f"Datasets/processed/{log}_logs.csv", index=False, mode="a", header=not os.path.exists(f"Datasets/processed/{log}_logs.csv"))

            except Exception as e:
                print(f" Error processing {filename}: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("log_type", type=str, help="Specify log type: firewall, proxy, xdr, mail, or all")
    args = parser.parse_args()
    process_logs(args.log_type)
