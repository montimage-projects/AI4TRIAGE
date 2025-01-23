import sys
import pandas as pd
import json
import os
from datetime import datetime
from dateutil import parser
from tqdm import tqdm

# Configuration for different log types, including the name of the time column and its format
LOG_CONFIG = {
    "firewall": {"time_column": "eventdate", "time_format": "%Y-%m-%d %H:%M:%S.%f"},
    "mail": {"time_column": "ts", "time_format": "%Y-%m-%dT%H:%M:%S.%f%z"},
    "proxy": {"time_column": "src_time", "time_format": "%a %b %d %H:%M:%S %Y"},
    "xdr": {"time_column": "_eventdate", "time_format": "%Y-%m-%dT%H:%M:%S.%f%z", "fallback_json": True},
}

# OUTPUT_FILE = "merged_all_logs.csv"

# Convert datetime strings to Unix timestamps (seconds since epoch)
def datetime_string_to_epoch(dtstring, time_format=None):
    try:
        if time_format:
            # Parse the datetime string using the given format
            dt_obj = datetime.strptime(dtstring, time_format)
        else:
            # Fallback: Automatically parse ISO 8601 formatted strings
            dt_obj = parser.isoparse(dtstring)
        return int(dt_obj.timestamp())
    except Exception as e:
        raise ValueError(f"Error parsing datetime '{dtstring}': {e}")

# Extract timestamp from a JSON string, if available
def extract_time_from_json(json_string):
    try:
        data = json.loads(json_string)
        if "last_seen" in data:  # Check if the JSON has the `last_seen` key
            return datetime_string_to_epoch(data["last_seen"], "%Y-%m-%d %H:%M:%S.%f")
        return None
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        print(f"Error parsing JSON: {json_string}, error: {e}")
        return None

# Process an individual file of a specific log type
def process_file(file_path, log_type):
    config = LOG_CONFIG[log_type]
    time_column = config["time_column"]
    
    print(f"Processing file: {file_path}")
    df = pd.read_csv(file_path, low_memory=False)

    # Convert the primary time column to datetime format
    df["time"] = pd.to_datetime(df[time_column], format=config["time_format"], errors="coerce", utc=True)

    # Handle rows where the time column is NaT (invalid datetime)
    if config.get("fallback_json"):
        mask_na = df["time"].isna()
        if mask_na.any():
            print(f"Extracting time from JSON for {mask_na.sum()} rows in file {file_path}")
            extracted_times = df.loc[mask_na].iloc[:, 0].apply(extract_time_from_json)
            extracted_times = pd.to_datetime(extracted_times, unit='s', errors='coerce', utc=True)
            df.loc[mask_na, "time"] = extracted_times

    # Drop rows where the time column is still invalid after processing
    df = df.dropna(subset=["time"])

    # Ensure the time column is in UTC and convert to Unix timestamps
    if not pd.api.types.is_datetime64_any_dtype(df["time"]):
        df["time"] = pd.to_datetime(df["time"], errors="coerce")
    if df["time"].dt.tz is None:  # If timezone information is missing, localize to UTC
        df["time"] = df["time"].dt.tz_localize("UTC")
    else:  # If timezone information exists, convert to UTC
        df["time"] = df["time"].dt.tz_convert("UTC")
    df["time"] = df["time"].astype(int) / 10**9  # Convert nanoseconds to seconds

    print(f"Processed file {file_path} with {len(df)} valid rows.")
    return df

# Process all files for a given log type in the input directory
def process_logs(input_dir, log_type):
    processed_logs = []
    for root, dirs, files in tqdm(os.walk(input_dir)):  # Traverse all subdirectories
        for file_name in files:
            if file_name.endswith(".csv"):
                if log_type in root:  # Only process files under directories matching the log type
                    file_path = os.path.join(root, file_name)
                    try:
                        processed_logs.append(process_file(file_path, log_type))
                    except Exception as e:
                        print(f"Could not process file {file_path} due to error: {e}")

    # Combine all processed files into a single DataFrame
    if processed_logs:
        return pd.concat(processed_logs, ignore_index=True)
    else:
        print(f"No valid data for log type '{log_type}'.")
        return pd.DataFrame()

# Main function to process and merge logs
def main():

    if len(sys.argv) < 3:
        print("Usage: python merge.py <input_directory> <output_file>")
        sys.exit(1)
    input_dir = sys.argv[1]
    output_file = sys.argv[2]

    merged_logs = None  # To hold the merged logs

    for log_type in LOG_CONFIG.keys():
        print(f"Processing logs of type: {log_type}")
        log_data = process_logs(input_dir, log_type)  # Process each log type

        if not log_data.empty:  # Merge only if the log has valid data
            if merged_logs is None:
                merged_logs = log_data
            else:
                # Merge current logs with the new log type
                merged_logs = pd.merge(
                    merged_logs,
                    log_data,
                    on="time",
                    how="outer",  # Use 'outer' to keep all records
                    suffixes=("", f"_{log_type}")  # Add suffix for overlapping columns
                )
                print(f"Merged '{log_type}' logs")

    # Save the merged logs to a CSV file
    if merged_logs is not None and not merged_logs.empty:
        num_rows = merged_logs.shape[0]
        print(f"Final merged log contains {num_rows} rows.")
        merged_logs.to_csv(output_file, index=False)
        print(f"Merged logs saved to '{output_file}'.")
    else:
        print("No valid data to merge.")

# Run the script
if __name__ == "__main__":
    main()
