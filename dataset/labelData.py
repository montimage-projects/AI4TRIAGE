import os
import sys
import glob
import json
import logging
import pandas as pd
from datetime import datetime
from dateutil import parser  # flexible date parser
from typing import Dict, Any, List

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("labelData.log"),
        logging.StreamHandler()
    ]
)

class LabelingError(Exception):
    pass

def load_config(config_path: str = 'dataset/config.json') -> Dict[str, Any]:
    """Load configuration and return a config dictionary.
       Expected keys include:
         "known_ranges": either a dict (preferred) or a list of [start, end] items,
         "time_column": dict mapping log types to their time column (index or name),
         "time_formats": dict mapping log types to a list (or single string) of time format(s).
    """
    if not os.path.exists(config_path):
        raise LabelingError(f"Configuration file not found: {config_path}")
    try:
        with open(config_path, "r") as fp:
            config = json.load(fp)
    except Exception as e:
        raise LabelingError(f"Error loading config: {e}")

    if "known_ranges" not in config:
        raise LabelingError("Missing 'known_ranges' in config file")

    known_ranges_conf = config["known_ranges"]
    if isinstance(known_ranges_conf, list):
        config["known_ranges"] = {str(i+1): r for i, r in enumerate(known_ranges_conf)}

    for attack, time_range in config["known_ranges"].items():
        try:
            start = float(time_range[0])
            end = float(time_range[1])
        except (TypeError, ValueError, IndexError) as e:
            raise LabelingError(f"Invalid time range for attack {attack}: {e}")
        config["known_ranges"][attack] = (start, end)

    if "time_column" not in config:
        raise LabelingError("Missing 'time_column' in config file")
    if "time_formats" not in config:
        config["time_formats"] = {}
    return config

def convert_eventdate(log_type: str, eventdate_str: str, config: Dict[str, Any]) -> float:
    """Convert eventdate string to Unix epoch (float), except for proxy logs which are assumed numeric."""
    if log_type.lower() == "proxy":
        try:
            return float(eventdate_str)
        except Exception as e:
            raise ValueError(f"Error converting proxy eventdate '{eventdate_str}' to numeric value: {e}")
    
    # For all other log types, try to use any specified time formats.
    time_formats = config.get("time_formats", {})
    fmt_entry = time_formats.get(log_type, None)
    formats = []
    if fmt_entry:
        if isinstance(fmt_entry, str):
            if fmt_entry.strip() != "":
                formats = [fmt_entry]
        elif isinstance(fmt_entry, list):
            formats = fmt_entry
    for fmt in formats:
        try:
            dt_obj = datetime.strptime(eventdate_str, fmt)
            return dt_obj.timestamp()
        except Exception:
            continue
    try:
        dt_obj = parser.parse(eventdate_str)
        return dt_obj.timestamp()
    except Exception as e:
        raise ValueError(f"Error converting eventdate '{eventdate_str}' for log_type '{log_type}': {e}")

def assign_attack_label(log_type: str, timestamp: float, config: Dict[str, Any]) -> Any:
    """Assigns an attack label by comparing timestamp to known ranges."""
    try:
        ranges = config["known_ranges"]
        for attack, (start, end) in ranges.items():
            if start <= timestamp <= end:
                try:
                    return int(attack)
                except ValueError:
                    return attack
        return 0
    except Exception as e:
        logging.error(f"Error assigning label for log_type '{log_type}' and timestamp {timestamp}: {e}")
        return 0

def validate_input(input_path: str) -> List[str]:
    """Validate input path and return list of CSV files."""
    if not os.path.exists(input_path):
        raise LabelingError(f"Input path does not exist: {input_path}")
    if os.path.isfile(input_path):
        if not input_path.lower().endswith('.csv'):
            raise LabelingError(f"Input file must be CSV: {input_path}")
        return [input_path]
    elif os.path.isdir(input_path):
        files = glob.glob(os.path.join(input_path, "*.csv"))
        if not files:
            raise LabelingError(f"No CSV files found in directory: {input_path}")
        return files
    else:
        raise LabelingError(f"Invalid input path: {input_path}")

def process_file(file: str, output_file: str, config: Dict[str, Any], chunksize: int = 100000) -> tuple[int, Dict[Any, int]]:
    """Process the CSV file in chunks using pandas.
       Returns a tuple: (number of rows processed, dictionary of label counts)
    """
    total_processed = 0
    aggregated_labels = {}

    # Check if output file exists to determine header write.
    write_header = not os.path.exists(output_file) or os.path.getsize(output_file) == 0
    
    time_columns = config.get("time_column", {})

    def process_row(row):
        try:
            log_type = str(row["log_type"]).lower()
            time_col = time_columns.get(log_type)
            if time_col is None:
                raise LabelingError(f"Time column not defined for log type '{log_type}'")
            # If time_col is an integer, use iloc; if it's a string, use direct indexing.
            if isinstance(time_col, int):
                eventdate_str = row.iloc[time_col]
            else:
                eventdate_str = row[time_col]
            ts = convert_eventdate(log_type, str(eventdate_str), config)
            row["timestamp"] = ts
        except Exception as e:
            logging.warning(f"Row skipped due to error: {e}")
            row["timestamp"] = None
        return row

    try:
        for chunk in pd.read_csv(file, chunksize=chunksize,low_memory=False):
            # Only process if 'log_type' column exists.
            if "log_type" not in chunk.columns:
                logging.error(f"File {file} is missing required column 'log_type'")
                continue
            chunk = chunk.apply(process_row, axis=1)
            missing = chunk["timestamp"].isna().sum()
            if missing > 0:
                logging.warning(f"{missing} row(s) in chunk skipped due to missing/invalid timestamp in {file}")
            chunk = chunk.dropna(subset=["timestamp"])
            # Assign attack labels.
            chunk["attack_label"] = chunk.apply(
                lambda row: assign_attack_label(str(row["log_type"]).lower(), row["timestamp"], config), axis=1)
            # Reorder columns so that attack_label and timestamp come first.
            cols = chunk.columns.tolist()
            for col in ["attack_label", "timestamp"]:
                if col in cols:
                    cols.remove(col)
            new_order = ["attack_label", "timestamp"] + cols
            chunk = chunk[new_order]
            processed_count = len(chunk)
            label_count = chunk["attack_label"].value_counts().to_dict()
            total_processed += processed_count
            for label, count in label_count.items():
                aggregated_labels[label] = aggregated_labels.get(label, 0) + count
            try:
                chunk.to_csv(output_file, mode="a", header=write_header, index=False)
                write_header = False  # Only write header for the first chunk.
                logging.info(f"Processed a chunk of {processed_count} row(s) from {file}")
            except Exception as e:
                logging.error(f"Error writing chunk to output for {file}: {e}")
    except Exception as e:
        logging.error(f"Error processing file {file}: {e}")

    return total_processed, aggregated_labels

def main():
    try:
        if len(sys.argv) < 3:
            print("Usage: python labelData.py <input_path> <output_path>")
            sys.exit(1)
        input_path = sys.argv[1]
        output_path = sys.argv[2]  # This can be a file or a directory

        config = load_config()
        files = validate_input(input_path)
        logging.info(f"Found {len(files)} file(s) to process.")

        total_rows = 0
        aggregated_labels = {}

        # If input_path is a directory, then treat output_path as a directory
        if os.path.isdir(input_path):
            os.makedirs(output_path, exist_ok=True)
            for f in files:
                basename = os.path.basename(f)
                # Replace "cleaned" with "labelled" in the filename
                out_file = os.path.join(output_path, basename.replace("cleaned", "labelled"))
                try:
                    rows, label_counts = process_file(f, out_file, config)
                    total_rows += rows
                    for label, count in label_counts.items():
                        aggregated_labels[label] = aggregated_labels.get(label, 0) + count
                except Exception as e:
                    logging.error(f"Failed processing {f}: {e}")
                    continue
        else:
            # Input is a single file; ensure the output directory exists.
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            try:
                rows, label_counts = process_file(input_path, output_path, config)
                total_rows += rows
                for label, count in label_counts.items():
                    aggregated_labels[label] = aggregated_labels.get(label, 0) + count
            except Exception as e:
                logging.error(f"Failed processing {input_path}: {e}")

        logging.info(f"Total rows processed: {total_rows}")
        for label, count in aggregated_labels.items():
            logging.info(f"Label {label}: {count}")
    except Exception as e:
        logging.error(str(e))
        sys.exit(1)

if __name__ == "__main__":
    main()