import os
import pandas as pd
import numpy as np
import logging
from tqdm import tqdm
import json
import argparse
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Load config from config.json
config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.json")
with open(config_path, "r") as f:
    config = json.load(f)

RAW_DIR = config.get("RAW_DIR", "Datasets/raw/")
CLEANED_DIR = config.get("CLEANED_DIR", "Datasets/cleaned/")
SUBDIRECTORIES = config.get("SUBDIRECTORIES", [])
CSV_SEPARATOR = config.get("CSV_SEPARATOR", ",")
LOG_TYPE_MAPPING = config.get("LOG_TYPE_MAPPING", {})
CHUNKSIZE = int(config.get("CHUNKSIZE", 100000))
MISSING_THRESHOLD = float(config.get("MISSING_THRESHOLD", 0.95))

class GlobalStatistics:
    def __init__(self):
        self.missing_ratios = {}
        self.means = {}
        self.stds = {}
        self.median_values = {}
        self.unique_counts = {}
        self.total_rows = 0
        self.column_dtypes = {}

    def update_from_chunk(self, chunk):
        n = len(chunk)
        if self.total_rows == 0:
            self._initialize_from_chunk(chunk)
        else:
            self._update_statistics(chunk, n)
        self.total_rows += n

    def _initialize_from_chunk(self, chunk):
        self.column_dtypes = chunk.dtypes.to_dict()
        for col in chunk.columns:
            self.missing_ratios[col] = chunk[col].isnull().sum()
            self.unique_counts[col] = set(chunk[col].dropna().unique())
            if pd.api.types.is_numeric_dtype(chunk[col]):
                self.means[col] = chunk[col].mean()
                self.stds[col] = chunk[col].var() * len(chunk)
                self.median_values[col] = chunk[col].median()

    def _update_statistics(self, chunk, n):
        new_columns = set(chunk.columns) - set(self.missing_ratios.keys())
        for col in new_columns:
            self.missing_ratios[col] = 0
            self.unique_counts[col] = set()
            if pd.api.types.is_numeric_dtype(chunk[col]):
                self.means[col] = 0
                self.stds[col] = 0
                self.median_values[col] = 0
        for col in chunk.columns:
            self.missing_ratios[col] += chunk[col].isnull().sum()
            if pd.api.types.is_numeric_dtype(chunk[col]):
                if col not in self.means:
                    self.means[col] = chunk[col].mean()
                    self.stds[col] = chunk[col].var() * n
                    self.median_values[col] = chunk[col].median()
                else:
                    old_mean = self.means[col]
                    chunk_mean = chunk[col].mean()
                    delta = chunk_mean - old_mean
                    self.means[col] = old_mean + (delta * n) / self.total_rows
                    self.stds[col] += chunk[col].var() * (n - 1)
                    old_median = self.median_values[col]
                    chunk_median = chunk[col].median()
                    self.median_values[col] = (old_median * self.total_rows + chunk_median * n) / (self.total_rows + n)
            self.unique_counts[col].update(chunk[col].dropna().unique())

    def finalize_statistics(self):
        for col in self.missing_ratios:
            self.missing_ratios[col] /= self.total_rows
            if col in self.means:
                self.stds[col] = np.sqrt(self.stds[col] / (self.total_rows - 1))
            self.unique_counts[col] = len(self.unique_counts[col])

def first_pass(subdir, chunksize=CHUNKSIZE):
    logging.info(f"Starting first pass for {subdir}: Computing global statistics...")
    stats = GlobalStatistics()
    subdir_path = os.path.join(RAW_DIR, subdir)
    for file in os.listdir(subdir_path):
        if file.endswith(".csv"):
            file_path = os.path.join(subdir_path, file)
            for chunk in tqdm(pd.read_csv(file_path, chunksize=chunksize, low_memory=False, sep=CSV_SEPARATOR), desc=f"Cleaning {file}"):
                try:
                    stats.update_from_chunk(chunk)
                except Exception as e:
                    logging.warning(f"Error cleaning chunk in {file}: {str(e)}")
                    continue
    stats.finalize_statistics()
    logging.info("First pass completed: Global statistics computed")
    return stats

def second_pass(subdir, stats, chunksize=CHUNKSIZE, missing_threshold=MISSING_THRESHOLD):
    logging.info(f"Starting second pass for {subdir}: Applying transformations...")
    log_type = LOG_TYPE_MAPPING.get(subdir, "unknown")
    logging.info(f"Cleaning log type: {log_type}")

    constant_cols = set(col for col, unique_count in stats.unique_counts.items() if unique_count <= 1)
    high_missing_cols = set(col for col, ratio in stats.missing_ratios.items() if ratio > missing_threshold)
    cols_to_remove = constant_cols.union(high_missing_cols)
    if constant_cols:
        logging.info(f"Columns to remove due to constant values: {sorted(constant_cols)}")
    if high_missing_cols:
        logging.info(f"Columns to remove due to high missing rate: {sorted(high_missing_cols)}")
    logging.info(f"Total unique columns to remove: {sorted(cols_to_remove)}")

    cleaned_chunks = []
    subdir_path = os.path.join(RAW_DIR, subdir)
    for file in os.listdir(subdir_path):
        if file.endswith(".csv"):
            file_path = os.path.join(subdir_path, file)
            for chunk in tqdm(pd.read_csv(file_path, chunksize=chunksize, low_memory=False, sep=CSV_SEPARATOR), desc=f"cleaning {file}"):
                chunk = chunk.drop(columns=cols_to_remove, errors='ignore')
                chunk['log_type'] = log_type

                # Use the timestamp column as specified in config.json
                timestamp_col = config.get("time_column", {}).get(log_type)
                if not timestamp_col:
                    logging.warning(f"No timestamp column specified for log type '{log_type}'. Please add it to config.json under 'time_column'.")
                else:
                    if timestamp_col not in chunk.columns:
                        logging.warning(f"Timestamp column '{timestamp_col}' not found in file for log type '{log_type}'.")

                # Fill missing values in numeric columns
                numeric_columns = chunk.select_dtypes(include=['number']).columns
                for col in numeric_columns:
                    if col in stats.median_values:
                        chunk[col] = chunk[col].fillna(stats.median_values[col])

                # Log-type-specific filtering (optional, can be extended)
                if log_type == "firewall":
                    if "type" in chunk.columns:
                        chunk["type"] = chunk["type"].str.lower()
                        chunk = chunk[chunk["type"] == "threat"]
                elif log_type == "proxy":
                    if "action" in chunk.columns:
                        chunk["action"] = chunk["action"].str.lower()
                        chunk = chunk[chunk["action"] != "allow"]
                elif log_type == "xdr":
                    if "_table" in chunk.columns:
                        chunk["_table"] = chunk["_table"].astype(str)
                        chunk = chunk[chunk["_table"].str.strip() != ""]
                elif log_type == "mail":
                    if "evento" in chunk.columns:
                        mail_filter_evento = chunk["evento"].str.contains("message", case=False, na=False)
                    else:
                        mail_filter_evento = True
                    if "tls.verify" in chunk.columns:
                        mail_filter_tls = chunk["tls.verify"].astype(str).str.strip() != "OK"
                    else:
                        mail_filter_tls = True
                    chunk = chunk[mail_filter_evento | mail_filter_tls]

                if not chunk.empty:
                    cleaned_chunks.append(chunk)

    if cleaned_chunks:
        final_data = pd.concat(cleaned_chunks, ignore_index=True)
        cols = list(final_data.columns)
        if 'log_type' in cols:
            cols.remove('log_type')
            final_data = final_data[['log_type'] + cols]
        return final_data
    else:
        logging.warning("No data remained after cleaning")
        return pd.DataFrame()

def save_data(data, output_dir, filename):
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, filename)
    data.to_csv(output_path, index=False)
    logging.info(f"Data saved to {output_path}")

def main():
    parser = argparse.ArgumentParser(description='Clean log data with options to clean specific log types.')
    parser.add_argument('log_types', nargs='*', type=str,
                      help='Log types to clean (default: all). Options: all, firewall, mail, proxy, xdr, ...')
    args = parser.parse_args()

    # Accept any log type present in LOG_TYPE_MAPPING
    valid_types = set(LOG_TYPE_MAPPING.values()) | {'all'}

    if not args.log_types:
        subdirs_to_clean = SUBDIRECTORIES
    else:
        log_types = [lt.lower() for lt in args.log_types]
        invalid_types = set(log_types) - valid_types
        if invalid_types:
            logging.error(f"Invalid log type(s): {invalid_types}")
            logging.error(f"Valid choices are: {sorted(valid_types)}")
            sys.exit(1)
        if 'all' in log_types:
            subdirs_to_clean = SUBDIRECTORIES
        else:
            reverse_mapping = {v: k for k, v in LOG_TYPE_MAPPING.items()}
            subdirs_to_clean = [reverse_mapping[log_type] for log_type in log_types if log_type in reverse_mapping]

    for subdir in subdirs_to_clean:
        try:
            logging.info(f"Cleaning subdirectory: {subdir}")
            stats = first_pass(subdir)
            cleaned_data = second_pass(subdir, stats)
            if not cleaned_data.empty:
                if subdir in LOG_TYPE_MAPPING:
                    cleaned_filename = f"{LOG_TYPE_MAPPING[subdir]}_cleaned.csv"
                    save_data(cleaned_data, CLEANED_DIR, cleaned_filename)
                else:
                    logging.warning(f"Subdirectory '{subdir}' not found in LOG_TYPE_MAPPING. Skipping save.")
            logging.info(f"Completed cleaning {subdir}")
        except Exception as e:
            logging.error(f"Error cleaning {subdir}: {str(e)}")
            continue

if __name__ == "__main__":
    main()