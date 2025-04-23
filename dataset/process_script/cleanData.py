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

# Directories
RAW_DIR = "/home/montimage/anhhaobui/cbx/AI4TRIAGE/Datasets/raw/"
CLEANED_DIR = "/home/montimage/anhhaobui/cbx/AI4TRIAGE/Datasets/cleaned/"
PROCESSED_DIR = "/home/montimage/anhhaobui/cbx/AI4TRIAGE/Datasets/processed/"

# Subdirectories for raw data
SUBDIRECTORIES = ["firewall_attack_chunks", "mail_attack_chunks", "proxy_attack_chunks", "xdr_alerts_attack_chunks"]

# Log type mapping
LOG_TYPE_MAPPING = {
    "firewall_attack_chunks": "firewall",
    "mail_attack_chunks": "mail",
    "proxy_attack_chunks": "proxy",
    "xdr_alerts_attack_chunks": "xdr"
}

class GlobalStatistics:
    """Class to hold global statistics computed in the first pass"""
    def __init__(self):
        self.missing_ratios = {}
        self.medians = {}
        self.means = {}
        self.stds = {}
        self.unique_counts = {}
        self.total_rows = 0
        self.median_values = {}  # Store actual median values instead of lists
        self.column_dtypes = {}  # Store column data types
        
    def update_from_chunk(self, chunk):
        """Update running statistics with a new chunk"""
        n = len(chunk)
        if self.total_rows == 0:
            self._initialize_from_chunk(chunk)
        else:
            self._update_statistics(chunk, n)
        self.total_rows += n

    def _initialize_from_chunk(self, chunk):
        """Initialize statistics from the first chunk"""
        # Store data types for all columns
        self.column_dtypes = chunk.dtypes.to_dict()
        
        # Initialize statistics for all columns
        for col in chunk.columns:
            self.missing_ratios[col] = chunk[col].isnull().sum()
            self.unique_counts[col] = set(chunk[col].dropna().unique())
            
            # Handle numeric columns
            if pd.api.types.is_numeric_dtype(chunk[col]):
                self.means[col] = chunk[col].mean()
                self.stds[col] = chunk[col].var() * len(chunk)
                self.median_values[col] = chunk[col].median()

    def _update_statistics(self, chunk, n):
        """Update running statistics with a new chunk"""
        # Handle new columns that appear in subsequent chunks
        new_columns = set(chunk.columns) - set(self.missing_ratios.keys())
        if new_columns:
            for col in new_columns:
                self.missing_ratios[col] = 0
                self.unique_counts[col] = set()
                if pd.api.types.is_numeric_dtype(chunk[col]):
                    self.means[col] = 0
                    self.stds[col] = 0
                    self.median_values[col] = 0
        
        for col in chunk.columns:
            # Update missing counts
            self.missing_ratios[col] += chunk[col].isnull().sum()
            
            # Update statistics for numeric columns
            if pd.api.types.is_numeric_dtype(chunk[col]):
                if col not in self.means:
                    # Initialize statistics for new numeric columns
                    self.means[col] = chunk[col].mean()
                    self.stds[col] = chunk[col].var() * n
                    self.median_values[col] = chunk[col].median()
                else:
                    # Update existing statistics
                    old_mean = self.means[col]
                    chunk_mean = chunk[col].mean()
                    delta = chunk_mean - old_mean
                    self.means[col] = old_mean + (delta * n) / self.total_rows
                    
                    # Update sum of squared deviations
                    self.stds[col] += chunk[col].var() * (n - 1)
                    
                    # Update median (approximate using running average)
                    old_median = self.median_values[col]
                    chunk_median = chunk[col].median()
                    self.median_values[col] = (old_median * self.total_rows + chunk_median * n) / (self.total_rows + n)
            
            # Update unique values
            self.unique_counts[col].update(chunk[col].dropna().unique())

    def finalize_statistics(self):
        """Finalize the computation of statistics"""
        for col in self.missing_ratios:
            self.missing_ratios[col] /= self.total_rows
            if col in self.means:
                self.stds[col] = np.sqrt(self.stds[col] / (self.total_rows - 1))
            self.unique_counts[col] = len(self.unique_counts[col])

def extract_evento(text, log_type):
    """
    Extract timestamp from evento column, handling various JSON formats and errors.
    Returns None if extraction fails.
    """
    if pd.isna(text):  # Check if input is NaN or None
        return None
        
    if log_type == "mail":
        try:
            # Try to clean the string before parsing
            clean_text = str(text).strip().replace("'", '"')
            data = json.loads(clean_text)
            return data.get('messageTime')
        except (json.JSONDecodeError, TypeError, AttributeError) as e:
            logging.debug(f"Error extracting 'messageTime' from evento: {e}")
            # Try regex fallback if JSON parsing fails
            import re
            try:
                match = re.search(r'"messageTime"\s*:\s*"([^"]+)"', str(text))
                if match:
                    return match.group(1)
            except Exception as e:
                logging.debug(f"Regex extraction failed: {e}")
            return None
            
    elif log_type == "xdr":
        try:
            # Try to clean the string before parsing
            clean_text = str(text).strip().replace("'", '"')
            data = json.loads(clean_text)
            # Try different possible key names
            for key in ['_eventdate', 'eventdate', 'event_date']:
                if key in data:
                    return data[key]
            return None
        except (json.JSONDecodeError, TypeError, AttributeError) as e:
            logging.debug(f"Error extracting timestamp from evento: {e}")
            # Try regex fallback if JSON parsing fails
            import re
            try:
                match = re.search(r'"(?:_eventdate|eventdate|event_date)"\s*:\s*"([^"]+)"', str(text))
                if match:
                    return match.group(1)
            except Exception as e:
                logging.debug(f"Regex extraction failed: {e}")
            return None
    
    return None

def first_pass(subdir, chunksize=100000):
    """First pass: Compute global statistics"""
    logging.info(f"Starting first pass for {subdir}: Computing global statistics...")
    stats = GlobalStatistics()
    subdir_path = os.path.join(RAW_DIR, subdir)
    
    for file in os.listdir(subdir_path):
        if file.endswith(".csv"):
            file_path = os.path.join(subdir_path, file)
            # Read CSV with low_memory=False to avoid DtypeWarning
            for chunk in tqdm(pd.read_csv(file_path, chunksize=chunksize, low_memory=False), 
                            desc=f"Processing {file}"):
                try:
                    stats.update_from_chunk(chunk)
                except Exception as e:
                    logging.warning(f"Error processing chunk in {file}: {str(e)}")
                    continue
    
    stats.finalize_statistics()
    logging.info("First pass completed: Global statistics computed")
    return stats

def second_pass(subdir, stats, output_dir, chunksize=100000, missing_threshold=0.85):
    """Second pass: Apply transformations using precomputed statistics"""
    logging.info(f"Starting second pass for {subdir}: Applying transformations...")
    
    # Get log type for this subdirectory
    log_type = LOG_TYPE_MAPPING.get(subdir, "unknown")
    logging.info(f"Processing log type: {log_type}")
    
    # Identify constant columns (columns with only one unique value)
    constant_cols = set(col for col, unique_count in stats.unique_counts.items() 
                       if unique_count <= 1)
    
    # Identify columns with high missing rates 
    high_missing_cols = set(col for col, ratio in stats.missing_ratios.items() 
                           if ratio > missing_threshold)
    
    # Log the specific reasons for removal
    if constant_cols:
        logging.info(f"Columns to remove due to constant values: {sorted(constant_cols)}")
    if high_missing_cols:
        logging.info(f"Columns to remove due to high missing rate: {sorted(high_missing_cols)}")
    
    # Combine columns to remove (using set union)
    cols_to_remove = constant_cols.union(high_missing_cols)
    logging.info(f"Total unique columns to remove: {sorted(cols_to_remove)}")
    
    processed_chunks = []
    subdir_path = os.path.join(RAW_DIR, subdir)
    
    for file in os.listdir(subdir_path):
        if file.endswith(".csv"):
            file_path = os.path.join(subdir_path, file)
            for chunk in tqdm(pd.read_csv(file_path, chunksize=chunksize, low_memory=False),
                            desc=f"Processing {file}"):
                # Drop constant columns and high missing columns
                chunk = chunk.drop(columns=cols_to_remove, errors='ignore')
                
                # Add log_type column
                chunk['log_type'] = log_type

                # If the input file has the 'evento' column, extract data from it.
                if log_type in ["mail", "xdr"]:
                    if 'evento' in chunk.columns:
                        # Create or ensure target column exists
                        target_col = 'ts' if log_type == "mail" else '_eventdate'
                        if target_col not in chunk.columns:
                            chunk[target_col] = None
                        
                        # Extract values only where target column is null
                        chunk[target_col] = chunk.apply(
                            lambda row: extract_evento(row['evento'], log_type) 
                            if pd.isnull(row[target_col]) else row[target_col],
                            axis=1
                        )
                
                # Fill missing values in numeric columns
                numeric_columns = chunk.select_dtypes(include=['number']).columns
                for col in numeric_columns:
                    if col in stats.median_values:
                        chunk[col] = chunk[col].fillna(stats.median_values[col])
                
                if not chunk.empty:
                    processed_chunks.append(chunk)
    
    # Combine all processed chunks
    if processed_chunks:
        final_data = pd.concat(processed_chunks, ignore_index=True)
        
        # Reorder columns to put log_type at the beginning
        cols = list(final_data.columns)
        if 'log_type' in cols:
            cols.remove('log_type')
            final_data = final_data[['log_type'] + cols]  # Fixed: Use DataFrame indexing instead of list
        
        return final_data
    else:
        logging.warning("No data remained after processing")
        return pd.DataFrame()

def save_data(data, output_dir, filename):
    """
    Save the processed data to the specified directory.
    """
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, filename)
    data.to_csv(output_path, index=False)
    logging.info(f"Data saved to {output_path}")

def main():
    """Main function implementing the two-pass strategy with selective log type processing"""
    parser = argparse.ArgumentParser(description='Clean log data with options to process specific log types.')
    parser.add_argument('log_types', nargs='*', type=str,
                      help='Log types to process (default: all). Options: all, firewall, mail, proxy, xdr')
    args = parser.parse_args()

    # Validate and process log types
    valid_types = {'all', 'firewall', 'mail', 'proxy', 'xdr'}
    
    # If no arguments provided, default to processing all
    if not args.log_types:
        subdirs_to_process = SUBDIRECTORIES
    else:
        # Convert input to lowercase for case-insensitive comparison
        log_types = [lt.lower() for lt in args.log_types]
        
        # Validate input log types
        invalid_types = set(log_types) - valid_types
        if invalid_types:
            logging.error(f"Invalid log type(s): {invalid_types}")
            logging.error(f"Valid choices are: {sorted(valid_types)}")
            sys.exit(1)
            
        # If 'all' is specified, process everything
        if 'all' in log_types:
            subdirs_to_process = SUBDIRECTORIES
        else:
            # Map log types back to their subdirectory names
            reverse_mapping = {v: k for k, v in LOG_TYPE_MAPPING.items()}
            subdirs_to_process = [reverse_mapping[log_type] for log_type in log_types]

    # Process each selected subdirectory
    for subdir in subdirs_to_process:
        try:
            logging.info(f"Processing subdirectory: {subdir}")
            
            # First pass: Compute global statistics
            stats = first_pass(subdir)
            
            # Second pass: Apply transformations
            processed_data = second_pass(subdir, stats, PROCESSED_DIR)
            
            if not processed_data.empty:
                # Save processed data
                processed_filename = f"{LOG_TYPE_MAPPING[subdir]}_cleaned.csv"
                save_data(processed_data, CLEANED_DIR, processed_filename)
            
            logging.info(f"Completed processing {subdir}")
            
        except Exception as e:
            logging.error(f"Error processing {subdir}: {str(e)}")
            continue

if __name__ == "__main__":
    main()