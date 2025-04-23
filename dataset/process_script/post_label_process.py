import sys
import pandas as pd
import numpy as np
import logging
from tqdm import tqdm
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from collections import defaultdict
from imblearn.under_sampling import RandomUnderSampler
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('post_processing.log'),
        logging.StreamHandler()
    ]
)

class PostLabelStatistics:
    """Class to hold statistics for labeled data processing"""
    def __init__(self):
        self.means = {}
        self.stds = {}
        self.categorical_columns = set()
        self.label_encoders = {}
        self.class_distribution = defaultdict(int)
        self.total_rows = 0
        self.scaler = MinMaxScaler(feature_range=(0, 1))  # Initialize scaler for MinMax scaling
        self.numeric_columns = set()
        self.feature_ranges = {}  # Track min/max values for features
        
    def update_from_chunk(self, chunk):
        """Update statistics from a new chunk"""
        n = len(chunk)
        if self.total_rows == 0:
            self._initialize_from_chunk(chunk)
        else:
            self._update_statistics(chunk, n)
        self.total_rows += n

    def _initialize_from_chunk(self, chunk):
        """Initialize statistics from first chunk"""
        # Identify categorical and numeric columns
        for col in chunk.columns:
            if col != 'attack_label':  # Skip label column
                # Try to enforce numeric conversion.
                series = pd.to_numeric(chunk[col], errors='coerce')
                if series.notnull().sum() > 0:
                    self.means[col] = series.mean()
                    # Multiply variance by count of non-null values for online updating.
                    self.stds[col] = series.var() * series.notnull().sum()
                    self.numeric_columns.add(col)  # Track numeric columns
                    self.feature_ranges[col] = {
                        'min': series.min(),
                        'max': series.max()
                    }
                else:
                    self.categorical_columns.add(col)
                    self.label_encoders[col] = LabelEncoder()
                    
        # Update class distribution
        labels = chunk['attack_label'].value_counts()
        for label, count in labels.items():
            self.class_distribution[label] += count

    def _update_statistics(self, chunk, n):
        """Update running statistics with new chunk using enforced numeric conversion"""
        for col in self.means.keys():
            series = pd.to_numeric(chunk[col], errors='coerce')
            chunk_mean = series.mean()
            old_mean = self.means[col]
            delta = chunk_mean - old_mean
            # Update running mean
            self.means[col] = old_mean + (delta * n) / self.total_rows
            # Update running sum of variances (using non-null count)
            self.stds[col] += series.var() * (n - 1)
            
        # Update min/max values for numeric columns
        for col in self.numeric_columns:
            if col in chunk.columns:
                series = pd.to_numeric(chunk[col], errors='coerce')
                current_min = series.min()
                current_max = series.max()
                self.feature_ranges[col]['min'] = min(self.feature_ranges[col]['min'], current_min)
                self.feature_ranges[col]['max'] = max(self.feature_ranges[col]['max'], current_max)
        
        # Update class distribution
        labels = chunk['attack_label'].value_counts()
        for label, count in labels.items():
            self.class_distribution[label] += count

    def finalize_statistics(self):
        """Finalize statistics computation"""
        # Compute final standard deviations using total_rows - 1 as degrees of freedom
        for col in self.means.keys():
            self.stds[col] = np.sqrt(self.stds[col] / (self.total_rows - 1))
            
        logging.info("Class distribution:")
        for label, count in self.class_distribution.items():
            logging.info(f"Label {label}: {count} samples")

def first_pass(input_file: str, chunksize: int = 100000) -> PostLabelStatistics:
    """First pass: compute statistics from labeled data"""
    logging.info("Starting first pass: Computing statistics...")
    stats = PostLabelStatistics()
    
    with tqdm(desc="First pass", unit="rows") as pbar:
        for chunk in pd.read_csv(input_file, chunksize=chunksize, low_memory=False):
            stats.update_from_chunk(chunk)
            pbar.update(len(chunk))
    
    stats.finalize_statistics()
    logging.info("First pass completed")
    return stats

def second_pass(input_file: str, output_file: str, stats: PostLabelStatistics, 
                chunksize: int = 100000, z_threshold: float = 10.0):
    """Second pass: apply transformations using computed statistics"""
    logging.info("Starting second pass: Applying transformations...")
    
    processed_chunks = []
    with tqdm(desc="Second pass", unit="rows") as pbar:
        for chunk in pd.read_csv(input_file, chunksize=chunksize, low_memory=False):
            # 1. Encode categorical variables
            for col in stats.categorical_columns:
                if col in chunk.columns:
                    chunk[col] = stats.label_encoders[col].fit_transform(chunk[col])
            
            # 2. Remove outliers using robust IQR on numeric columns
            iqr_threshold = 1.5  # Adjust this value as needed
            for col in stats.numeric_columns:
                if col in chunk.columns:
                    series = pd.to_numeric(chunk[col], errors='coerce')
                    Q1 = series.quantile(0.25)
                    Q3 = series.quantile(0.75)
                    IQR = Q3 - Q1
                    lower_bound = Q1 - iqr_threshold * IQR
                    upper_bound = Q3 + iqr_threshold * IQR
                    outliers = series[(series < lower_bound) | (series > upper_bound)].count()
                    if outliers > 0:
                        logging.info(f"Column {col}: {outliers} outliers found outside [{lower_bound}, {upper_bound}]")
                    chunk = chunk[(series >= lower_bound) & (series <= upper_bound)]

            total_rows_after = len(chunk)
            
            # 3. Scale numeric features using MinMaxScaler
            if not chunk.empty:
                numeric_data = chunk[list(stats.numeric_columns)]
                if not numeric_data.empty:
                    scaled_data = stats.scaler.fit_transform(numeric_data)
                    chunk[list(stats.numeric_columns)] = scaled_data
                processed_chunks.append(chunk)
            
            pbar.update(len(chunk))
    
    # After processing all chunks
    if not processed_chunks:
        logging.error("No objects to concatenate: processed_chunks is empty. Check filtering criteria!")
        sys.exit("No objects to concatenate")
    final_data = pd.concat(processed_chunks, ignore_index=True)
    
    # NEW BALANCING APPROACH:
    logging.info("Balancing data: undersampling benign and oversampling attack classes...")

    # Separate benign (label 0) and attack (labels 1..N) samples
    df_benign = final_data[final_data['attack_label'] == 0]
    df_attack = final_data[final_data['attack_label'] != 0]

    # Get counts for each attack label and determine target_count as the maximum attack label count
    attack_counts = df_attack['attack_label'].value_counts()
    if attack_counts.empty:
        logging.error("No attack records found!")
        sys.exit("No attack records found!")
    target_count = attack_counts.max()
    logging.info(f"Target count for attack classes (highest attack label count): {target_count}")

    # Undersample benign samples to target_count if needed.
    benign_count = len(df_benign)
    if benign_count > target_count:
        logging.info(f"Undersampling benign class from {benign_count} to {target_count} samples")
        df_benign = df_benign.sample(n=target_count, random_state=42)

    # Identify attack labels that are below target_count.
    attack_over_labels = [label for label, count in attack_counts.items() if count < target_count]
    # Pass through labels that already have enough samples.
    df_attack_ok = df_attack[~df_attack['attack_label'].isin(attack_over_labels)]
    df_attack_final = df_attack_ok.copy()

    # For attack labels needing oversampling, split based on count:
    # Use SMOTE when count > 1; if count==1, use random oversampling.
    smote_labels = [label for label in attack_over_labels if attack_counts[label] > 1]
    random_labels = [label for label in attack_over_labels if attack_counts[label] == 1]

    if smote_labels:
        strategy = {label: target_count for label in smote_labels}
        df_attack_smote = df_attack[df_attack['attack_label'].isin(smote_labels)]
        X_smote = df_attack_smote.drop('attack_label', axis=1)
        y_smote = df_attack_smote['attack_label']
        min_attack_samples = min(attack_counts[label] for label in smote_labels)
        # Ensure k_neighbors is set low enough. (Note: SMOTE requires n_neighbors < n_samples)
        k_neighbors = min(5, min_attack_samples - 1) if min_attack_samples > 1 else 1
        logging.info(f"Using SMOTE with k_neighbors={k_neighbors} for labels: {smote_labels}")
        oversampler = SMOTE(random_state=42, sampling_strategy=strategy, k_neighbors=k_neighbors)
        X_res, y_res = oversampler.fit_resample(X_smote, y_smote)
        df_res_smote = pd.concat([pd.DataFrame(y_res, columns=['attack_label']),
                                  pd.DataFrame(X_res, columns=X_smote.columns)], axis=1)
        df_attack_final = pd.concat([df_attack_final, df_res_smote], ignore_index=True)

    if random_labels:
        logging.info(f"Applying random oversampling for labels with a single sample: {random_labels}")
        df_random = pd.concat([df_attack[df_attack['attack_label'] == label]
                               .sample(n=target_count, replace=True, random_state=42)
                               for label in random_labels], ignore_index=True)
        df_attack_final = pd.concat([df_attack_final, df_random], ignore_index=True)

    final_data_balanced = pd.concat([df_benign, df_attack_final], axis=0).reset_index(drop=True)
    
    try:
        final_data_balanced.to_csv(output_file, index=False)
        logging.info(f"Final data saved to {output_file}")
    except Exception as e:
        logging.error(f"Error writing final output: {e}")
        sys.exit(1)
    
    final_distribution = pd.Series(final_data_balanced['attack_label']).value_counts()
    logging.info("Final class distribution after balancing:")
    for label, count in final_distribution.items():
        logging.info(f"Label {label}: {count} samples")

def main():
    if len(sys.argv) < 3:
        print("Usage: python post_label_process.py <input_labeled_csv> <output_processed_csv>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    try:
        stats = first_pass(input_file)
        second_pass(input_file, output_file, stats)
        logging.info("Processing completed successfully")
    except Exception as e:
        logging.error(f"Error during processing: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()