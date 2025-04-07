import sys
import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler
import logging
import json

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logging.info("Processing started.")

# Function to process a single chunk
def process_chunk(chunk, undersample_label=0, target_column="attack_label", skip_undersample=False, skip_outliers=False):
    # Drop columns where > 70% of values are missing
    missing_ratio = chunk.isnull().mean()
    columns_to_drop = missing_ratio[missing_ratio > 0.7].index
    chunk.drop(columns=columns_to_drop, inplace=True)

    # Check if the chunk is empty after column removal
    if chunk.empty:
        logging.warning("Chunk is empty after column removal. Skipping further processing.")
        return chunk

    # Identify numeric and categorical columns
    numeric_columns = chunk.select_dtypes(include=['number']).columns
    categorical_columns = chunk.select_dtypes(exclude=['number']).columns

    # Fill missing values in numeric columns with median
    chunk[numeric_columns] = chunk[numeric_columns].fillna(chunk[numeric_columns].median())

    # Fill missing values in categorical columns with mode
    for col in categorical_columns:
        if not chunk[col].dropna().empty:  # Ensure mode() calculation has non-empty values
            mode_value = chunk[col].mode()[0]
            chunk.fillna({col: mode_value}, inplace=True)

    # Encode categorical variables using factorization (memory-efficient)
    for col in categorical_columns:
        chunk[col] = pd.factorize(chunk[col])[0]

    # Perform undersampling if not skipped
    if not skip_undersample and target_column in chunk.columns:
        majority_class = chunk[chunk[target_column] == undersample_label]
        minority_class = chunk[chunk[target_column] != undersample_label]

        # Check if there are no minority samples
        if minority_class.empty:
            logging.warning("Chunk contains only non-attack labels (label 0). Skipping undersampling.")
            return chunk

        # Limit the majority class to the size of the minority class
        majority_class = majority_class.sample(n=len(minority_class), random_state=42)
        chunk = pd.concat([majority_class, minority_class])

    # Check if the chunk is empty after undersampling
    if chunk.empty:
        logging.warning("Chunk is empty after undersampling. Skipping further processing.")
        return chunk

    # Remove outliers if not skipped
    if not skip_outliers:
        chunk_with_outliers_removed = remove_outliers(chunk, numeric_columns)

        # Check if the chunk is empty after outlier removal
        if chunk_with_outliers_removed.empty:
            logging.warning("Chunk is empty after outlier removal. Skipping outlier removal and using original chunk.")
            chunk_with_outliers_removed = chunk

        chunk = chunk_with_outliers_removed

    # Normalize numeric columns
    chunk = normalize_data(chunk, numeric_columns)

    return chunk

# Function to process a CSV file in chunks sequentially
def process_large_csv(input_file, output_file, chunksize=100000, undersample_label=0, target_column="attack_label"):
    # Initialize an empty list to store processed chunks
    processed_chunks = []

    # Read the CSV file in chunks
    for chunk in pd.read_csv(input_file, chunksize=chunksize, low_memory=False):
        logging.info(f"Processing a chunk of size {len(chunk)}...")
        processed_chunk = process_chunk(chunk, undersample_label, target_column)
        if not processed_chunk.empty:
            processed_chunks.append(processed_chunk)

    # Concatenate all processed chunks into a single DataFrame
    if processed_chunks:
        final_data = pd.concat(processed_chunks, ignore_index=True)

        # Save the processed DataFrame to CSV
        final_data.to_csv(output_file, index=False)
        print(f"Processed data saved to {output_file}!")

        # Save metadata
        save_metadata(final_data, output_file.replace('.csv', '_metadata.json'))
    else:
        logging.warning("The entire dataset is empty after processing. No output file will be created.")

# Function to clean a large CSV file without undersampling or outlier removal
def clean_large_csv(input_file, cleaned_file, chunksize=100000):
    # Initialize an empty list to store cleaned chunks
    cleaned_chunks = []

    # Read the CSV file in chunks
    for chunk in pd.read_csv(input_file, chunksize=chunksize, low_memory=False):
        logging.info(f"Cleaning a chunk of size {len(chunk)}...")
        # Perform cleaning (without undersampling or outlier removal)
        cleaned_chunk = process_chunk(chunk, undersample_label=None, target_column=None, skip_undersample=True, skip_outliers=True)
        if not cleaned_chunk.empty:
            cleaned_chunks.append(cleaned_chunk)

    # Concatenate all cleaned chunks into a single DataFrame
    if cleaned_chunks:
        final_cleaned_data = pd.concat(cleaned_chunks, ignore_index=True)

        # Save the cleaned DataFrame to a new CSV file
        final_cleaned_data.to_csv(cleaned_file, index=False)
        print(f"Cleaned data saved to {cleaned_file}!")
    else:
        logging.warning("The entire dataset is empty after cleaning. No cleaned file will be created.")

# Function to process the cleaned data as a whole
def process_cleaned_csv(cleaned_file, output_file, undersample_label=0, target_column="attack_label"):
    # Read the entire cleaned file into memory
    cleaned_data = pd.read_csv(cleaned_file, low_memory=False)
    logging.info(f"Processing the cleaned data with undersampling and outlier removal...")

    # Remove constant columns from the entire dataset
    cleaned_data = remove_constant_columns(cleaned_data, target_column)

    # Apply undersampling and outlier removal to the entire dataset
    processed_data = process_chunk(cleaned_data, undersample_label, target_column, skip_undersample=False, skip_outliers=False)

    # Save the processed data to a new CSV file
    if not processed_data.empty:
        processed_data.to_csv(output_file, index=False)
        print(f"Processed data saved to {output_file}!")
        save_metadata(processed_data, output_file.replace('.csv', '_metadata.json'))
    else:
        logging.warning("The entire dataset is empty after processing. No output file will be created.")

# Function to remove outliers
def remove_outliers(chunk, numeric_columns, z_threshold=5):
    for col in numeric_columns:
        if col in chunk.columns:
            z_scores = (chunk[col] - chunk[col].mean()) / chunk[col].std()
            chunk = chunk[(z_scores.abs() <= z_threshold)]
    if chunk.empty:
        logging.warning("All rows were removed as outliers. Consider relaxing the z_threshold.")
    return chunk

# Function to normalize numeric columns
def normalize_data(chunk, numeric_columns, label_column="attack_label"):
    if chunk.empty:
        logging.warning("Chunk is empty before normalization. Skipping normalization.")
        return chunk

    # Exclude the label column from normalization
    columns_to_normalize = [col for col in numeric_columns if col != label_column]

    if columns_to_normalize:
        scaler = MinMaxScaler()
        chunk[columns_to_normalize] = scaler.fit_transform(chunk[columns_to_normalize])
    else:
        logging.info("No numeric columns to normalize (excluding label column).")

    return chunk

# Function to remove constant columns
def remove_constant_columns(data, target_column="attack_label"):
    # Identify constant columns (excluding the target column)
    constant_columns = [col for col in data.columns if data[col].nunique() <= 1 and col != target_column]
    if constant_columns:
        logging.info(f"Removing constant columns: {constant_columns}")
        data.drop(columns=constant_columns, inplace=True)
    return data

# Function to save metadata
def save_metadata(data, output_file):
    if data.empty:
        metadata = {
            "num_rows": 0,
            "num_columns": 0,
            "class_distribution": {},
            "column_stats": {}
        }
        logging.warning("Dataset is empty. Saving empty metadata.")
    else:
        metadata = {
            "num_rows": len(data),
            "num_columns": len(data.columns),
            "class_distribution": data["attack_label"].value_counts().to_dict(),
            "column_stats": data.describe().to_dict()
        }
    with open(output_file, 'w') as f:
        json.dump(metadata, f, indent=4)

# Main function
def main():
    if len(sys.argv) < 4:
        print("Usage: python processData.py <input_csv_file> <cleaned_csv_file> <output_csv_file>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    cleaned_file = sys.argv[2]
    output_file = sys.argv[3]

    # Stage 1: Clean the data without undersampling or outlier removal
    clean_large_csv(input_file, cleaned_file)

    # Stage 2: Process the cleaned data with undersampling and outlier removal
    process_cleaned_csv(cleaned_file, output_file)

if __name__ == "__main__":
    main()
