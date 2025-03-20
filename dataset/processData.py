import sys
import pandas as pd
import numpy as np

# Function to process a CSV file in chunks
def process_large_csv(input_file, output_file, chunksize=100000):
    # Initialize an empty list to store processed chunks
    processed_chunks = []
    
    # Read the CSV file in chunks
    for chunk in pd.read_csv(input_file, chunksize=chunksize, low_memory=False):
        # Drop columns where > 70% of values are missing
        missing_ratio = chunk.isnull().mean()
        columns_to_drop = missing_ratio[missing_ratio > 0.7].index
        chunk.drop(columns=columns_to_drop, inplace=True)

        # Identify numeric and categorical columns
        numeric_columns = chunk.select_dtypes(include=['number']).columns
        categorical_columns = chunk.select_dtypes(exclude=['number']).columns

        # Fill missing values in numeric columns with median
        chunk[numeric_columns] = chunk[numeric_columns].fillna(chunk[numeric_columns].median())

        # Fill missing values in categorical columns with mode
        for col in categorical_columns:
            if not chunk[col].dropna().empty:  # Ensure mode() calculation has non-empty values
                mode_value = chunk[col].mode()[0]
                chunk[col].fillna(mode_value, inplace=True)

        # Encode categorical variables using factorization (memory-efficient)
        for col in categorical_columns:
            chunk[col] = pd.factorize(chunk[col])[0]

        # Append the processed chunk to the list
        processed_chunks.append(chunk)

    # Concatenate all processed chunks into a single DataFrame
    final_data = pd.concat(processed_chunks, ignore_index=True)

    # Save the processed DataFrame to CSV
    final_data.to_csv(output_file, index=False)
    print(f"Processed data saved to {output_file}!")

# Main function
def main():
    if len(sys.argv) < 3:
        print("Usage: python processData.py <input_csv_file> <output_csv_file>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]

    # Process the large CSV file efficiently
    process_large_csv(input_file, output_file)

if __name__ == "__main__":
    main()
