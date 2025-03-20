import pandas as pd
import sys
import glob

def merge_processed_logs(input_folder, output_file):
    """
    Merges all processed CSV files into a single dataset.
    Assumes all files have a standardized structure (same columns, including 'timestamp').
    """
    all_files = glob.glob(f"{input_folder}/*.csv")
    if not all_files:
        print("No processed CSV files found in the specified folder.")
        return
    
    dataframes = [pd.read_csv(file) for file in all_files]
    
    # Concatenate all processed data
    merged_data = pd.concat(dataframes, ignore_index=True)

    # Sort data by timestamp (important for attack sequence detection)
    merged_data.sort_values(by="timestamp", inplace=True)

    # Save the merged dataset
    merged_data.to_csv(output_file, index=False)
    print(f" Merged dataset saved to {output_file}")

# Main function
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python merge.py <processed_logs_directory> <output_merged_csv>")
        sys.exit(1)

    input_folder = sys.argv[1]
    output_file = sys.argv[2]

    merge_processed_logs(input_folder, output_file)
