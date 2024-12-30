import csv
import sys
import numpy as np
from sklearn.preprocessing import LabelEncoder
import pandas as pd

# Function to convert a string to a float, handling errors
def convert_to_float(value):
    try:
        return float(value.strip())
    except ValueError:
        return np.nan  # Return NaN for non-convertible values

# Function to load and pad labeled data
def load_and_pad_labeled_data(file_path):
    rows = []
    
    max_columns = 0
    csv.field_size_limit(sys.maxsize)
    # Read the CSV file and find the maximum number of columns
    with open(file_path, 'rt') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            rows.append(row)
            if len(row) > max_columns:
                max_columns = len(row)
        

    # Pad rows with fewer columns with 'NaN' to match max_columns
    padded_rows = []
    for row in rows:
        if len(row) < max_columns:
            row += ['NaN'] * (max_columns - len(row))  # Pad with 'NaN'
        padded_rows.append(row)
    
    return padded_rows, max_columns

# Function to split labels and features
def split_labels_and_features(padded_rows):
    labels = []
    features = []
    
    for row in padded_rows:
        labels.append(row[0])  # First column is the label
        feature_values = [convert_to_float(value) for value in row[1:]]  # Convert remaining columns to float
        features.append(feature_values)
    
    return np.array(features), np.array(labels)

def main():
    # Load and pad labeled data
    if len(sys.argv) < 3:
        print("Usage: python processData.py <input_csv_file> <output_csv_file>")
        sys.exit(1)
    
    labeled_file=(sys.argv[1])   
    output_file = (sys.argv[2])
 
    data, max_columns = load_and_pad_labeled_data(labeled_file)
    data = pd.DataFrame(data)
    # Assume the first column contains the labels
    eventdate_column = data.iloc[:, 0]
    data_without_first_column = data.iloc[:, 1:] 
    # Calculate the missing value ratio for columns excluding the first
    missing_ratio = data_without_first_column.isnull().mean()
           
    # Determine the threshold for dropping columns with majority missing values
    threshold = 0.7  # Set threshold to 70%
    columns_to_drop = missing_ratio[missing_ratio > threshold].index  # Find columns with missing ratio exceeding the threshold

    # Drop these columns
    data_cleaned = data.drop(columns=columns_to_drop)
    data_cleaned.insert(0, 'attack_label', eventdate_column)

    # Identify numeric and categorical columns in the remaining columns
    numeric_columns = data_cleaned.select_dtypes(include=['number']).columns  # Find numeric columns
    categorical_columns = data_cleaned.select_dtypes(exclude=['number']).columns  # Find categorical columns

    # Fill missing values in numeric columns with median
    for col in numeric_columns:
        data_cleaned[col].fillna(data_cleaned[col].median(), inplace=True)  # Fill with median
        
    # Fill missing values in categorical columns with mode
    for col in categorical_columns:
        mode_value = data_cleaned[col].mode()[0]  # Calculate mode
        data_cleaned[col].fillna(mode_value, inplace=True)  # Fill with mode
        
    # Apply label encoding
    label_encoder = LabelEncoder()  # Create LabelEncoder instance
    for col in categorical_columns:
        data_cleaned[col] = label_encoder.fit_transform(data_cleaned[col].astype(str))
 
    # data['eventdate'] = label_encoder.fit_transform(data['eventdate'].astype(str))  # Apply label encoding to categorical columns

    # Save the processed DataFrame to a CSV file

    data_cleaned.to_csv(output_file, index=False)
    print(f"Processed data saved to {output_file}!")
if __name__ == "__main__":
    main()    

