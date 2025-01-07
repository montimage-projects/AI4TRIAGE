import csv
import sys
import numpy as np
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
import pandas as pd

def load_and_pad_labeled_data(file_path):
    """Load CSV file and pad rows to handle missing columns."""
    rows = []
    max_columns = 0
    csv.field_size_limit(sys.maxsize)

    with open(file_path, 'rt', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            rows.append(row)
            if len(row) > max_columns:
                max_columns = len(row)

    # Extract header
    header = rows[0]
    # Pad rows
    padded_rows = [row + [np.nan] * (max_columns - len(row)) for row in rows[1:]]
   
    return pd.DataFrame(padded_rows, columns=header), max_columns


def preprocess_data(data):
    """Preprocess the data to handle missing values and encode categorical columns."""
    # Assume the first column is the label
    # print("Column name:", data.columns.tolist())
    label_column = data.iloc[:, 0]
    features = data.iloc[:, 1:]  # Exclude the first column (attack_label)
    
    # Convert all NaN strings to actual NaN values
    features.replace('NaN', np.nan, inplace=True)

    # Handle missing values: fill numeric columns with median, categorical with mode
    numeric_columns = features.select_dtypes(include=np.number).columns
    categorical_columns = features.select_dtypes(exclude=np.number).columns

    for col in numeric_columns:
        features[col].fillna(features[col].median(), inplace=True)
    for col in categorical_columns:
        features[col].fillna(features[col].mode()[0], inplace=True)

    # Apply label encoding to categorical columns
    label_encoder = LabelEncoder()
    for col in categorical_columns:
        features[col] = label_encoder.fit_transform(features[col].astype(str))

    # Recombine label column with features
    data_cleaned = pd.concat([label_column.rename("attack_label"), features], axis=1)
    return data_cleaned


def calculate_feature_importance(data_cleaned):
    """Calculate feature importance using RandomForestClassifier."""
    # Separate features and labels
    # print("Column name:", data_cleaned.columns.tolist())
    X = data_cleaned.drop(columns=["attack_label"])
    y = data_cleaned["attack_label"]

    # Encode labels if necessary
    if y.dtype == 'object' or isinstance(y, pd.Categorical):
        y = LabelEncoder().fit_transform(y)

    # Train a RandomForest model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)

    # Extract feature importances
    importances = model.feature_importances_
    feature_names = X.columns

    # Create a DataFrame of feature importances
    feature_importance_df = pd.DataFrame({
        "Feature": feature_names,
        "Importance": importances
    }).sort_values(by="Importance", ascending=False)

    return feature_importance_df


def main():
    # Check for command-line arguments
    if len(sys.argv) < 3:
        print("Usage: python processData.py <input_csv_file> <output_file>")
        sys.exit(1)

    labeled_file = sys.argv[1]
    output_file = sys.argv[2]
    
    # Load and preprocess the data
    data, _ = load_and_pad_labeled_data(labeled_file)
    print("Column name:", data.columns.tolist())
    data_cleaned = preprocess_data(data)

    # Calculate feature importance
    feature_importance_df = calculate_feature_importance(data_cleaned)

    # Get top 15 features
    top_15_features = feature_importance_df.head(15)

    # Print top 15 features in the desired format
    for index, row in top_15_features.iterrows():
        print(f"{index},{row['Feature']},{row['Importance']}")

    # Save cleaned data and top features to files
    data_cleaned.to_csv(output_file, index=False, encoding="utf-8")
    top_15_features.to_csv("top_15_features.csv", index=False, encoding="utf-8",mode ='a')


if __name__ == "__main__":
    main()
