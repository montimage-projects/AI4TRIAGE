import sys
import pandas as pd
import glob
from imblearn.over_sampling import SMOTE
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib
from sklearn.preprocessing import StandardScaler

def merge_csv_files(input_folder, output_file):
    """
    Merge all CSV files from a folder into one file.
    """
    all_files = glob.glob(f"{input_folder}/*.csv")
    if not all_files:
        print("No CSV files found in the specified folder.")
        return
    
    dataframes = [pd.read_csv(file) for file in all_files]
    merged_data = pd.concat(dataframes, ignore_index=True)
    merged_data.to_csv(output_file, index=False)
    print(f"Merged data saved to {output_file}")

def preprocess_data(file_path, label_column):
    """
    Load data, separate features and labels, and split into training and test sets.
    """
    data = pd.read_csv(file_path)
    X = data.drop(columns=[label_column])  # Features
    y = data[label_column]  # Labels
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    print(f"Training size: {len(X_train)}, Test size: {len(X_test)}")
    return X_train, X_test, y_train, y_test

def balance_data(X_train, y_train):
    """
    Balance the training data using SMOTE.
    """
    smote = SMOTE(random_state=42)
    X_resampled, y_resampled = smote.fit_resample(X_train, y_train)
    print(f"Resampled training size: {len(X_resampled)}")
    return X_resampled, y_resampled

def scale_data(X_train, X_test):
    """
    Standardize the data using StandardScaler.
    """
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    return X_train_scaled, X_test_scaled, scaler

def train_knn_model(X_train, y_train, n_neighbors=5, metric='euclidean'):
    """
    Train a KNN model with the given parameters.
    """
    knn_model = KNeighborsClassifier(n_neighbors=n_neighbors, metric=metric)
    knn_model.fit(X_train, y_train)
    return knn_model

def evaluate_model(model, X_test, y_test):
    """
    Evaluate the model on the test set.
    """
    y_pred = model.predict(X_test)
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print("Classification Report:\n", classification_report(y_test, y_pred))

def save_model_and_scaler(model, scaler, model_path="Models/knn_model.joblib", scaler_path="Models/scaler.pkl"):
    """
    Save the trained model and scaler for later use.
    """
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    print(f"KNN model saved as {model_path}")
    print(f"Scaler saved as {scaler_path}")

# Main script execution
if __name__ == "__main__":
    # Step 1: Merge CSV files
    if len(sys.argv) < 3:
        print("Usage: python KNN1.py <directory *.csv file> <output_csv_file>")
        sys.exit(1)
    input_folder = sys.argv[1]
    output_file =sys.argv[2]
    merge_csv_files(input_folder, output_file)
    
    # Step 2: Preprocess data
    label_column = 'attack_label'
    X_train, X_test, y_train, y_test = preprocess_data(output_file, label_column)
    
    # Step 3: Balance training data
    X_train_resampled, y_train_resampled = balance_data(X_train, y_train)
    
    # Step 4: Scale data
    X_train_scaled, X_test_scaled, scaler = scale_data(X_train_resampled, X_test)
    
    # Step 5: Train KNN model
    knn_model = train_knn_model(X_train_scaled, y_train_resampled)
    
    # Step 6: Evaluate model
    evaluate_model(knn_model, X_test_scaled, y_test)
    
    # Step 7: Save model and scaler
    save_model_and_scaler(knn_model, scaler)
