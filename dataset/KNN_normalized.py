import sys
import pandas as pd
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import classification_report, accuracy_score
import joblib
from sklearn.preprocessing import StandardScaler

def load_data_in_chunks(file_path, label_column, chunksize=100000):
    """
    Load data in chunks to handle large files.
    """
    chunks = []
    for chunk in pd.read_csv(file_path, chunksize=chunksize, low_memory=False):
        # Drop columns where > 70% of values are missing
        missing_ratio = chunk.isnull().mean()
        columns_to_drop = missing_ratio[missing_ratio > 0.7].index
        chunk.drop(columns=columns_to_drop, inplace=True)

        # Fill missing values in numeric columns with median
        chunk.fillna(chunk.median(numeric_only=True), inplace=True)

        chunks.append(chunk)

    data = pd.concat(chunks, ignore_index=True)
    print(f"Loaded large dataset: {len(data)} rows")
    
    X = data.drop(columns=[label_column])  # Features
    y = data[label_column]  # Labels

    return train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

def balance_data(X_train, y_train):
    """
    Balance the training data: Undersample the majority class first, then apply SMOTE.
    """
    class_counts = y_train.value_counts()
    print("\n Original Class Distribution:\n", class_counts)

    # Identify the majority class (largest value in the dataset)
    majority_class = class_counts.idxmax()
    max_attack_count = class_counts.drop(majority_class, errors="ignore").max()

    # Set target count for the majority class (keep only twice the largest attack)
    target_majority_count = max_attack_count * 2  

    # Define undersampling strategy
    undersample_strategy = {majority_class: min(target_majority_count, class_counts[majority_class])}
    for attack in class_counts.index:
        if attack != majority_class:
            undersample_strategy[attack] = class_counts[attack]  

    # Apply Random Undersampling
    rus = RandomUnderSampler(sampling_strategy=undersample_strategy, random_state=42)
    X_resampled, y_resampled = rus.fit_resample(X_train, y_train)

    # Apply SMOTE to oversample minority classes
    smote = SMOTE(sampling_strategy="auto", random_state=42)
    X_resampled, y_resampled = smote.fit_resample(X_resampled, y_resampled)

    print("\n Resampled Class Distribution:\n", pd.Series(y_resampled).value_counts())

    return X_resampled, y_resampled

def scale_data(X_train, X_test):
    """
    Standardize the data using StandardScaler.
    """
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    return X_train_scaled, X_test_scaled, scaler

def train_knn_model(X_train, y_train, n_neighbors=5, metric="euclidean"):
    """
    Train a KNN model with the given parameters.
    """
    knn_model = KNeighborsClassifier(n_neighbors=n_neighbors, metric=metric, n_jobs=-1)
    knn_model.fit(X_train, y_train)
    return knn_model

def evaluate_model(model, X_test, y_test):
    """
    Evaluate the model on the test set.
    """
    y_pred = model.predict(X_test)
    print("🔹 Accuracy:", accuracy_score(y_test, y_pred))
    print("\n🔹 Classification Report:\n", classification_report(y_test, y_pred))

def save_model_and_scaler(model, scaler, model_path="knn_model.joblib", scaler_path="scaler.pkl"):
    """
    Save the trained model and scaler for later use.
    """
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    print(f"KNN model saved as {model_path}")
    print(f"Scaler saved as {scaler_path}")

# Main script execution
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python KNN_normalized.py <merged_csv_file>")
        sys.exit(1)

    file_path = sys.argv[1]
    label_column = "attack_label"

    # Step 1: Load large dataset in chunks
    X_train, X_test, y_train, y_test = load_data_in_chunks(file_path, label_column)

    # Step 2: Balance training data
    X_train_resampled, y_train_resampled = balance_data(X_train, y_train)

    # Step 3: Scale data
    X_train_scaled, X_test_scaled, scaler = scale_data(X_train_resampled, X_test)

    # if skip balance and scale data
    

    # Step 4: Train KNN model
    knn_model = train_knn_model(X_train_scaled, y_train_resampled)

    # Step 5: Evaluate model
    evaluate_model(knn_model, X_test_scaled, y_test)

    # Step 6: Save model and scaler
    save_model_and_scaler(knn_model, scaler)
