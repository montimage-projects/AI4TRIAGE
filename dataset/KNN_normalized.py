import sys
import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import classification_report, accuracy_score, f1_score, precision_score, recall_score
import joblib
import json


# Load configuration
with open('dataset/config.json', 'r') as config_file:
    config = json.load(config_file)

# Get parameters for KNN_normalized
knn_config = config.get("KNN_normalized", {})
n_neighbors = knn_config.get("n_neighbors", 5)  # Default to 5
weights = knn_config.get("weights", "uniform")  # Default to "uniform"
metric = knn_config.get("metric", "euclidean")  # Default to "euclidean"
param_grid = knn_config.get("param_grid", {
    "n_neighbors": [3, 5, 7, 9],
    "weights": ["uniform", "distance"],
    "metric": ["euclidean", "manhattan"]
})


def load_preprocessed_data(file_path, label_column):
    """
    Load preprocessed data from a CSV file and handle missing values.
    """
    data = pd.read_csv(file_path)
    print(f"Loaded preprocessed dataset: {len(data)} rows")

    # Handle missing values
    if data.isnull().values.any():
        print("🔹 Missing values detected. Imputing missing values...")
        # Fill missing numeric values with the median
        data.fillna(data.median(numeric_only=True), inplace=True)

    X = data.drop(columns=[label_column])  # Features
    y = data[label_column]  # Labels

    return train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)


def perform_grid_search(X_train, y_train, param_grid, cv=5):
    """
    Perform grid search to find the best hyperparameters for the KNN model.
    """
    knn = KNeighborsClassifier(n_jobs=-1)
    grid_search = GridSearchCV(knn, param_grid, cv=cv, scoring="accuracy", n_jobs=-1)
    grid_search.fit(X_train, y_train)

    print("\n🔹 Best Parameters Found:", grid_search.best_params_)
    print("🔹 Best Cross-Validation Accuracy:", grid_search.best_score_)

    return grid_search.best_params_


def update_config_file(config_path, best_params):
    """
    Update the config.json file with the best parameters.
    """
    with open(config_path, 'r') as config_file:
        config = json.load(config_file)

    # Update the KNN_normalized section with the best parameters
    config["KNN_normalized"].update(best_params)

    with open(config_path, 'w') as config_file:
        json.dump(config, config_file, indent=4)
    print(f"🔹 Updated {config_path} with best parameters: {best_params}")


def train_knn_model(X_train, y_train, n_neighbors=5, metric="euclidean", weights="uniform"):
    """
    Train a KNN model with the given parameters.
    """
    knn_model = KNeighborsClassifier(n_neighbors=n_neighbors, metric=metric, weights=weights, n_jobs=-1)
    knn_model.fit(X_train, y_train)
    return knn_model


def evaluate_model(model, X_test, y_test):
    """
    Evaluate the model on the test set.
    """
    y_pred = model.predict(X_test)
    # print("🔹 Accuracy:", accuracy_score(y_test, y_pred))
    print("\n🔹 Classification Report:\n", classification_report(y_test, y_pred))
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average='weighted')
    recall = recall_score(y_test, y_pred, average='weighted')
    f1 = f1_score(y_test, y_pred, average='weighted')
    print("\n=== Global Performance Metrics ===")
    print(f"Accuracy   : {accuracy:.4f}")
    print(f"Precision  : {precision:.4f}")
    print(f"Recall     : {recall:.4f}")
    print(f"F1-Score   : {f1:.4f}")   


def save_model(model, model_path="knn_model.joblib"):
    """
    Save the trained model for later use.
    """
    joblib.dump(model, model_path)
    print(f"KNN model saved as {model_path}")


# Main script execution
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python KNN_normalized.py <preprocessed_csv_file>")
        sys.exit(1)

    file_path = sys.argv[1]
    label_column = "attack_label"
    config_path = "dataset/config.json"

    # Step 1: Load preprocessed data
    X_train, X_test, y_train, y_test = load_preprocessed_data(file_path, label_column)

    # Step 2: Perform grid search to find the best hyperparameters
    best_params = perform_grid_search(X_train, y_train, param_grid)

    # Step 3: Update the config.json file with the best parameters
    update_config_file(config_path, best_params)

    # Step 4: Train KNN model with the best parameters
    knn_model = train_knn_model(
        X_train, y_train,
        n_neighbors=best_params["n_neighbors"],
        metric=best_params["metric"],
        weights=best_params["weights"]
    )

    # Step 5: Evaluate model
    evaluate_model(knn_model, X_test, y_test)

    # Step 6: Save model
    save_model(knn_model)
