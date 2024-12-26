import sys
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from sklearn.neighbors import KNeighborsClassifier




def preprocess_data(data):
    # Handle missing values
    data['eventdate'] = data['eventdate'].fillna('BENIGN')  # Fill label column
    data = data.fillna(data.median(numeric_only=True))  # Fill numeric columns with median

    # Convert categorical features to numerical using one-hot encoding
    data = pd.get_dummies(data, drop_first=True)

    # Separate features and labels
    X = data.drop(columns=['eventdate'], errors='ignore').values
    y = data['eventdate'].values

    return X, y
# Feature Importance using Random Forest
def feature_importance(X, y):
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X, y)
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    
    print("Feature ranking:")
    for f in range(X.shape[1]):
        print(f"{f + 1}. Feature {indices[f]} ({importances[indices[f]]})")
        
    # Return the indices of the most important features (top 10)
    top_features = indices[:10]
    return top_features

# GridSearchCV for Model Optimization (KNN example)
def grid_search_knn(X_train, y_train):
    param_grid = {
        'n_neighbors': [3, 5, 7, 9],  # KNN hyperparameters
        'weights': ['uniform', 'distance'],
        'metric': ['euclidean', 'manhattan']
    }

    knn = KNeighborsClassifier()
    grid_search = GridSearchCV(knn, param_grid, cv=5, n_jobs=-1, verbose=2)
    grid_search.fit(X_train, y_train)
    
    print("Best parameters found: ", grid_search.best_params_)
    return grid_search.best_estimator_

# Main Program to Execute the Process
def main():
    # Load and preprocess data
    # # Directory containing CSV files
    if len(sys.argv) < 2:
        print("Usage: python <directory *.csv file>")
        sys.exit(1)
    csv_files= sys.argv[1]

    data = pd.read_csv(csv_files)
    X, y = preprocess_data(data)
    
    # Split the data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Feature Importance
    top_features = feature_importance(X_train, y_train)
    
    # Select only the top features for training and testing
    X_train_important = X_train[:, top_features]
    X_test_important = X_test[:, top_features]

    # Perform GridSearchCV to find optimal parameters
    best_model = grid_search_knn(X_train_important, y_train)
    
    # Evaluate the optimized model
    y_pred = best_model.predict(X_test_important)  # Use selected top features
    print("Accuracy: ", accuracy_score(y_test, y_pred))
    print(classification_report(y_test, y_pred))

if __name__ == "__main__":
    main()
