import sys
import pandas as pd
import joblib

def main():
    if len(sys.argv) != 4:
        print("Usage: python classify_logs.py <input_csv> <output_csv> <model_file>")
        sys.exit(1)

    input_csv = sys.argv[1]
    output_csv = sys.argv[2]
    model_file = sys.argv[3]

    # Load processed data
    df = pd.read_csv(input_csv)

    # Load the trained model
    model = joblib.load(model_file)

    # Drop label column if present (since we want to predict it)
    X = df.drop(columns=['attack_label'], errors='ignore')
    X = X.fillna(0)

    # Predict
    predictions = model.predict(X)
    df['predicted_label'] = predictions

    # Save results
    df.to_csv(output_csv, index=False)
    print(f"Classification complete. Results saved to {output_csv}")

if __name__ == "__main__":
    main()