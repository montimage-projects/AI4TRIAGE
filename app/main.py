import sys
import pandas as pd
import joblib
import paho.mqtt.client as mqtt
import os
import json
# from sklearn.preprocessing import StandardScaler

# Configuration
BROKER = "localhost"
LOGS_TOPIC = "ai4triage/logs"
RESULTS_TOPIC = "ai4triage/results"
MODEL_PATH = '/Users/haobui/Montimge/AI4CYBER/app/models/knn_model.joblib'
SCALER_PATH = '/Users/haobui/Montimge/AI4CYBER/app/models/scaler.pkl'
FEATURES_FILE= '/Users/haobui/Montimge/AI4CYBER/top_features.csv'

# Load pre-trained model and scaler
model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

def select_features(features_file):
    try:
        features_df = pd.read_csv(features_file)
        selected_features = features_df['Feature'].tolist()  # Extract the "Feature" column
    except Exception as e:
        print(f"Error reading features file: {e}")
        sys.exit(1)
    return selected_features

# Important features based on prior analysis
IMPORTANT_FEATURES = select_features(FEATURES_FILE)

def process_log(file_path):
    """Process log file to extract features."""
    df = pd.read_csv(file_path)
    missing_features = [f for f in IMPORTANT_FEATURES if f not in df.columns]
    if missing_features:
        raise ValueError(f"Missing features: {missing_features}")
    return df[IMPORTANT_FEATURES]

def normalize_and_predict(data):
    """Normalize data and predict using pre-trained model."""
    normalized_data = scaler.transform(data)
    predictions = model.predict(normalized_data)
    return predictions

def save_results(data, predictions, output_path):
    """Save prediction results to CSV."""
    data['prediction'] = predictions
    data.to_csv(output_path, index=False)
    return output_path

def send_to_mqtt(data):
    """Send data to MQTT broker."""
    client = mqtt.Client()
    client.connect(BROKER, 1883, 60)
    client.publish(RESULTS_TOPIC, json.dumps(data))
    client.disconnect()

# MQTT Handlers
def on_message(client, userdata, message):
    try:
        # Ensure that the payload is in JSON format
        payload = json.loads(message.payload)
        # Check that the payload is a list of dictionaries or data that can be converted to a DataFrame
        if isinstance(payload, list):
            df = pd.DataFrame(payload)
            # Process the data and make predictions
            df = df[IMPORTANT_FEATURES]  # Select the relevant features
            predictions = normalize_and_predict(df)
            results = {"predictions": predictions.tolist()}
            send_to_mqtt(results)  # Send results to MQTT broker
        else:
            print(f"Unexpected data format: {type(payload)}")
    except Exception as e:
        print(f"Error processing message: {e}")

def run_mqtt_listener():
    """Run MQTT listener to process logs."""
    client = mqtt.Client()
    client.on_message = on_message
    client.connect(BROKER, 1883, 60)
    client.subscribe(LOGS_TOPIC)
    client.loop_forever()

if __name__ == '__main__':
    os.makedirs('uploads', exist_ok=True)
    run_mqtt_listener()
