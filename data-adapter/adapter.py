import sys
import pandas as pd
import paho.mqtt.client as mqtt
import json

# MQTT Configuration
BROKER = "localhost"
TOPIC = "ai4triage/logs"
FEATURES_FILE = '/top_features.csv'

def select_features(features_file):
    try:
        features_df = pd.read_csv(features_file)
        if 'Feature' not in features_df.columns:
            raise ValueError(f"'Feature' column not found in {features_file}")
        selected_features = features_df['Feature'].tolist()  # Extract the "Feature" column
    except Exception as e:
        print(f"Error reading features file: {e}")
        sys.exit(1)
    return selected_features

# Important features based on prior analysis
IMPORTANT_FEATURES = select_features(FEATURES_FILE)

def process_log(file_path):
    """Read log file and extract features."""
    try:
        df = pd.read_csv(file_path)
        missing_features = [feature for feature in IMPORTANT_FEATURES if feature not in df.columns]
        if missing_features:
            raise ValueError(f"Missing features: {', '.join(missing_features)}")
        
        # Select important features
        important_features = df[IMPORTANT_FEATURES]
        return important_features.to_dict(orient='records')
    except Exception as e:
        print(f"Error processing log file: {e}")
        sys.exit(1)

def send_to_mqtt(data):
    """Send processed log data to MQTT broker."""
    try:
        client = mqtt.Client()
        client.connect(BROKER, 1883, 60)
        client.publish(TOPIC, json.dumps(data))
        client.disconnect()
    except Exception as e:
        print(f"Error sending data to MQTT: {e}")

if __name__ == '__main__':
    # Test with a sample file
    
    file_path = "sample_log.csv"  # Replace with actual log file path
    log_data = process_log(file_path)
    send_to_mqtt(log_data)
