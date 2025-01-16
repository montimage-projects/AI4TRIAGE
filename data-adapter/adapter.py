import pandas as pd
import paho.mqtt.client as mqtt
import json

# MQTT Configuration
BROKER = "localhost"
TOPIC = "ai4triage/logs"

def process_log(file_path):
    """Read log file and extract features."""
    df = pd.read_csv(file_path)
    # Select important features (replace with your actual feature names)
    important_features = df[['feature1', 'feature2', 'feature3', 'feature4']]
    return important_features.to_dict(orient='records')

def send_to_mqtt(data):
    """Send processed log data to MQTT broker."""
    client = mqtt.Client()
    client.connect(BROKER, 1883, 60)
    client.publish(TOPIC, json.dumps(data))
    client.disconnect()

if __name__ == '__main__':
    # Test with a sample file
    file_path = "sample_log.csv"  # Replace with actual log file path
    log_data = process_log(file_path)
    send_to_mqtt(log_data)