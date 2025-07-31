# AI4TRIAGE

**AI4TRIAGE - CAIXA bank use case**  
This project processes attack logs, labels the data, and trains a model using the KNN algorithm.

---

## Overview

This project processes attack logs, labels the data, and trains a model using the KNN algorithm. The workflow includes downloading a dataset, labeling various types of logs, processing the data, and training a KNN model.

---

## Prerequisites

- **Python 3.x** – Ensure you have Python installed.

- **Create a Virtual Environment:**
  ```bash
  python3 -m venv myenv
  source myenv/bin/activate
  ```

- **Install Required Libraries:**
  ```bash
  pip install -r requirements.txt
  ```

---

## Configuration File (`config.json`)

This project uses a configuration file named `config.json` to manage parameters and settings for data processing and model training.

- **Location:** The `config.json` file is located at `dataset/config.json` in the project directory.
- **Usage:** Before running scripts, review and update `config.json` to ensure all paths and parameters match your environment and requirements.

**Example (excerpt):**
```json
{
  "RAW_DIR": "Datasets/raw/",
  "CLEANED_DIR": "Datasets/cleaned/",
  "CSV_SEPARATOR": "|",
  "KNN_normalized": {
    "n_neighbors": 3,
    "weights": "distance",
    "metric": "manhattan"
  }
  // ... other settings
}
```

---

## Setup & Execution Steps

### Step 1: Download the Dataset

- **Source:** Download the CSV dataset from the provided [Shared folder](https://tecnalia365.sharepoint.com/sites/TEAMGRP106747HORIZON/Documentos%20compartidos/General/AI4CYBER_Project/Work%20Packages/WP07%20Demonstration%20in%20Use%20Cases/Use_Cases/UC2%20(CXB)/Datasets.zip?csf=1&web=1&e=IeQIlM&CID=147571dc-8f18-4fc7-adda-8323ca2b8ec1).
- **Destination:** Save the file in the following directory: `Datasets/raw/`
  *(Make sure the `Datasets/raw/` directory exists; if not, create it.)*

### Step 2: Clean the Raw Data

Run the script to clean **all logs**:
```bash
python dataset/process_script/cleanData.py
```
To clean a **specific log type** (e.g., firewall, mail, xdr, proxy), use:
```bash
python dataset/process_script/cleanData.py firewall
```

### Step 3: Label the Cleaned Data

Label **all cleaned logs**:
```bash
python dataset/labelData.py Datasets/cleaned/ Datasets/labelled/
```
Or, label a **specific log**:
```bash
python dataset/labelData.py Datasets/cleaned/firewall_cleaned.csv Datasets/labelled/firewall_labelled.csv
```

*Ensure each script completes successfully before moving on to the next step.*

### Step 4: Process the Data

Process **all labelled logs**:
```bash
python dataset/process_script/post_label_process.py Datasets/labelled/ Datasets/processed/
```
Or, process a **specific log**:
```bash
python dataset/process_script/post_label_process.py Datasets/labelled/firewall_labelled.csv Datasets/processed/firewall_processed.csv
```

### Step 5: Merge Processed Logs

Always merge all processed logs before training or classifying:
```bash
python dataset/process_script/merge.py Datasets/processed/ Datasets/merged_log.csv
```
This step prepares the dataset for model training or classification and ensures all log types are included.

### Step 6: Train the Model

Train the KNN model using the merged file:
```bash
python dataset/KNN_normalized.py Datasets/merged_log.csv
```
This script uses the processed and merged data to train the model.

---

### Step 7: Classify New Log Files

If you have new log files (any log type), always preprocess and merge them as above before classification.

1. **Preprocess new log files (clean, label, post-process):**
   - For all new logs:
     ```bash
     python dataset/process_script/cleanData.py
     python dataset/labelData.py Datasets/cleaned/ Datasets/labelled/
     python dataset/process_script/post_label_process.py Datasets/labelled/ Datasets/processed/
     ```
   - Or for a specific log type:
     ```bash
     python dataset/process_script/cleanData.py firewall
     python dataset/labelData.py Datasets/cleaned/firewall_cleaned.csv Datasets/labelled/firewall_labelled.csv
     python dataset/process_script/post_label_process.py Datasets/labelled/firewall_labelled.csv Datasets/processed/firewall_processed.csv
     ```

2. **Merge all processed logs (including new ones):**
   ```bash
   python dataset/process_script/merge.py Datasets/processed/ Datasets/merged_new_log.csv
   ```

3. **Classify the merged log file:**
   ```bash
   python dataset/classify_logs.py Datasets/merged_new_log.csv Datasets/predicted_new_log.csv knn_model.joblib
   ```
   The output file will have an additional column `predicted_label` with the predicted class for each log entry.

---
### Step 8: Generate STIX Alerts and Send to Kafka
ai4triage.js eads the classified log file (e.g., predicted_new_log.csv), converts entries to STIX format, and sends them to a Kafka topic.
   ```bash
   node ai4triage.js Datasets/predicted_new_log.csv
   ```
Make sure Kafka is running and accessible on the configured port.

---
### Step 9 (Optional): Run testConsumer.js to Monitor Kafka Topic
Use this consumer script to subscribe to the Kafka topic and view the published STIX alerts:

   ```bash
   node testConsumer.js
   ```
Make sure Kafka is running and accessible on the configured port.

---
### Step 10 : View Alerts on the AI4TRIAGE Dashboard
Visualize alerts using the web-based dashboard:
🔗 [AI4TRIAGE-Dashboard on GitHub](https://github.com/montimage-projects/AI4TRIAGE-Dashboard).
Follow the setup instructions in the dashboard repository to run the frontend locally or on a server.

---
## Troubleshooting

- **Dataset Not Found:** Verify that the CSV file is in the `Datasets/raw/` folder.
- **Module Not Found Errors:** Confirm that all required libraries are installed.
- **Script Errors:** Check the terminal output for error messages and ensure the data format matches the expected requirements.

---

## Quick Start

```bash
python3 -m venv myenv
source myenv/bin/activate
pip install -r requirements.txt
# Edit config.json as needed
# Download and unzip dataset into Datasets/raw/
python dataset/process_script/cleanData.py
python dataset/labelData.py Datasets/cleaned/ Datasets/labelled/
python dataset/process_script/post_label_process.py Datasets/labelled/ Datasets/processed/
python dataset/process_script/merge.py Datasets/processed/ Datasets/merged_log.csv
python dataset/KNN_normalized.py Datasets/merged_log.csv
# To classify new logs (after preprocessing and merging):
python dataset/classify_logs.py Datasets/merged_new_log.csv Datasets/predicted_new_log.csv knn_model.joblib
node ai4triage.js Datasets/predicted_new_log.csv
node testConsumer.js
```

---

## Additional Notes

- Always preprocess and merge all log types before training or classification.
- Make sure all directory paths in `config.json` are correct.
- Review each script’s output for successful processing before proceeding to the next step.

---
