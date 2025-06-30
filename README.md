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

Run the script to clean logs:
```bash
python dataset/process_script/cleanData.py 
```
To clean a specific log type (e.g., firewall, mail, xdr, proxy), use:
```bash
python dataset/process_script/cleanData.py firewall
```

### Step 3: Label the Cleaned Data

Label all cleaned logs:
```bash
python dataset/labelData.py Datasets/cleaned/ Datasets/labelled/
```
Or, label specific logs:
```bash
python dataset/labelData.py Datasets/cleaned/firewall_cleaned.csv Datasets/labelled/firewall_labelled.csv
```

*Ensure each script completes successfully before moving on to the next step.*

### Step 4: Process the Data

Process each labelled log:
```bash
python dataset/process_script/post_label_process.py Datasets/labelled/ Datasets/processed/
```
Or, process specific logs:
```bash
python dataset/process_script/post_label_process.py Datasets/labelled/firewall_labelled.csv Datasets/processed/firewall_processed.csv
```

Merge all processed logs into one file:
```bash
python dataset/process_script/merge.py Datasets/processed/ Datasets/merged_log.csv
```
This step prepares the dataset for model training.

### Step 5: Train the Model

Train the KNN model using:
```bash
python dataset/KNN_normalized.py Datasets/merged_log.csv
```
This script uses the processed data to train the model.

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
```

---

## Additional Notes

- Make sure all directory paths in `config.json` are correct.
- Review each script’s output for successful processing before proceeding to the next step.

---
