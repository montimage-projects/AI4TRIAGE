# AI4TRIAGE
AI4TRIAGE - CAIXA bank use case 
This project processes attack logs, labels the data, and trains a model using the KNN algorithm. Follow the steps below to set up and run the code.
## Overview
This project processes attack logs, labels the data, and trains a model using the KNN algorithm. The workflow includes downloading a dataset, labeling various types of logs, processing the data, and training a KNN model.

## Prerequisites

- **Python 3.x** - Ensure you have Python installed.
- **Create env**
  ```bash
  python3 -m venv myenv
  source myenv/bin/activate
  ```
- **Required Libraries** - Install the necessary libraries (e.g., pandas, numpy, scikit-learn) with:
  ```bash
    pip install -r requirements.txt
  ```

  
## Setup & Execution Steps

### Step 1: Download the Dataset
- **Source:** Download the CSV dataset from the provided  [Shared folder]([https://tecnalia365.sharepoint.com/:u:/r/sites/TEAMGRP106747HORIZON/Documentos%20compartidos/General/AI4CYBER_Project/Work%20Packages/WP07%20Demonstration%20in%20Use%20Cases/Use_Cases/UC2%20(CXB)/Datasets.zip?csf=1&web=1&e=IeQIlM](https://tecnalia365.sharepoint.com/sites/TEAMGRP106747HORIZON/Documentos%20compartidos/General/AI4CYBER_Project/Work%20Packages/WP07%20Demonstration%20in%20Use%20Cases/Use_Cases/UC2%20(CXB)/Datasets.zip?csf=1&web=1&e=IeQIlM&CID=147571dc-8f18-4fc7-adda-8323ca2b8ec1)).
- **Destination:** Save the file in the following directory: Datasets/raw/
  *(Make sure the `Datasets/raw/` directory exists; if not, create it.)*

### Step 2: Labeling the Data
Run each of the following scripts to label different types of logs:

- **Firewall Attacks:**
```bash
python dataset/label_attack_firewall.py Datasets/raw/firewall_attack_chunks/ Datasets/labelled/firewall_labelled.csv
```
- **Mail Attacks:**
```bash
python dataset/label_mail_attack.py Datasets/raw/mail_attack_chunks/ Datasets/labelled/mail_labelled.csv
```
- **Proxy Attacks:**
```bash
python dataset/label_proxy_attack.py Datasets/raw/proxy_attack_chunks/ Datasets/labelled/proxy_labelled.csv
```
- **XDR Alerts Attacks:**
```bash
python dataset/label_xdr_alerts_attack.py Datasets/raw/xdr_alerts_attack_chunks/ Datasets/labelled/xdr_labelled.csv
```
*Ensure each script completes successfully before moving on to the next step.*

### Step 3: Process the Data
After labeling, process the data and then merge it using:
```bash
python dataset/processData.py Datasets/labelled/firewall_labelled.csv Datasets/processed/firewall_processed.csv
python dataset/processData.py Datasets/labelled/mail_labelled.csv Datasets/processed/mail_processed.csv
python dataset/processData.py Datasets/labelled/proxy_labelled.csv Datasets/processed/proxy_processed.csv
python dataset/processData.py Datasets/labelled/xdr_labelled.csv Datasets/processed/xdr_processed.csv
python dataset/merge.py Datasets/processed/ Datasets/merged_log.csv
```
This step cleans and prepares the dataset for model training.

### Step 4: Train the Model
Train the KNN model using:
```bash
python dataset/KNN_normalized.py Datasets/merged_log.csv
```
This script uses the processed data to train the model.



## Troubleshooting

- **Dataset Not Found:** Verify that the CSV file is in the `Datasets/raw/` folder.
- **Module Not Found Errors:** Confirm that all required libraries are installed.
- **Script Errors:** Check the terminal output for error messages and ensure the data format matches the expected requirements.
