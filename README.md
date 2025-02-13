# AI4TRIAGE
AI4TRIAGE - CAIXA bank use case 
This project processes attack logs, labels the data, and trains a model using the KNN algorithm. Follow the steps below to set up and run the code.
## Overview
This project processes attack logs, labels the data, and trains a model using the KNN algorithm. The workflow includes downloading a dataset, labeling various types of logs, processing the data, and training a KNN model.

## Prerequisites

- **Python 3.x** - Ensure you have Python installed.
- **Required Libraries** - Install the necessary libraries (e.g., pandas, numpy, scikit-learn) with:
  ```bash
    pip install -r requirements.txt
  ```

  
## Setup & Execution Steps

### Step 1: Download the Dataset
- **Source:** Download the CSV dataset from the provided  [Shared folder](https://tecnalia365.sharepoint.com/:u:/r/sites/TEAMGRP106747HORIZON/Documentos%20compartidos/General/AI4CYBER_Project/Work%20Packages/WP07%20Demonstration%20in%20Use%20Cases/Use_Cases/UC2%20(CXB)/Datasets.zip?csf=1&web=1&e=IeQIlM).
- **Destination:** Save the file in the following directory: Datasets/raw/
  *(Make sure the `Datasets/raw/` directory exists; if not, create it.)*

### Step 2: Labeling the Data
Run each of the following scripts to label different types of logs:

- **Firewall Attacks:**
```bash
python label_attack_firewall.py attack_firewall_1.csv labelled_attack_firewall.csv 
python label_attack_firewall.py attack_firewall_2.csv labelled_attack_firewall.csv 
python label_attack_firewall.py attack_firewall_3.csv labelled_attack_firewall.csv
```
- **Mail Attacks:**
```bash
python label_mail_attack.py Datasets/raw/mail_attack_chunks/ Datasets/processed/labelled_mail.csv
```
- **Proxy Attacks:**
```bash
python label_proxy_attack.py Datasets/raw/proxy_attack_chunks/ Datasets/processed/labelled_proxy.csv
```
- **XDR Alerts Attacks:**
```bash
python label_xdr_alerts_attack.py Datasets/raw/xdr_alerts_attack_chunks/ Datasets/processed/labelled_xdr.csv
```
*Ensure each script completes successfully before moving on to the next step.*

### Step 3: Process the Data
After labeling, process the data using:
```bash
python processFile.py labelled_attack_firewall.csv processed_firewall.csv
python processFile.py labelled_mail.csv processed_mail.csv
python processFile.py labelled_proxy.csv processed_proxy.csv
python processFile.py labelled_xdr.csv processed_xdr.csv
```
This step cleans and prepares the dataset for model training.

### Step 4: Train the Model
Train the KNN model using:
```bash
python KNN.py
```
This script uses the processed data to train the model.



## Troubleshooting

- **Dataset Not Found:** Verify that the CSV file is in the `Datasets/raw/` folder.
- **Module Not Found Errors:** Confirm that all required libraries are installed.
- **Script Errors:** Check the terminal output for error messages and ensure the data format matches the expected requirements.
