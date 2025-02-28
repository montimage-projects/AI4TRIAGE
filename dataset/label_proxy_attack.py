import csv
import glob
import re
import sys
from datetime import datetime
import os
# Define the known attack timestamp ranges (Unix epoch time)
known_ranges = {
    'ATTACK1': (1724921820, 1724922300),
    'ATTACK2': (1724848560, 1724849760),
    'ATTACK3': (1724846100, 1724847240),
    'ATTACK4': (1724769420, 1724770080),
    'ATTACK5': (1724767920, 1724768940),
    'ATTACK6': (1724420820, 1724421660),
    'ATTACK7': (1724411220, 1724411700),
    'ATTACK8': (1724410200, 1724410620),
    'ATTACK9': (1724334120, 1724334600),
    'ATTACK10': (1724325240, 1724326440),
    'ATTACK11': (1723028400, 1723032000)
}

# Function to convert 'src_time' string to Unix epoch time
def datetime_string_to_epoch(dtstring):
    try:
        dt_obj = datetime.strptime(dtstring, '%a %b %d %H:%M:%S %Y')  # Example format: 'Thu Jun 27 03:11:00 2024'
        return int(dt_obj.timestamp())  # Convert to Unix timestamp
    except Exception as e:
        raise ValueError(f"Unrecognized datetime format: {dtstring}")

# Function to assign attack labels based on Unix timestamp ranges
def assign_attack_label(unix_timestamp):
    for attack, (start, end) in known_ranges.items():
        if start <= unix_timestamp <= end:
            return attack
    return 'BENIGN'


def labelled_csv(input_file, output_file):
    csv.field_size_limit(sys.maxsize)
    attack_counts = {label: 0 for label in known_ranges.keys()}
    attack_counts['BENIGN'] = 0  # Add 'BENIGN' to the dictionary
    with open(input_file, 'rt') as csvfile, open(output_file, 'at') as outfile:
        reader = csv.reader(csvfile)
        writer = csv.writer(outfile)
        
        # Adding the new column to the header
        header = next(reader)
        timestamp_col = 155
        header.insert(0,'attack_label')  # Insert 'attack_label' at the beginning
        del header[timestamp_col + 1]
        if os.path.getsize(output_file) == 0:
            writer.writerow(header)
        row_count =0
        for row in reader:
            row_count+=1
            ts_value = row[timestamp_col]
        
            try:
                unix_timestamp = datetime_string_to_epoch(ts_value)  # Convert to Unix timestamp
                attack_label = assign_attack_label(unix_timestamp)  # Assign attack label
                row.insert(0, attack_label)
                attack_counts[attack_label] += 1  # Increment the count for the attack label
            except ValueError as e:
                print(f"Error processing row: {e}")
                row.insert(0, 'BENIGN')
                attack_counts['BENIGN'] += 1  # Increment 'BENIGN' count
            del row[timestamp_col + 1]
            writer.writerow(row)
    print("Attack Counts:")
    for attack_label, count in attack_counts.items():
        print(f"{attack_label}: {count}")
    print(f"CSV file '{input_file}' processed and saved as '{output_file}'!")


def main():
    # Ensure a file path is provided via command-line argument
    if len(sys.argv) < 3:
        print("Usage: python <directory> <out_put> ")
        sys.exit(1)
    directory = sys.argv[1]
    # # Get all CSV files in the directory
    csv_files = glob.glob(os.path.join(directory, '*.csv'))
    output_file = sys.argv[2]  # Define the output file path


    for file in csv_files:
        #output_file= file.split('proxy_attack_chunks/chunk')[0] + 'labelled_attack/labelled_proxy_attack/chunk' +  file.split('proxy_attack_chunks/chunk')[1]
        labelled_csv(file,output_file)

if __name__ == "__main__":
    main()