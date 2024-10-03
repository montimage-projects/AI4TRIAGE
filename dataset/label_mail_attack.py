import csv
import re
import sys
from datetime import datetime
from dateutil import parser

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

# Function to convert 'ts' string to Unix epoch time
def datetime_string_to_epoch(dtstring):
    try:
        dt_obj = parser.isoparse(dtstring)
        return int(dt_obj.timestamp())  # Convert to Unix timestamp
    except Exception as e:
        raise ValueError(f"Unrecognized datetime format: {dtstring}")

# Function to assign attack labels based on Unix timestamp ranges
def assign_attack_label(unix_timestamp):
    for attack, (start, end) in known_ranges.items():
        if start <= unix_timestamp <= end:
            return attack
    return 'NA'

csv.field_size_limit(sys.maxsize)
# Ensure a file path is provided via command-line argument
if len(sys.argv) < 2:
    print("Usage: python script.py <input_csv_file>")
    sys.exit(1)

# Input file is the first argument passed to the script
input_file = sys.argv[1]

output_file = sys.argv[2]  # Define the output file path

# Read and process the CSV file using csv.reader
with open(input_file, 'rt') as csvfile, open(output_file, 'at') as outfile:
    reader = csv.reader(csvfile)
    writer = csv.writer(outfile,  quotechar=' ', quoting=csv.QUOTE_ALL)
    
    # Adding the new column to the header
    header = next(reader)
    header.insert(0, 'attack_label')  # Insert 'attack_label' at the beginning
    if len(outfile) == 0:
        writer.writerow(header)

    for row in reader:
        row_str = ','.join(row)  # Convert list to string to search for 'ts'

        # Find the 'ts' in the row (assuming it's in the format: 'ts': 'Thu Jun 27 03:11:00 2024')
        match = re.search(r"'ts': '(.+?)'", row_str)
        
        if match:
            ts_value = match.group(1)  # Extract the timestamp string
            try:
                unix_timestamp = datetime_string_to_epoch(ts_value)  # Convert to Unix timestamp
                attack_label = assign_attack_label(unix_timestamp)  # Assign attack label
                row.insert(0, attack_label)
                # Replace 'src_time' value with the attack label in the row
                #updated_row = re.sub(r"'ts': '(.+?)'", f"'{attack_label}'", row_str)
            except ValueError as e:
                print(f"Error processing row: {e}")
                #updated_row = row_str  # If an error occurs, leave the row unchanged
                row.insert(0, 'NA')  # Insert 'NA' if there's an error
        else:
            #updated_row = row_str  # If no 'ts' found, leave the row unchanged
            row.insert(0, 'NA')  # Insert 'NA' if no 'ts' found
        # Convert updated_row back to a list and write to the output CSV
        writer.writerow(row)

print(f"CSV file '{input_file}' processed and saved as '{output_file}'!")
