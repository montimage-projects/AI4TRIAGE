import csv
import re
import sys
from datetime import datetime
import os
from dateutil import parser  # This library helps with ISO 8601 parsing

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

# Function to convert the different datetime formats to Unix epoch time
def datetime_string_to_epoch(dtstring):
    try:
        # Handle 'last_seen' format: '2024-08-20 14:26:54.430'
        if re.match(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}', dtstring):
            dt_obj = datetime.strptime(dtstring, '%Y-%m-%d %H:%M:%S.%f')
            return int(dt_obj.timestamp())
        
        # Handle '_eventdate' ISO format: '2024-08-23T21:28:52.715170712+02:00'
        else:
            dt_obj = parser.isoparse(dtstring)  # Use dateutil.parser for ISO 8601
            return int(dt_obj.timestamp())
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
if len(sys.argv) < 3:
    print("Usage: python script.py <input_csv_file> <output_csv_file>")
    sys.exit(1)

# Input and output file paths from command-line arguments
input_file = sys.argv[1]
output_file = sys.argv[2]

# Initialize a dictionary to count occurrences of each attack label
attack_counts = {label: 0 for label in known_ranges.keys()}
attack_counts['NA'] = 0  # Add 'NA' to the dictionary

# Read and process the CSV file using csv.reader
with open(input_file, 'r') as csvfile, open(output_file, 'a', newline='') as outfile:
    reader = csv.reader(csvfile)
    writer = csv.writer(outfile, quoting=csv.QUOTE_ALL)

    # Reading the header and inserting the 'attack_label' column
    header = next(reader)
    if os.path.getsize(output_file) == 0:  # Write header only if file is empty
        header.insert(0, 'attack_label')  # Insert 'attack_label' at the beginning
        writer.writerow(header)

    # Process each row
    for row in reader:
        row_str = ','.join(row)  # Convert row to string to search for timestamp fields

        # Search for 'last_seen' and '_eventdate' formats in the row
        match_last_seen = re.search(r'"last_seen":"(.+?)"', row_str)
        match_eventdate = re.search(r'"_eventdate":"(.+?)"', row_str)
        
        if match_last_seen:
            ts_value = match_last_seen.group(1)  # Extract the 'last_seen' timestamp string
        elif match_eventdate:
            ts_value = match_eventdate.group(1)  # Extract the '_eventdate' timestamp string
        else:
            ts_value = None

        if ts_value:
            try:
                unix_timestamp = datetime_string_to_epoch(ts_value)  # Convert to Unix timestamp
                attack_label = assign_attack_label(unix_timestamp)  # Assign attack label
                row.insert(0, attack_label)  # Insert the attack label at the beginning of the row
                attack_counts[attack_label] += 1  # Increment the count for the attack label
            except ValueError as e:
                print(f"Error processing row: {e}")
                row.insert(0, 'NA')  # Insert 'NA' if there's an error in processing the timestamp
                attack_counts['NA'] += 1  # Increment 'NA' count
        else:
            row.insert(0, 'NA')  # Insert 'NA' if no timestamp field is found
            attack_counts['NA'] += 1  # Increment 'NA' count

        # Write the modified row to the output file
        writer.writerow(row)
        
print("\nAttack label counts:")
for label, count in attack_counts.items():
    print(f"{label}: {count}")

print(f"CSV file '{input_file}' processed and saved as '{output_file}'!")
