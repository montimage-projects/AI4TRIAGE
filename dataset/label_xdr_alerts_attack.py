import csv
import glob
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
    return 'BENIGN'

def labelled_csv(input_file, output_file):
    csv.field_size_limit(sys.maxsize)

    # Initialize a dictionary to count occurrences of each attack label
    attack_counts = {label: 0 for label in known_ranges.keys()}
    attack_counts['BENIGN'] = 0  # Add 'BENIGN' to the dictionary

    # Read and process the CSV file using csv.reader
    with open(input_file, 'rt') as csvfile, open(output_file, 'at') as outfile:
        reader = csv.reader(csvfile)
        writer = csv.writer(outfile)

        # Reading the header and inserting the 'attack_label' column
        header = next(reader)

         # Identify indices of the columns to remove
        columns_to_remove = [header.index(col) for col in ['last_seen', '_eventdate'] if col in header]

        # Remove the unwanted columns from the header
        header = [col for idx, col in enumerate(header) if idx not in columns_to_remove]
        header.insert(0, 'attack_label')  # Insert 'attack_label' at the beginning


        if os.path.getsize(output_file) == 0:  # Write header only if file is empty
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
                    attack_counts[attack_label] += 1  # Increment the count for the attack label
                except ValueError as e:
                    print(f"Error processing row: {e}")
                    attack_label = 'BENIGN'
                    attack_counts['BENIGN'] += 1  # Increment 'BENIGN' count
            else:
                attack_label = 'BENIGN'
                attack_counts['BENIGN'] += 1  # Increment 'BENIGN' count

            # Remove the unwanted columns from the row BEFORE adding the label
            row = [value for idx, value in enumerate(row) if idx not in columns_to_remove]

            # Insert the attack label at the beginning of the row
            row.insert(0, attack_label)
            # Write the modified row to the output file
            writer.writerow(row)
            
    print("\nAttack label counts:")
    for label, count in attack_counts.items():
        print(f"{label}: {count}")

    print(f"CSV file '{input_file}' processed and saved as '{output_file}'!")

def main():
    #output several file
    if len(sys.argv) < 3:
        print("Usage: python <directory> <out_put>")
        sys.exit(1)
    directory = sys.argv[1]
    # # Get all CSV files in the directory
    csv_files = glob.glob(os.path.join(directory, '*.csv'))
    
    #output several file
    # for file in csv_files:
    #     output_file= file.split('xdr_alerts_attack_chunks/chunk')[0] + 'labelled_attack/labelled_xdr_alerts_attack/chunk' +  file.split('xdr_alerts_attack_chunks/chunk')[1]
    #     labelled_csv(file,output_file)
    #output 1 file
    output_file = sys.argv[2]
    for file in csv_files:
        labelled_csv(file,output_file)



if __name__ == "__main__":
    main()