import csv
import sys
from datetime import datetime
import os
import glob

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
attack_counts = {label: 0 for label in known_ranges.keys()}
attack_counts['BENIGN'] = 0  # Add 'BENIGN' to the dictionary
error_row_count = 0

# Function to convert 'ts' string to Unix epoch time
def datetime_string_to_epoch(dtstring):
    try:
        dt_obj = datetime.strptime(dtstring, '%Y-%m-%dT%H:%M:%S.%f%z') # format  "2024-08-27T06:50:14.103264+0200"
        return int(dt_obj.timestamp())  # Convert to Unix timestamp
    except Exception as e:
        raise ValueError(f"Unrecognized datetime format: {dtstring}")

# Function to assign attack labels based on Unix timestamp ranges
def assign_attack_label(unix_timestamp):
    for attack, (start, end) in known_ranges.items():
        if start <= unix_timestamp <= end:
            return attack
    return 'BENIGN'


def readFile(input_file,output_file):
    # Read and process the CSV file using csv.reader
    with open(input_file, 'rt') as csvfile, open(output_file, 'at') as outfile:
        #reader = csv.reader(csvfile, delimiter=';')
        reader = csv.reader(csvfile)
        writer = csv.writer(outfile)
        
        # Adding the new column to the header
        header = next(reader)
        timestamp_col = 3
        header.insert(0, 'attack_label')  # Insert 'attack_label' at the beginning
        del header[timestamp_col + 1]
        if os.path.getsize(output_file) == 0:
            writer.writerow(header)

        for row in reader:
            ts_value = row[timestamp_col]  #  the timestamp string
            try:
                unix_timestamp = datetime_string_to_epoch(ts_value)  # Convert to Unix timestamp
                
                #print (unix_timestamp)
                attack_label = assign_attack_label(unix_timestamp)  # Assign attack label
                row.insert(0, attack_label)
                attack_counts[attack_label] += 1

            except ValueError as e:
                row.insert(0, 'BENIGN')  # Insert 'BENIGN' if there's an error
                attack_counts['BENIGN'] += 1 
            # Convert updated_row back to a list and write to the output CSV
            del row[timestamp_col + 1]
            writer.writerow(row)
        
    print(f"CSV file '{input_file}' processed and saved as '{output_file}'!")



# Main function
def main():
    csv.field_size_limit(sys.maxsize)
    # Directory containing CSV files
    if len(sys.argv) < 3:
        print("Usage: python <directory *.csv file> <output_csv_file>")
        sys.exit(1)
    directory = sys.argv[1]
    # Get all CSV files in the directory
    csv_files = glob.glob(os.path.join(directory, '*.csv'))

    # output 1 file
    output_file = sys.argv[2]
    for file in csv_files:
        readFile(file,output_file)

    #Output several file
    # for file in csv_files:
    #     output_file= file.split('mail_attack_chunks/chunk')[0] + 'labelled_attack/labelled_mail_attack/chunk' +  file.split('mail_attack_chunks/chunk')[1]
    #     readFile(file,output_file)


    # Output the attack counts
    print("Attack Counts:")
    for attack_label, count in attack_counts.items():
        print(f"{attack_label}: {count}")
        
if __name__ == "__main__":
    main()

