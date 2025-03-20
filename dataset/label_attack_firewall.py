import glob
import os
import sys
import pandas as pd



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

# Function to assign attack labels based on Unix timestamp ranges
def assign_attack_label(row):
    for attack, (start_time, end_time) in known_ranges.items():
        if start_time <= row['timestamp'] <= end_time:
            return attack
    return 'BENIGN'


def readFile(input_file,output_file):
    time_format = '%Y-%m-%d %H:%M:%S.%f'
    df = pd.read_csv(input_file)

    df['eventdate'] = pd.to_datetime(df['eventdate'], format=time_format)

    df['timestamp'] = df['eventdate'].apply(lambda x: x.timestamp()) 
    df.pop('eventdate')
    df['attack_label'] = df.apply(assign_attack_label, axis=1)
    df.insert(0, 'attack_label', df.pop('attack_label'))

    df.insert(1, 'timestamp', df.pop('timestamp'))

    
    df.to_csv(output_file, index=False)
        
    print(f"CSV file '{input_file}' processed and saved as '{output_file}'!")



def main():
    if len(sys.argv) < 3:
        print("Usage: python <directory *.csv file> <output_csv_file>")
        sys.exit(1)
    directory = sys.argv[1]
    # Get all CSV files in the directory
    csv_files = glob.glob(os.path.join(directory, '*.csv'))

    # output 1 file
    output_file = sys.argv[2]
    for file in csv_files:
        readFile(file, output_file)


if __name__ == "__main__":
    main()
