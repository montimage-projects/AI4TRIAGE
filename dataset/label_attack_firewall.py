from datetime import datetime
import csv
import sys
from dateutil import parser


def datetime_string_to_epoch(dtstring): 
    # Input datetime string
    # Convert the datetime string to a datetime object
    try: 
        dt_obj = parser.parse(dtstring)
        # Convert the datetime object to an epoch timestamp
        epoch_time = dt_obj.timestamp()
        return epoch_time
    except:
        return "NULL"


#Test datetime_string_to_epoch
#dtstring = "2024-08-29 00:10:19"    
#print('Epoch time for ' + str(dtstring) + ' is: ' + str(datetime_string_to_epoch(dtstring)))

def convert_epoch_to_attack_label(ts):
    if (ts >= 1724921820) and (ts <= 1724922300): 
        return 'ATTACK1'
    elif  (ts >= 1724848560) and (ts <= 1724849760): 
        return 'ATTACK2'
    elif  (ts >= 1724846100) and (ts <= 1724847240): 
        return 'ATTACK3'
    elif  (ts >= 1724769420) and (ts <= 1724770080): 
        return 'ATTACK4'
    elif  (ts >= 1724767920) and (ts <= 1724768940): 
        return 'ATTACK5'
    elif  (ts >= 1724420820) and (ts <= 1724421660): 
        return 'ATTACK6'
    elif  (ts >= 1724411220) and (ts <= 1724411700): 
        return 'ATTACK7'
    elif  (ts >= 1724410200) and (ts <= 1724410620): 
        return 'ATTACK8'
    elif  (ts >= 1724334120) and (ts <= 1724334600): 
        return 'ATTACK9'
    elif  (ts >= 1724325240) and (ts <= 1724326440): 
        return 'ATTACK10'
    elif  (ts >= 1723028400) and (ts <= 1723032000): 
        return 'ATTACK11'
    else: 
        return 'NA'  
def convert_dtstring_to_attack_label(dtstring): 
    ts = datetime_string_to_epoch(dtstring)
    if (ts >= 1724921820) and (ts <= 1724922300): 
        return 'ATTACK1'
    elif  (ts >= 1724848560) and (ts <= 1724849760): 
        return 'ATTACK2'
    elif  (ts >= 1724846100) and (ts <= 1724847240): 
        return 'ATTACK3'
    elif  (ts >= 1724769420) and (ts <= 1724770080): 
        return 'ATTACK4'
    elif  (ts >= 1724767920) and (ts <= 1724768940): 
        return 'ATTACK5'
    elif  (ts >= 1724420820) and (ts <= 1724421660): 
        return 'ATTACK6'
    elif  (ts >= 1724411220) and (ts <= 1724411700): 
        return 'ATTACK7'
    elif  (ts >= 1724410200) and (ts <= 1724410620): 
        return 'ATTACK8'
    elif  (ts >= 1724334120) and (ts <= 1724334600): 
        return 'ATTACK9'
    elif  (ts >= 1724325240) and (ts <= 1724326440): 
        return 'ATTACK10'
    elif  (ts >= 1723028400) and (ts <= 1723032000): 
        return 'ATTACK11'
    else: 
        return 'NA'  
    
csv.field_size_limit(sys.maxsize)

file_in = open(str(sys.argv[1]),'rt')
reader = csv.reader(file_in)

file_out = open(str(sys.argv[2]),'at')
writer = csv.writer(file_out, delimiter=',', quotechar=' ', quoting=csv.QUOTE_ALL)

line_nb = 0
attacks = []
print('Start labelling the csv file: ' + str(sys.argv[1]))
for line in reader: 
    if line_nb == 0:
        #print(line)
        if len(file_out) == 0: 
            writer.writerow(line)
            line_nb += 1
            continue
        else: 
            line_nb += 1
            continue
    else: 
        #print(line)
        new_line = []
        for i in range(len(line)): 
            if i == 0: 
                #print(line[i])
                label = convert_dtstring_to_attack_label(str(line[i]))
                new_line.append(label)
                #print(label)
                if label not in attacks: 
                    attacks.append(label)
            else: 
                new_line.append(line[i])
        #print(new_line)
        writer.writerow(new_line)
        line_nb += 1
print('Finish labelling the csv file. Outfile is: ' + str(sys.argv[2]))
print(attacks)
        
    






