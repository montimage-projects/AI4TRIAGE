from datetime import datetime
import csv
import sys
from dateutil import parser

    
csv.field_size_limit(sys.maxsize)

file_in = open(str(sys.argv[1]),'rt')
reader = csv.reader(file_in)

file_out_training = open(str(sys.argv[2]),'w+')
writer_training = csv.writer(file_out_training, delimiter=',', quotechar=' ', quoting=csv.QUOTE_ALL)

file_out_testing = open(str(sys.argv[3]),'w+')
writer_testing = csv.writer(file_out_testing, delimiter=',', quotechar=' ', quoting=csv.QUOTE_ALL)

line_nb = 0
nb_ATK1 = 0
nb_ATK2 = 0
nb_ATK3 = 0
nb_ATK4 = 0
nb_ATK5 = 0
nb_ATK6 = 0
nb_ATK7 = 0
nb_ATK8 = 0
nb_ATK9 = 0
nb_ATK10 = 0
nb_ATK11 = 0
nb_NA = 0
attacks = []

print('Start dividing the csv file: ' + str(sys.argv[1]))
for line in reader: 
    if line_nb == 0:
        #print(line)
        first_char1 = file_out_training.read(1)
        if not first_char1: 
            writer_training.writerow(line)
            first_char2 = file_out_testing.read(1)
            if not first_char2: 
                writer_testing.writerow(line)
            line_nb += 1
            continue
        else: 
            line_nb += 1
            continue
    else: 
        #print(line)
        line_nb += 1
        label = line[0]
        if label not in attacks: 
            attacks.append(label)
        match label: 
            case ' ATTACK1 ': 
                nb_ATK1 += 1
                if (nb_ATK1 % 3 != 0):
                    writer_training.writerow(line)
                elif (nb_ATK1 % 3 == 0):
                    writer_testing.writerow(line)
            case ' ATTACK2 ': 
                nb_ATK2 += 1
                if (nb_ATK2 % 3 != 0):
                    writer_training.writerow(line)
                elif (nb_ATK2 % 3 == 0):
                    writer_testing.writerow(line)
            case ' ATTACK3 ': 
                nb_ATK3 += 1
                if (nb_ATK3 % 3 != 0):
                    writer_training.writerow(line)
                elif (nb_ATK3 % 3 == 0):
                    writer_testing.writerow(line)
            case ' ATTACK4 ': 
                nb_ATK4 += 1
                if (nb_ATK4 % 3 != 0):
                    writer_training.writerow(line)
                elif (nb_ATK4 % 3 == 0):
                    writer_testing.writerow(line)
            case ' ATTACK5 ': 
                nb_ATK5 += 1
                if (nb_ATK5 % 3 != 0):
                    writer_training.writerow(line)
                elif (nb_ATK5 % 3 == 0):
                    writer_testing.writerow(line)
            case ' ATTACK6 ': 
                nb_ATK6 += 1
                if (nb_ATK6 % 3 != 0):
                    writer_training.writerow(line)
                elif (nb_ATK6 % 3 == 0):
                    writer_testing.writerow(line)
            case ' ATTACK7 ': 
                nb_ATK7 += 1
                if (nb_ATK7 % 3 != 0):
                    writer_training.writerow(line)
                elif (nb_ATK7 % 3 == 0):
                    writer_testing.writerow(line)
            case ' ATTACK8 ': 
                nb_ATK8 += 1
                if (nb_ATK8 % 3 != 0):
                    writer_training.writerow(line)
                elif (nb_ATK8 % 3 == 0):
                    writer_testing.writerow(line)
            case ' ATTACK9 ': 
                nb_ATK9 += 1
                if (nb_ATK9 % 3 != 0):
                    writer_training.writerow(line)
                elif (nb_ATK9 % 3 == 0):
                    writer_testing.writerow(line)
            case ' ATTACK10 ': 
                nb_ATK10 += 1
                if (nb_ATK10 % 3 != 0):
                    writer_training.writerow(line)
                elif (nb_ATK10 % 3 == 0):
                    writer_testing.writerow(line)
            case ' ATTACK11 ': 
                nb_ATK11 += 1
                if (nb_ATK11 % 3 != 0):
                    writer_training.writerow(line)
                elif (nb_ATK11 % 3 == 0):
                    writer_testing.writerow(line)
            case ' NA ': 
                nb_NA += 1
                if (nb_NA % 3 != 0):
                    writer_training.writerow(line)
                elif (nb_NA % 3 == 0):
                    writer_testing.writerow(line)      
nb_attacks = [nb_ATK1, nb_ATK2, nb_ATK3, nb_ATK4, nb_ATK5, nb_ATK6, nb_ATK7, nb_ATK8, nb_ATK9, nb_ATK10, nb_ATK11, nb_NA]
print(attacks)
print(nb_attacks)  
print('Finish dividing the csv file. Outfile is: ' + str(sys.argv[2]) + ' and ' + str(sys.argv[3]))

        
    






