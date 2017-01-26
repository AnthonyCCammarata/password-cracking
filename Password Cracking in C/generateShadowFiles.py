#--- Generate an shadow password file using a list of popular passwords

# This uses the (slightly edited) list of over 3500 popular passwords from
# the John the Ripper project maintained by OpenWall

import random
import crypt
import sys
from getopt import getopt

random.seed(0)
mangle = False
outputFile = 'shadow'

# Process command line arguments
opts, args = getopt(sys.argv[1:], 'ms:o:')

for pair in opts:
    if pair[0] == '-s':
        random.seed(pair[1])
    if pair[0] == '-m':
        print 'Mangling enabled...'
        mangle = True
    if pair[0] == '-o':
        outputFile = pair[1]

# Open the list and read the words into a list
f = open('password.lst')

passwords = []
for line in f:
    line = line.strip();
    passwords.append(line);
    
# Pick 100 words at random
keys = []

while len(keys) < 100:
    index = random.randint(0, len(passwords) - 1)
    
    if passwords[index] not in keys:
        key = passwords[index]
        
        if mangle:
            key = key + str(random.randint(0, 10))
            
        keys.append(key)
        
print keys
        
        
# Generate output file
output = open(outputFile, 'w')

for i in range(len(keys)):
    username = 'user' + str(i)
    
    hash = crypt.crypt(keys[i], '$1$')
    
    output.write(username + ':' + hash + ':' + keys[i] + '\n');
    
f.close()
output.close()

print crypt.crypt('password', '$1$')
