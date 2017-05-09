#!/usr/bin/python
'''
The following commands were ran prior to execution of this script:
$ touch goodpass.txt
    ** For storing our successful password
$ vi zero.txt 
    ** type in some passphrases from a hint you have...hopefully
Example:
    zero kool
    zerokool
    zerocool
    zero cool
    ...
$ sudo john --rules=nt --wordlist=zero.txt --stdout > zeropass.txt
$ sudo john --rules=L33t --wordlist=zeropass.txt --stdout > zeropass1.txt


'''
import subprocess as s
import os

p = open(os.getcwd() + '/goodpass.txt', 'w')

# Used to escape symbols such as $,#,|, etc in bash that will cause echo to behave weird
def clean(word):
    password = word.strip()
    password = "'" + password + "'"
    return password

with open(os.getcwd() + '/zeropass1.txt' , 'r') as f:
    for password in f:
        password = clean(password)

        test = s.call('echo ' + password + ' | gpg --passphrase-fd 0 -q --batch --allow-multiple-messages --no-tty --output decrypt.txt -d ' + os.getcwd() + '/flag.txt.gpg', shell=True)
        
        if test == 2:
            print "Bad Password: " + password
        else:
            print "Password: " + password
            p.write(password)
            f.close
            p.close
            break

f.close
p.close
