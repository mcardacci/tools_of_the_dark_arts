#!/bin/bash

# If the length of command line argument is zero (that is the '-z' option) 
# Then execute code block
if [ -z "$1" ]; then
    echo "[*] Simple Zone Transfer Script"
    echo "[*] Usage     : $0 <domain name w/o 'www.'>"
    exit 0
fi

# If an argument was given, identify the DNS servers for that domain.
# For each of these servers, attempt a zone transfer

for server in $(host -t ns $1 | cut -d " " -f4); do 
    host -l $1 $server | grep "has address"
done
