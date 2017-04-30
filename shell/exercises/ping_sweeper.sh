#! /bin/bash

for ip in $(seq 1 254); do
    ping -c 2 192.168.0.$ip | grep "bytes from" | cut -d " " -f4 | cut -d ":" -f1 &
done

