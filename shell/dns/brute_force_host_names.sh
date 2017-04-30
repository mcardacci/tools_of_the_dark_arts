#!/bin/bash

for name in $(cat common_host_names.txt);do
    host $name.<domain> | grep "has address" | cut -d " " -f1,4
done
