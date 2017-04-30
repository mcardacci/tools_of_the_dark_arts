#!/bin/bash

for ip in $(seq 130 194);do
    host 194.68.30.$ip | grep "<WhateverDomain>" | cut -d " " -f1,5 
done
