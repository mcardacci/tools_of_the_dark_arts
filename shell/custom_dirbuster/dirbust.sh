#!/bin/bash

for word in $(cat /usr/share/dirb/wordlists/common.txt); do
    # find pages whose last line does NOT contain the phrase 'what are you trying' (basically a custom 404 message)
    curl -q "192.168.0.104:60080/?page=$word" 2>/dev/null | tail -1 | grep -v 'what are you trying'
    # 'grep -v' prints everything but the given string

    if [[ $? -eq 0 ]]; then
        # if the last command was successful, print the word we found
        echo $word
    fi
done | grep -v "/" # Don't print results with slashes in them, they're false positives.
