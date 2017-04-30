#!/usr/bin/bash

# Define bash global variables
var="global var"

function bash {
    local var="local variable"
    echo $var
}

echo $var
bash
echo $var
