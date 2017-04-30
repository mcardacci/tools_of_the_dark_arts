#!/bin/bash

# MUST RUN AS ROOT TO MAKE 'iptables' work

#reset all counters and iptables rules
iptables -Z && iptables -F

# measure incoming traffic to specified IP
iptables -I INPUT 1 -s 10.11.1.8 -j ACCEPT

# measure outgoing traffic to specified IP
iptables -I OUTPUT 1 -d 10.11.1.8 -j ACCEPT

# AFTER EXECUTED RUN:
# iptables -vn -L

