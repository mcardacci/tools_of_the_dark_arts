#!/usr/bin/python

from sys import argv
import nmap

host = '192.168.0.100'
ports = '21-443'

nm = nmap.PortScanner()
nm.scan(host, ports)
nm.command_line()
nm.scaninfo()
nm.all_hosts()
nm.scaninfo() # get nmap scan informations {'tcp': {'services': '22-443', 'method': 'connect'}}
nm.all_hosts() # get all hosts that were scanned
nm[host].hostname() # get one hostname for host 127.0.0.1, usualy the user record
nm[host].hostnames() # get list of hostnames for host 127.0.0.1 as a list of dict
                            # [{'name':'hostname1', 'type':'PTR'}, {'name':'hostname2', 'type':'user'}]
nm[host].hostname() # get hostname for host 127.0.0.1
nm[host].state() # get state of host 127.0.0.1 (up|down|unknown|skipped) 
nm[host].all_protocols() # get all scanned protocols ['tcp', 'udp'] in (ip|tcp|udp|sctp)
nm[host]['tcp'].keys() # get all ports for tcp protocol
nm[host].all_tcp() # get all ports for tcp protocol (sorted version)
nm[host].all_udp() # get all ports for udp protocol (sorted version)
nm[host].all_ip() # get all ports for ip protocol (sorted version)
nm[host].all_sctp() # get all ports for sctp protocol (sorted version)
nm[host].has_tcp(22) # is there any information for port 22/tcp on host 127.0.0.1
nm[host]['tcp'][22] # get infos about port 22 in tcp on host 127.0.0.1
nm[host].tcp(22) # get infos about port 22 in tcp on host 127.0.0.1
nm[host]['tcp'][22]['state'] # get state of port 22/tcp on host 127.0.0.1 (open


# for host in nm.all_hosts():
#     print '----------------------------------------------------'
#     print 'Host : {} ({})'.format(host, nm[host].hostname())
#     print 'State : {}'.format(nm[host].state())
    
for proto in nm[host].all_protocols():
    print '----------'
    print 'Protocol : {}'.format(proto)
        
lport = nm[host][proto].keys()
lport.sort()

for port in lport:
    print 'port : {}\tstate : {}'.format(port, nm[host][proto][port]['state'])


