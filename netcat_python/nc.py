#!/usr/bin/python
import socket
import subprocess 

def netcat(hostname, port,command):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, port))
    op = subprocess.Popen(command, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

    if op:
        output=str(op.stdout.read())
        print "Output:",output
        s.sendall(output)
    else:
        error=str(op.stderr.read())
        print "Error:",error
        s.sendall(error)
    s.shutdown(socket.SHUT_WR)

    while 1:
        data = s.recv(1024)
        if data == "":
            break
        print "Received:", repr(data)
    print "Connection closed."

    s.close()

netcat('127.0.0.1', 4444, 'pwd')

