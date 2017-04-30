
Description
-----------
* An experiment in python sockets usage.
* Sends a command to attacker (listening) machine from the victim machine.
* The victim must have Python installed.
* The script can send a one-off command before the connection is closed

'nc.py' Script Usage
--------------------
* In the script edit the 'host' and 'port' arguments to those of the attacker machine.
* Also edit the 'command' parameter
* Start a netcat listener on the attacker machine on the port you've put in the script
* Connection will happen, magic takes place, connection will close


