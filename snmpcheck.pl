#!/usr/bin/perl

#
# Copyright (c) 2005,2006 by Matteo Cantoni <goony@nothink.org>
#
# snmpcheck is a tool to get information via SNMP protocols on Windows, Linux, Cisco, HP-UX, SunOS platforms.
# snmpchek has been tested on GNU/Linux, *BSD and Windows (Cygwin and ActivePerl) systems.
# snmpcheck is distributed under GPL license and based on "Athena-2k" script by jshaw. 
#

use strict;
use Getopt::Std;
use IO::Socket;
use Net::SNMP;

my $name        = "snmpcheck.pl";
my $version     = "v1.0";
my $description = "snmp enumerator";
my $copyright   = "Copyright (c) 2005";
my $author      = "Matteo Cantoni <goony\@nothink.org>";

#####################################################################################################
# MIBs Involved 
my $mibDescr                       = "1.3.6.1.2.1.1.1.0";            # System Description
my $mibNTDomain                    = "1.3.6.1.4.1.77.1.4.1.0";       # NT Primary Domain
my $mibUptime                      = "1.3.6.1.2.1.1.3.0";            # System Uptime
my $mibContact                     = "1.3.6.1.2.1.1.4.0";            # System Contact
my $mibName                        = "1.3.6.1.2.1.1.5.0";            # System Name
my $mibLocation                    = "1.3.6.1.2.1.1.6.0";            # System Location
my $mibRunning                     = "1.3.6.1.2.1.25.4.2.1.2";       # Running Programs
my $mibRunPid                      = "1.3.6.1.2.1.25.4.2.1.1";       # Running PIDs
my $mibProName                     = "1.3.6.1.4.1.42.3.12.1.1.10";   # Running Process Name (Solaris)
my $mibProPid                      = "1.3.6.1.4.1.42.3.12.1.1.1";    # Running Process Pid (Solaris)
my $mibProUser                     = "1.3.6.1.4.1.42.3.12.1.1.8";    # Running Process User (Solaris)
my $mibInstalled                   = "1.3.6.1.2.1.25.6.3.1.2";       # Installed Programs
my $mibInstDate                    = "1.3.6.1.2.1.25.6.3.1.5";       # Installed Date
my $mibServices                    = "1.3.6.1.4.1.77.1.2.3.1.1";     # Services (add to it)
my $mibAccounts                    = "1.3.6.1.4.1.77.1.2.25";        # User Accounts
my $mibDateTime                    = "1.3.6.1.2.1.25.1.2.0";         # System Date & Time
my $mibMemSize                     = "1.3.6.1.2.1.25.2.2.0";         # Total System Memory
my $mibMotd                        = "1.3.6.1.4.1.42.3.1.3.0";       # Motd (Solaris)
# Storage
my $mibStorDescr                   = "1.3.6.1.2.1.25.2.3.1.3";       # Storage Description
my $mibStoreHP                     = "1.3.6.1.4.1.11.2.3.1.2";       # Storage Description (HP-UX)
my $mibStorSize                    = "1.3.6.1.2.1.25.2.3.1.5";       # Storage Total Size
my $mibStorUsed                    = "1.3.6.1.2.1.25.2.3.1.6";       # Storage Used
my $mibPtype                       = "1.3.6.1.2.1.25.3.8.1.4";       # Partition Type
my $mibSDType                      = "1.3.6.1.2.1.25.2.3.1.2";       # Storage Device Type
# Network
my $mibInt                         = "1.3.6.1.2.1.2.2.1.2";          # Network Interfaces
my $mibIntMTU                      = "1.3.6.1.2.1.2.2.1.4";          # Net Int MTU Size
my $mibIntSpeed                    = "1.3.6.1.2.1.2.2.1.5";          # Net Int Speed
my $mibIntBytesIn                  = "1.3.6.1.2.1.2.2.1.10";         # Net Int Octets In
my $mibIntBytesOut                 = "1.3.6.1.2.1.2.2.1.16";         # Net Int Octects Out
my $mibIntPhys                     = "1.3.6.1.2.1.2.2.1.6";          # Int MAC addr
my $mibAdminStat                   = "1.3.6.1.2.1.2.2.1.7";          # Int up/down?
my $mibIPForward                   = "1.3.6.1.2.1.4.1.0";            # IP Forwarding?
my $mibIPAddr                      = "1.3.6.1.2.1.4.20.1.1";         # Int IP Address
my $mibNetmask                     = "1.3.6.1.2.1.4.20.1.3";         # Int IP Netmask
# IIS
my $http_totalBytesSentLowWord     = "1.3.6.1.4.1.311.1.7.3.1.2.0";  # totalBytesSentLowWord
my $http_totalBytesReceivedLowWord = "1.3.6.1.4.1.311.1.7.3.1.4.0";  # totalBytesReceivedLowWord
my $http_totalFilesSent            = "1.3.6.1.4.1.311.1.7.3.1.5.0";  # totalFilesSent
my $http_currentAnonymousUsers     = "1.3.6.1.4.1.311.1.7.3.1.6.0";  # currentAnonymousUsers
my $http_currentNonAnonymousUsers  = "1.3.6.1.4.1.311.1.7.3.1.7.0";  # currentNonAnonymousUsers
my $http_totalAnonymousUsers       = "1.3.6.1.4.1.311.1.7.3.1.8.0";  # totalAnonymousUsers
my $http_totalNonAnonymousUsers    = "1.3.6.1.4.1.311.1.7.3.1.9.0";  # totalNonAnonymousUsers
my $http_maxAnonymousUsers         = "1.3.6.1.4.1.311.1.7.3.1.10.0"; # maxAnonymousUsers
my $http_maxNonAnonymousUsers      = "1.3.6.1.4.1.311.1.7.3.1.11.0"; # maxNonAnonymousUsers
my $http_currentConnections        = "1.3.6.1.4.1.311.1.7.3.1.12.0"; # currentConnections
my $http_maxConnections            = "1.3.6.1.4.1.311.1.7.3.1.13.0"; # maxConnections
my $http_connectionAttempts        = "1.3.6.1.4.1.311.1.7.3.1.14.0"; # connectionAttempts
my $http_logonAttempts	           = "1.3.6.1.4.1.311.1.7.3.1.15.0"; # logonAttempts
my $http_totalGets	           = "1.3.6.1.4.1.311.1.7.3.1.16.0"; # totalGets
my $http_totalPosts	           = "1.3.6.1.4.1.311.1.7.3.1.17.0"; # totalPosts
my $http_totalHeads	           = "1.3.6.1.4.1.311.1.7.3.1.18.0"; # totalHeads
my $http_totalOthers	           = "1.3.6.1.4.1.311.1.7.3.1.19.0"; # totalOthers
my $http_totalCGIRequests          = "1.3.6.1.4.1.311.1.7.3.1.20.0"; # totalCGIRequests
my $http_totalBGIRequests          = "1.3.6.1.4.1.311.1.7.3.1.21.0"; # totalBGIRequests
my $http_totalNotFoundErrors       = "1.3.6.1.4.1.311.1.7.3.1.22.0"; # totalNotFoundErrors
# Shares
my $mibShareName                   = "1.3.6.1.4.1.77.1.2.27.1.1";    # Reports Share Names
my $mibSharePath                   = "1.3.6.1.4.1.77.1.2.27.1.2";    # Reports Share Path
my $mibShareComm                   = "1.3.6.1.4.1.77.1.2.27.1.3";    # Reports Share Comments
# Routing Info
my $mibRouteDest                   = "1.3.6.1.2.1.4.21.1.1";         # Route Destinations
my $mibRouteMetric                 = "1.3.6.1.2.1.4.21.1.3";         # Route Metric
my $mibRouteNHop                   = "1.3.6.1.2.1.4.21.1.7";         # Route Next Hop 
my $mibRouteMask                   = "1.3.6.1.2.1.4.21.1.11";        # Route Mask
# TCP Connections
my $mibTCPState                    = "1.3.6.1.2.1.6.13.1.1";         # TCP Connect State
my $mibTCPLAddr                    = "1.3.6.1.2.1.6.13.1.2";         # TCP Local Address
my $mibTCPLPort                    = "1.3.6.1.2.1.6.13.1.3";         # TCP Local Port
my $mibTCPRAddr                    = "1.3.6.1.2.1.6.13.1.4";         # TCP Remote Address
my $mibTCPRPort                    = "1.3.6.1.2.1.6.13.1.5";         # TCP Remote Port
# UDP Listening
my $mibUDPLAddr                    = "1.3.6.1.2.1.7.5.1.1";          # UDP Local Address
my $mibUDPLPort                    = "1.3.6.1.2.1.7.5.1.2";          # UDP Local Port
#####################################################################################################

my ($session,$error,$response,$temp,$a);

my $windows = 0;
my $linux   = 0;
my $cisco   = 0;
my $sunos   = 0;
my $hpux    = 0;

my $timeout = 15;
my $retries = 2;
my $webport = 80;
my %option;

my $usage = "$name $version - $description\n$copyright by $author\n
 Usage ./$name -t host [-p udp/tcp] [-P] [-c] [-h]\n
\t-t : target host;
\t-p : set snmp protocol; default is \'udp\';
\t-P : set snmp port; default port is \'161\';
\t-c : set snmp community; default is \'public\';
\t-h : show help menu;\n\n";

our ($opt_t, $opt_p, $opt_P, $opt_c, $opt_h);
getopts("t:p:P:c:h");
die $usage if  $opt_h;
die $usage if !$opt_t;

my $remote    = $opt_t;
my $community = $opt_c || "public";
my $protocol  = $opt_p || "udp";
my $port      = $opt_P || 161;

$|=1;

print "$name $version - $description\n$copyright by $author\n\n";

Connect();

print "\n";

exit(0);

sub Connect{
	($session, $error) = Net::SNMP->session(
		Hostname  => $remote,
		Community => $community,
		Domain    => $protocol,
		Port      => $port,
		Timeout   => $timeout,
		Retries   => $retries
	);

	die " ERROR: $error\n\n" if !$session;

	my $Descr = GetRequest($mibDescr);
	for ($Descr){ s/^\s//; }
	$windows = 1 if ($Descr =~ /^Hardware/i);
	$linux   = 1 if ($Descr =~ /^Linux/i);
	$cisco   = 1 if ($Descr =~ /^Cisco/i);
	$sunos   = 1 if ($Descr =~ /^Sun/i);
	$hpux    = 1 if ($Descr =~ /^HP-UX/i);

	my $Name     = GetRequest($mibName);
	my $Contact  = GetRequest($mibContact);
	my $Location = GetRequest($mibLocation);
	my $Uptime   = GetRequest($mibUptime);
	
	print " Hostname         : $Name\n";
	print " Ip address       : $remote\n";

	if ($windows == 1){
		my @Descr = split(/:/, $Descr);
		my $NTDomain = GetRequest($mibNTDomain);
		my $Uptime   = GetRequest($mibUptime);
		for ($Descr[1]){ s/^\s//; }
		for ($Descr[2]){ s/^\s//; }

		print " Hardware         : $Descr[1]\n";
		print " Software         : $Descr[2]\n";
		print " Primary Domain   : $NTDomain\n";
		print " System Uptime    : $Uptime\n";
		print " Contact          : $Contact\n";
		print " Location         : $Location\n";
	}
	
	if ($linux == 1){
		my @Descr_linux = $Descr;
		for (@Descr_linux){ s/\r\n//g; }

		print " Hardware         : @Descr_linux\n";
		print " System Uptime    : $Uptime\n";
		print " Contact          : $Contact\n";
		print " Location         : $Location\n";
	}
	
	if ($cisco == 1){
		my @Descr_cisco = $Descr;
		for (@Descr_cisco){ s/\r\n//g; }

		print " Hardware         : @Descr_cisco\n";
		print " System Uptime    : $Uptime\n";
		print " Contact          : $Contact\n";
		print " Location         : $Location\n";
	}
	
	if ($sunos == 1){
		my $motd = GetRequest($mibMotd);
		chomp $motd;
		print " Hardware         : $Descr\n";
		print " System Uptime    : $Uptime\n";
		print " Motd             : $motd\n";
		print " Contact          : $Contact\n";
		print " Location         : $Location\n";
	}
	
	if ($hpux == 1){
		print " Hardware         : $Descr\n";
		print " System Uptime    : $Uptime\n";
		print " Contact          : $Contact\n";
		print " Location         : $Location\n";
	}

	#
	# Hardware
	#

	if ($windows == 1){
		my $MemSize   = GetRequest($mibMemSize);
		my @StorDescr = GetTable($mibStorDescr);
		my @SDType    = GetTable($mibSDType);
		my @Ptype     = GetTable($mibPtype);

		print "\n\n Hardware\n";
		print " -------------------------------------------------------------------------\n\n";
		print " Total Memory     : $MemSize KB\n";
	
		for ($a = 0; $a < $#StorDescr; $a++){

			if ($SDType[$a] eq "1.3.6.1.2.1.25.2.1.3"){
				$SDType[$a] = "Virtual Memory";
			}

			if ($SDType[$a] eq "1.3.6.1.2.1.25.2.1.4"){
				$SDType[$a] = "Fixed Disk";
			}

			if ($SDType[$a] eq "1.3.6.1.2.1.25.2.1.5"){
				$SDType[$a] = "Removable Disk";
			}

			if ($SDType[$a] eq "1.3.6.1.2.1.25.2.1.7"){
				$SDType[$a] = "Compact Disc";
			}

			if ($Ptype[$a] eq "1.3.6.1.2.1.25.3.9.2"){
				$Ptype[$a] = "UNKNOWN";
			}

			if ($Ptype[$a] eq "1.3.6.1.2.1.25.3.9.9"){
				$Ptype[$a] = "NTFS";
			}

			if ($StorDescr[$a] ne "Virtual Memory"){
				print "\n";
				print " $StorDescr[$a]\n";
				print "\t Device Type    : $SDType[$a]\n";
				print "\t Partition Type : $Ptype[$a]\n";
			}
		}
	}
	
	if ($hpux == 1){
		my @StorDescr = GetTable($mibStoreHP);

		print "\n\n Hardware\n";
		print " -------------------------------------------------------------------------\n\n";
		
		for ($a = 0; $a < $#StorDescr; $a++){
			print " $StorDescr[$a]\n" if (grep(/\//,$StorDescr[$a]));
		}
	}

	#
	# User accounts
	#

	if ($windows == 1){
		my @Accounts = GetTable($mibAccounts);

		print "\n\n User accounts\n";
		print " -------------------------------------------------------------------------\n\n";

		foreach $temp(@Accounts){
			 print " $temp\n";
		}
	}

	#
	#
	# Processes
	#
	
	if ($windows == 1){
		my @Running = GetTable($mibRunning);
		my @RunPid  = GetTable($mibRunPid);

		print "\n\n Processes\n";
		print " -------------------------------------------------------------------------\n";
		printf "\n %10s %25s\n", "process id", "process name";
		printf " %10s %25s\n\n", "----------", "------------";
		for ($a = 0; $a < scalar(@RunPid); $a++){
			if ($Running[$a] ne " System Idle Process"){
				printf " %10s %25s\n", $RunPid[$a], $Running[$a];
			}
		}
	}
	
	if ($linux == 1){
		my @Running = GetTable($mibRunning);
		my @RunPid  = GetTable($mibRunPid);

		print "\n\n Processes\n";
		print " -------------------------------------------------------------------------\n";
		printf "\n %10s %25s\n", "process id", "process name";
		printf " %10s %25s\n\n", "----------", "------------";
		for ($a = 0; $a < scalar(@RunPid); $a++){
			if ($Running[$a] ne " System Idle Process"){
				printf " %10s %25s\n", $RunPid[$a], $Running[$a];
			}
		}
	}

	if ($sunos == 1){
		my @Running = GetTable($mibProName);
		my @RunPid  = GetTable($mibProPid);
		my @RunUser = GetTable($mibProUser);	

		print "\n\n Processes\n";
		print " -------------------------------------------------------------------------\n\n";
		printf "\n %10s %25s %25s\n", "process ID", "process name", "user name";
		printf " %10s %25s %25s\n\n", "----------", "------------", "---------";

		for ($a = 0; $a < scalar(@RunPid); $a++){
			if ($Running[$a] ne " System Idle Process"){
				printf " %10s %25s %25s\n", $RunPid[$a], $Running[$a], $RunUser[$a];
			}
		}
	}

	#
	# Network services
	#

	if ($windows == 1){
		my @Services = GetTable($mibServices);

		print "\n\n Network services\n";
		print " -------------------------------------------------------------------------\n\n";

		foreach $temp(@Services){
			print " $temp\n";
		}
	}
	
	#
	# IIS
	#

	if ($windows == 1){

		my $connect = IO::Socket::INET->new(
			PeerAddr => $remote,
			PeerPort => $webport,
			Proto    => 'tcp',
			Timeout  => $timeout
		);

		if ($connect){
			my $http_totalBytesSentLowWord     = GetRequest($http_totalBytesSentLowWord); 
			my $http_totalBytesReceivedLowWord = GetRequest($http_totalBytesReceivedLowWord); 
			my $http_totalFilesSent            = GetRequest($http_totalFilesSent);
			my $http_currentAnonymousUsers     = GetRequest($http_currentAnonymousUsers);
			my $http_currentNonAnonymousUsers  = GetRequest($http_currentNonAnonymousUsers);
			my $http_totalAnonymousUsers       = GetRequest($http_totalAnonymousUsers);
			my $http_totalNonAnonymousUsers    = GetRequest($http_totalNonAnonymousUsers);
			my $http_maxAnonymousUsers         = GetRequest($http_maxAnonymousUsers);
			my $http_maxNonAnonymousUsers      = GetRequest($http_maxNonAnonymousUsers);
			my $http_currentConnections        = GetRequest($http_currentConnections);
			my $http_maxConnections            = GetRequest($http_maxConnections);
			my $http_connectionAttempts        = GetRequest($http_connectionAttempts);
			my $http_logonAttempts             = GetRequest($http_logonAttempts);
			my $http_totalGets                 = GetRequest($http_totalGets);
			my $http_totalPosts                = GetRequest($http_totalPosts);
			my $http_totalHeads                = GetRequest($http_totalHeads);
			my $http_totalOthers               = GetRequest($http_totalOthers);
			my $http_totalCGIRequests          = GetRequest($http_totalCGIRequests);
			my $http_totalBGIRequests          = GetRequest($http_totalBGIRequests );
			my $http_totalNotFoundErrors       = GetRequest($http_totalNotFoundErrors);

			print "\n\n IIS\n";
			print " -------------------------------------------------------------------------\n\n";

			print " totalBytesSentLowWord     : $http_totalBytesSentLowWord\n";
			print " totalBytesReceivedLowWord : $http_totalBytesReceivedLowWord\n";
			print " totalFilesSent            : $http_totalFilesSent\n";
			print " currentAnonymousUsers     : $http_currentAnonymousUsers\n";
			print " currentNonAnonymousUsers  : $http_currentNonAnonymousUsers\n";
			print " totalAnonymousUsers       : $http_totalAnonymousUsers\n";
			print " totalNonAnonymousUsers    : $http_totalNonAnonymousUsers\n";
			print " maxAnonymousUsers         : $http_maxAnonymousUsers\n";
			print " maxNonAnonymousUsers      : $http_maxNonAnonymousUsers\n";
			print " currentConnections        : $http_currentConnections\n";
			print " maxConnections            : $http_maxConnections\n";
			print " connectionAttempts        : $http_connectionAttempts\n";
			print " logonAttempts             : $http_logonAttempts\n";
			print " totalGets                 : $http_totalGets\n";
			print " totalPosts                : $http_totalPosts\n";
			print " totalHeads                : $http_totalHeads\n";
			print " totalOthers               : $http_totalOthers\n";
			print " totalCGIRequests          : $http_totalCGIRequests\n";
			print " totalBGIRequests          : $http_totalBGIRequests\n";
			print " totalNotFoundErrors       : $http_totalNotFoundErrors\n";
		}
	}

	#
	# Network & Interfaces
	#

	my @Int         = GetTable($mibInt);
	my @MTU         = GetTable($mibIntMTU);
	my @IntSpeed    = GetTable($mibIntSpeed);
	my @IntBytesIn  = GetTable($mibIntBytesIn);
	my @IntBytesOut = GetTable($mibIntBytesOut);
	my @IntPhys     = GetTable($mibIntPhys);
	my @IPAddr      = GetTable($mibIPAddr);
	my @Netmask     = GetTable($mibNetmask);
	my @AdminStat   = GetTable($mibAdminStat);
	my $IPForward   = GetRequest($mibIPForward);

	if ($IPForward eq "0" || $IPForward eq "2") { $IPForward = "no"; }

	print "\n\n Network interfaces\n";
	print " -------------------------------------------------------------------------\n\n";
	print " IP Forwarding Enabled   : $IPForward\n\n";

	for ($a = 0; $a < scalar(@Int); $a++){

		chomp $Int[$a];

		if ($AdminStat[$a] eq "0"){
			$AdminStat[$a] = "down";
		} else {
			$AdminStat[$a] = "up";
		}

		$IntSpeed[$a] = $IntSpeed[$a] / 1000000;
		print " Interface               : [ $AdminStat[$a] ] $Int[$a]\n";
		print "\tHardware Address : $IntPhys[$a]\n";
		print "\tInterface Speed  : $IntSpeed[$a] Mbps\n";
		print "\tIP Address       : $IPAddr[$a]\n" if $IPAddr[$a];
		print "\tNetmask          : $Netmask[$a]\n" if $IPAddr[$a];
		print "\tBytes In         : $IntBytesIn[$a]\n" if $IntBytesIn[$a];
		print "\tBytes Out        : $IntBytesOut[$a]\n" if $IntBytesOut[$a];
		print "\n";
	}

	#
	# Routing information
	#

	my @RouteDest	= &GetTable($mibRouteDest);
	my @RouteNHop	= &GetTable($mibRouteNHop);
	my @RouteMask	= &GetTable($mibRouteMask);
	my @RouteMetric	= &GetTable($mibRouteMetric);

	print "\n Routing information\n";
	print " -------------------------------------------------------------------------\n\n";
	print "     Destination:\t Next Hop:\t      Mask:\tMetric:\n";
	print "     ------------\t ---------\t      -----\t-------\n";

	for ($a = 0; $a < scalar(@RouteDest); $a++){
		printf "%17s%17s%17s%7s\n", $RouteDest[$a], $RouteNHop[$a],
			$RouteMask[$a], $RouteMetric[$a];
	}

	my @TCPState = &GetTable($mibTCPState);
	my @TCPLAddr = &GetTable($mibTCPLAddr); 
	my @TCPLPort = &GetTable($mibTCPLPort);
	my @TCPRAddr = &GetTable($mibTCPRAddr);
	my @TCPRPort = &GetTable($mibTCPRPort);

	#
	# TCP Connections 
	#
	
	print "\n\n TCP connections\n";
	print " -------------------------------------------------------------------------\n\n";
	print  "   Local Address:  Port      Remote Address: Port\n\n";

	for ($a = 0; $a < scalar(@TCPState); $a++){

		if ($TCPState[$a] eq "2")  { $TCPState[$a] = "(listening)";   }
		if ($TCPState[$a] eq "5")  { $TCPState[$a] = "(established)"; }
		if ($TCPState[$a] eq "8")  { $TCPState[$a] = "(Close Wait)";  }
		if ($TCPState[$a] eq "11") { $TCPState[$a] = "(time wait)";   }

		printf " %15s:%6s   %17s:%6s\n", $TCPLAddr[$a], $TCPLPort[$a], $TCPRAddr[$a], $TCPRPort[$a];
	}

	#
	# Listening UDP Ports
	#

	my @UDPLAddr = GetTable($mibUDPLAddr);
	my @UDPLPort = GetTable($mibUDPLPort);

	print "\n\n Listening UDP ports\n";
	print " -------------------------------------------------------------------------\n\n";
	printf " %17s %6s\n\n", "Address", "Port";

	for($a = 0; $a < scalar(@UDPLAddr); $a++) {
		printf " %17s:%6s\n", $UDPLAddr[$a], $UDPLPort[$a];
	}

	#
	# Mountpoints
	#
	
	if ($linux == 1){
		my @StorDescr = GetTable($mibStorDescr);

		print "\n\n Mountpoints\n";
		print " -------------------------------------------------------------------------\n\n";
		
		for ($a = 0; $a < $#StorDescr; $a++){
			print " $StorDescr[$a]\n" if (grep(/\//,$StorDescr[$a]));
		}
	}

	#
	# Software components
	#

	if ($windows == 1){
		my @Installed = GetTable($mibInstalled);
		my @InstDate  = GetTable($mibInstDate);

		print "\n\n Software components\n";
		print " -------------------------------------------------------------------------\n\n";

		for($a = 0; $a < scalar(@Installed); $a++) {
			print "\t$Installed[$a]\n";
		}
	}
	
	if ($linux == 1){
		my @Installed = GetTable($mibInstalled);
		my @InstDate  = GetTable($mibInstDate);

		print "\n\n Software components\n";
		print " -------------------------------------------------------------------------\n\n";

		my @soft;
		for($a = 0; $a < scalar(@Installed); $a++) {
			#print "\t$Installed[$a]\n";
			push @soft, $Installed[$a];
		}
		@soft = sort @soft;
		foreach (@soft){ print "\t$_\n";}
		
	}
	
	#
	# Shares
	#

	if ($windows == 1){
		&GetShares;
	}

	$session->close;
}

sub GetRequest{
	my $response = "";
	
	if (!($response = $session->get_request($_[0]))){
		return "No Reponse";
	} else {
		my $Return = $response->{$_[0]};
		return $Return;
	}
}

sub GetTable{

	my @Return;
	my $response = "";

	if (!($response = $session->get_table($_[0]))){
		return " No Response";
	}

	my $x = 0;
	my $key;

	foreach $key (sort keys %$response){
		if ($$response{$key} ne " Virtual Memory"){
			$Return[$x] = $$response{$key};
			$x++;
		}
	}

	return @Return;
}

sub GetShares{
	my @ShareName = GetTable($mibShareName);
	my @SharePath = GetTable($mibSharePath);
	my @ShareComm = GetTable($mibShareComm);

	print "\n\n Non-administrative shares\n";
	print " -------------------------------------------------------------------------\n\n";

	for ($a = 0; $a < scalar(@ShareName); $a++){
		print " Share Name : $ShareName[$a]\n";
		print "\tPath     : $SharePath[$a]\n";
		print "\tComments : $ShareComm[$a]\n\n";
	}
}