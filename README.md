# phpipam-scripts
These are various scripts to work in conjunction with PHPIPAM (https://github.com/phpipam/phpipam)

# nmapScanner.php: 
script to use Nmap as scanning tool besides ping/fping

This script does the following:
 
* fetches flagged subnets for scanning
 
* scans the whole subnet witn Nmap, this will also scan hosts which do not respond to ping and discover missing MAC

* FOR EACH scan enabled/toggled SUBNET from PHPIPAM, there are 2 phases and assumes that this nmap scanner script is "the boss" (it will overwrite any other scan/discovery in case of conflicts.)

* Phase 1 : 
Start from the nmap output of the subnet, and update or add to PHPIPAM, that way, we need to read the file only once. 
Updates lastseen (this is important for phase 2), hostname, MAC address, other info (notes or comments)

* Phase 2 : walk through the subnet from PHPIPAM, and compare the lastseen from the script with the lastseen from PHPIPAM:
If the one in the database is older, we assume the ip was no longer seen by nmap, and thus considered offline, change the status to offline (not yet as fine grained as in the pingCheck script with the grace period), calculate the Age Offline

In this version, the script updates PHPIPAM using the API

I can write scripts, but I'm not a full time developer, and this was done quick & dirty.
So the code may look messy and not optimal.

Feel free to contribute (suggestions, corrections, ....)



Disclaimer:

- Use these scripts at your own risk
- I'm not responsible for any data or system losses caused by this script. Do NOT use this script if you cannot read/understand PHP.
