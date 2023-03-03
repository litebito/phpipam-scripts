<?php
/**
 * Name         : nmapScanner.php
 * Author       : litebito
 * Created      : 07-apr-2018
 * Updated      : 03-mar-2023
 * Version      : 2.1
 * Description  : This script performs a similar function as pingScanner.php, but using nmap.
 *                This script will do a scan and discovery in one, so this script should find hosts which are not found by the standard scanner.
 *                It also will be able to find all MAC addresses (which the standard discovery does not seem to be able to do)
 *                Attention, this script may overwrite some information which is written by the other discovery or scanning scripts from PHPIPAM, like
 *                  - lastseen, notes, MAC addres, hostname, custom variables
 *
 * Disclaimer   : USE AT YOUR OWN RISK !!
 *                The author is NOT responsible for any data or system losses caused by this script. Do NOT use this script if you cannot read/understand PHP.
 *
 * This script does the following:
 *      - fetches flagged subnets for scanning
 *      - scans the whole subnet witn Nmap, this will also scan hosts which do not respond to ping and discover missing MAC
 *      - FOR EACH scan enabled/toggled SUBNET from PHPIPAM, there are 2 phases and assumes that this nmap scanner script is "the boss" (it will overwrite any other scan/discovery in case of conflicts.)
 *      - Phase 1 : start from the nmap output of the subnet, and update or add to PHPIPAM, that way, we need to read the file only once
 *              - lastseen (this is important for phase 2)
 *              - hostname
 *              - MAC address
 *              - other info (notes or comments)
 *      - Phase 2 : walk through the subnet from PHPIPAM, and compare the lastseen from the script with the lastseen from PHPIPAM:
 *              - if the one in the database is older, we assume the ip was no longer seen by nmap, and thus considered offline
 *              - change the status to offline (not yet as fine grained as in the pingCheck script with the grace period)
 *              - calculate the Age Offline
 *      - all updates to PHPIPAM are done using the PHPIPAM API
 *
 *  Requirements :
 *      - nmap 7.0+ installed (default nmap install)
 *      - PHPIPAM 1.5+ (and PHPIPAM api setup correctly)
 *      - PHPIPAM ip address custom fields:  (I use them for different purposes in my setup, not everyone may need them)
 *              cAgeOffline, cLastSeen, cNmapInfo, cDiscoveryScanComment
 *      - class.PHPIPAM-api.php needs to be present in /ipam/functions/classes/ (source: https://github.com/phpipam/phpipam-api-clients/tree/master/php-client )
 *      - api-config.php needs to be present in /ipam/functions/scripts
 *      - this script itself needs to be present in /ipam/functions/scripts
 *      - WARNING : for now, this script still requires mcript, so uncomment $api_crypt_encryption_library = "mcrypt"; in config.php (I did not have the time to fix it for openssl)
 *      - script needs to run as root, as per nmap requirement (nmap needs to be run as root in order todo ping scans)
 *
 *      Script can be run from cron, here is a crontab example for 15 minutes scanning:
 *              *\/15 * * * *  /usr/local/bin/php /<sitepath>/functions/scripts/nmapScanner.php > /dev/null 2>&1
 *
 *  Future todo/wishlist:
 *      - do more error checking on the Nmap output (check if it was a success or not)
 *      - better way to run through the Nmap output file (more optimal)
 *      - change this from API to native (incorporate nmap as a new option in the discoverycheck and pingcheck scripts)
 *      - use the DNS server info from PHPIPAM for Nmap
 *      - update the last scan setting on subnetlevel after running the script
 *      - update age online
 *
 *  Other comments:
 *      - namp output in XML for easier processing, also has more data dan txt output
 *      - if nested subnets are all set to be scanned, subnets will be scanned multiple times. In other words, it will not check for (already scanned) parent subnets.
 *      - Using XMLreader to avoid loading entire xml file in memory, as scan files can grow very large (for example, an nmap output xml of a discoveryscan of a /8 can be as large as 4GB !)
 *  Known issues (bugs in the API??):
 *      - there are errors when sections are empty:
 *          - if the section in phpipam is empty, there is no array to iterate to, so it is ok, it is just not the cleanest solution
 *          - if the subnet in phpipam is empty there is no array to iterate to, so it is ok, it is just not the cleanest solution
 *      - Does not seem to update the lastseen date in the PHPIPAM db, although the API does not return an error
 *      - Does not seem to update the tag (onnline/offline) in the PHPIPAM db? Although the API does not return an error
 *
 */

// script can only be run from cli
if(php_sapi_name()!="cli")                                              { die("This script can only be run from cli!"); }

/*
 * Init
 */
require("custom_api-config.php");
require( dirname(__FILE__) . '/../../functions/classes/class.phpipam-api.php');
$memstart = round(memory_get_usage()/1024,2);
$xmlread = new XMLReader;
$scriptname = basename(__FILE__);
$logdir = "/var/log/";
$logfile = $logdir."phpipam_".$scriptname.".log"; // logging
$debuglevel = 3 ; // 1 = errors 2 = info 3 = debug
$nmapdir = "/var/log/"; // where you want to save the nmap outputfiles for further processing
$nmapdns = "-dns-servers 10.0.2.14,,10.0.2.1" ; // update with the (internal) dns servers on your network, the dns servers which have the host records about the subnets you are scanning

// set now for whole script
$now     = time();
$nowdate = date ("Y-m-d H:i:s");
// init API object
$API = new PHPIPAM_api_client ($api_url, $api_app_id, $api_key, $api_username, $api_password, $result_format);
// debug - only to debug curl
$API->set_debug (true);



/*
 * Functions
 */

// just a quick logging function for logging to a logfile and console
function logger($level, $message){
    $logtime = date("Y-m-d H:i:s");
    global $logfile;
    global $memstart;
    global $debuglevel;
    switch ($level) {
        case 1:             $loglevel = "ERROR"; break;
        case 2:             $loglevel = "INFO"; break;
        case 3:             $loglevel = "DEBUG"; break;
    }
    $memcur = round(memory_get_usage()/1024,2)-$memstart;
    if ($level <= $debuglevel)
    {
        $logmessage = "[{$logtime}][{$loglevel}]{$message} [{$memcur}kb]".PHP_EOL;
        print_r($logmessage);
        file_put_contents($logfile, $logmessage, FILE_APPEND);
    }
}

/*
 * Start Script
 */
echo "\r\n";
logger(2,"====================================================================================================");
logger(2,"$scriptname STARTED...");
logger(2,"====================================================================================================");
echo "\r\n";

// get all sections from PHPIPAM
$API->execute ("GET", "sections", array(), array(), $token_file);
$APIresult = $API->get_result();
logger(3,"Response Headers ...");
logger(3,$response_headers);
//logger(3,"API result:  ...");
//logger(3,$APIresult);


// Getting rid of the api response info, and create the array for sections
$arr_result = json_decode($APIresult, true);
logger(3,$arr_result);



$ipam_sections = $arr_result['data'];


// Run through each section from PHPIPAM
foreach ($ipam_sections as $ipam_section) {
    echo "\r\n";
    logger(2,"====================================================================================================");
    logger(2,"Section name {$ipam_section['name']}");
    logger(2,"====================================================================================================");
        $API->execute ("GET", "sections", array($ipam_section['id'],"subnets"), array(), $token_file);
    $APIresult = $API->get_result();
    $arr_result = json_decode($APIresult, true);
    $ipam_subnets = $arr_result['data'];
    logger(3,"Start to run through all the subnets in the current section {$ipam_section['name']} ");
    foreach ($ipam_subnets as $ipam_subnet)
    {
        // Check if the subnet is set to be discovered
        if ($ipam_subnet['discoverSubnet'] == "1")
        {
            echo "\r\n";
            logger(2,"---------------------------------------------------------------------------------------------------------");
            logger(2,"The subnet {$ipam_subnet['subnet']}/{$ipam_subnet['mask']}, subnetId {$ipam_subnet['id']} is flagged for discovery, starting the work");
            logger(2,"---------------------------------------------------------------------------------------------------------");

            $_subnet2scan = $ipam_subnet['subnet'] . "/" . $ipam_subnet['mask'];
            $nmapfile = $nmapdir . "nmapscan_" . $ipam_subnet['subnet'] . "_" . $ipam_subnet['mask'].".xml";
            logger(3,"Nmap outputfile $nmapfile");
            exec("nmap -sn -PR -PE -R -oX $nmapfile $nmapdns $_subnet2scan", $output);
            $API->execute ("GET", "subnets", array($ipam_subnet['id'],"addresses"), array(), $token_file);
            $APIresult = $API->get_result();
            $arr_result = json_decode($APIresult, true);
            $ipam_hosts = $arr_result['data'];
            // Check if we can open the Nmap xml
            if (!$xmlread->open($nmapfile))
            {
                logger(1,"Something went wrong, failed to open $nmapfile");
            } #end if
            // Phase 1 : check for every ipaddress from the NMAP scan against PHPIPAM
            logger(3,"PHASE 1 : NMAP against IPAM : check every IP from $nmapfile for {$ipam_subnet['subnet']}/{$ipam_subnet['mask']} against IPAM");
            $i = 1;
            while($xmlread->read())
            {
                if ($xmlread->nodeType == XMLReader::ELEMENT && $xmlread->name == 'nmaprun')
                {
                    $_lastseen = date('Y-m-d H:i:s',$xmlread->getAttribute('start')); // convert from the nmap epoch string
                    logger(3,"Checking lastseen from start attribute (epoch) : $_lastseen");
                } #end if
                // setting bogus values
                $_nhostname ="NA";
                $_nhostipv4 = "NA";
                $_nhostmac = "00:00:00:00:00:00";
                $_nhostreason = "NA";
                if ($xmlread->nodeType == XMLReader::ELEMENT && $xmlread->name == 'host')
                {
                    $hostnode = new SimpleXMLElement($xmlread->readOuterXML());
                    // the hostname is stored in a different structure than the other attributes, so we look for them in a different way:
                    if($hostnode->hostnames->hostname['name'] != "") { $_nhostname = $hostnode->hostnames->hostname['name']; }
                    // Walk through the child nodes, to get each element we need
                    foreach ($hostnode->children() as $hostelement) {
                        if ($hostelement['addrtype'] == "ipv4") { $_nhostipv4 = $hostelement['addr']; }
                        if ($hostelement['addrtype'] == "mac") { $_nhostmac = $hostelement['addr']; }
                        if ($hostelement['state'] == "up") { $_nhostreason = $hostelement['reason']; }
                    } #end foreach
                    $_nmapinfo = "Type: " . $_nhostreason . " / MAC: " . $_nhostmac;
                    logger(3,"HOSTNODE $i has : hostipv4: $_nhostipv4 - hostmac: $_nhostmac - hostname: $_nhostname");
                    $i++;
                    // We have a host and its elements, now we can search for this IP in the current PHPIPAM subnet
                    $found = false;
                    if (is_iterable($ipam_hosts)) {
                        //logger(3,"THISISANARRAY");
                        //print_r ($ipam_hosts);
                        }
                    else
                       {
                        logger(3,"NOTANARRAY");
                        print_r ($ipam_hosts);
                       }
                
                    // if the nmapscan does not return hosts, $ipam_hosts is not an array, and the foreach below will fail. that is ok, because the nmapscan is empty anyway         
                    foreach ($ipam_hosts as $ipam_host)
                    {
                        if (($_nhostipv4 == $ipam_host['ip'])  )
                        {
                            // we have a winner, lets update;
                            $found = true;
                            if ($ipam_host['excludePing'] != "1" )
                            {
                                $_tmplogsubnetid = $ipam_subnet['id'];
                                logger(2, "Match found for $_nhostipv4, in subnetID $_tmplogsubnetid, updating PHPIPAM with $_nhostname, $_nhostmac, $_lastseen, $_nhostreason");
                                $_tmplogline = "Match found for $_nhostipv4, updating PHPIPAM with $_nhostname, $_nhostmac, $_lastseen, $_nhostreason";
                                // split the execution to avoid updating phpIPAM with the bogus values, fix for the fact that NMAP cannot get MAC addresses beyon the local subnet
                                $API->execute ("PATCH", "addresses", array($ipam_host['id']), array( "tag"=>2, "lastSeen"=>$_lastseen, "hostname"=>strval($_nhostname), "custom_cAgeOffline"=>"0", "custom_cNmapInfo"=>$_nmapinfo, "custom_cLastSeen"=>$_lastseen, "custom_cDiscoveryScanComment"=>$_tmplogline), $token_file);
                                $APIresult = $API->get_result();
                                if ($_nhostmac != "00:00:00:00:00:00")
                                {
                                    logger(3, "Updating $_nhostipv4, in PHPIPAM with MAC $_nhostmac");
                                    $API->execute ("PATCH", "addresses", array($ipam_host['id']), array("mac"=>"$_nhostmac"), $token_file);
                                    $APIresult = $API->get_result();
                                }
                                else 
                                {
                                    logger(3, "NOT Updating $_nhostipv4, scanned MAC is empty :  $_nhostmac");
                                    
                                }
                                
                                $arr_result = json_decode($APIresult, true);
                                if($arr_result["code"]!="200") { logger(1,"There was an error updating {$ipam_host['ip']}, message from PHPIPAM : {$arr_result["message"]}");  }
                                else { 
                                    logger(3,"Update was successful for {$ipam_host['ip']}, message from PHPIPAM : {$arr_result["message"]}"); 
                                }
                            } #end if
                            else
                            {
                                logger(2, "Host $_nhostipv4, was set to be excluded from ping/scan, not updating PHPIPAM");
                            } #end else
                        } #end if
                    } #end foreach
                    if ($found == false) 
                        { 
                            $_tmplogsubnetid = $ipam_subnet['id'];
                            logger(2, "No match found for $_nhostipv4 ($_nhostname), adding the new host to PHPIPAM to subnetid $_tmplogsubnetid.");
                            $_tmplogline = "No match found for $_nhostipv4 ($_nhostname), adding the new host to to subnetid $_tmplogsubnetid to PHPIPAM";
                            $API->execute ("POST", "addresses", array() , array( "subnetId"=>$ipam_subnet['id'] , "ip"=>strval($_nhostipv4), "hostname"=>strval($_nhostname), "mac"=>strval($_nhostmac), "tag"=>2, "lastSeen"=>$_lastseen, "custom_cAgeOffline"=>"0", "custom_cNmapInfo"=>$_nmapinfo, "custom_cLastSeen"=>$_lastseen, "custom_cDiscoveryScanComment"=>$_tmplogline), $token_file);
                            $APIresult = $API->get_result();
                            $arr_result = json_decode($APIresult, true);
                            //print_r ($arr_result);
                            if($arr_result["code"]!="200") { logger(1,"There was an error INSERTING $_nhostipv4, message from PHPIPAM : {$arr_result["message"]}");  }
                            else {
                                logger(3,"INSERT was successful for $_nhostipv4, message from PHPIPAM : {$arr_result["message"]}");
                            }
                            
                            
                        } #end if
                } #end if ($xmlread->nodeType == XMLReader::ELEMENT && $xmlread->name == 'host')
            } #end while($xmlread->read())
            $xmlread->close;
            // Now we'll run though all hosts of the subnet again, to update the hosts which were not found by the Nmap scanner we'll do this by comparing the custom field cLastSeen date
            // Phase 2 : Now we'll run though all hosts of the subnet again, to update the hosts which were not found by the Nmap scanner we'll do this by comparing the custom field cLastSeen date
            logger(3,"PHASE 2 : IPAM against NMAP : Check subnet {$ipam_subnet['subnet']}/{$ipam_subnet['mask']} from IPAM again for hosts not found in the nmapscan $nmapfile");
            foreach ($ipam_hosts as $ipam_host)
            {
                logger(3,"Checking host with {$ipam_host['ip']} for lastSeen {$ipam_host['lastSeen']}, cLastSeen {$ipam_host['custom_cLastSeen']}, tag {$ipam_host['tag']}");
                // the below is still a bit messy, too much juggling with the dates, but for now, it works for what I need.
                // because for now, we've 2 lastseen dates, as the API seems to be unable to update the lastseen in the PHPIPAM DB, we'll compare both results
                $_lsnmap = new DateTime($_lastseen);
                $_test = 2;
                if (!empty($ipam_host['lastSeen'])) { $_lsipam = new DateTime($ipam_host['lastSeen']); $_test--;  }
                if (!empty($ipam_host['custom_cLastSeen'])) { $_lsipam = new DateTime($ipam_host['custom_cLastSeen']); $_test--;  }
                if ($_test == 0)
                {
                    logger(3, "We have 2 dates, one is older than the other one; lets take the most recent of the two");
                    if (strtotime($ipam_host['lastSeen']) < strtotime($ipam_host['custom_cLastSeen'])) { $_lsipam = new DateTime($ipam_host['custom_cLastSeen']);  }
                    else { $_lsipam = new DateTime($ipam_host['lastSeen']);  }
                } # end if
                $_age = $_lsipam->diff($_lsnmap)->format("%a");
                //if age is more than 0, the host is considered offline, so we can update the tag also, We will not update hosts when they are excluded from scans
                if (($_age > 0) AND ($ipam_host['excludePing'] != "1" ))
                {
                        logger(2, "Updating age and status for {$ipam_host['ip']} with tag {$ipam_host['tag']} , updating PHPIPAM with $_age");
                        $API->execute ("PATCH", "addresses", array($ipam_host['id']), array("tag"=>1, "custom_cAgeOffline"=>$_age), $token_file);
                        $APIresult = $API->get_result();
                        $arr_result = json_decode($APIresult, true);
                        if($arr_result["code"]!="200") { logger(1,"There was an error updating {$ipam_host['ip']}, message from PHPIPAM : {$arr_result["message"]}");   }
                        else { 
                            logger(3,"Update was successful for {$ipam_host['ip']}, message from PHPIPAM : {$arr_result["message"]}");   
                        }
                } #end if
                else
                {
                     logger(3, "Host {$ipam_host['ip']}, does not need updating : Age is ($_age) or was set to be excluded from ping/scan, not updating PHPIPAM");
                } #end else
            } #end foreach ($ipam_hosts as $ipam_host)
        } #end if ($ipam_subnet['discoverSubnet'] == "1")
        else
        {
            logger(2,"The subnet {$ipam_subnet['subnet']}/{$ipam_subnet['mask']} NOT flagged for discovery, nothing todo");
        } #end else
    } #end foreach ($ipam_subnets as $ipam_subnet)
}
unset ($ipam_hosts, $ipam_host, $ipam_subnets, $ipam_subnet, $xmlread);

echo "\r\n";
logger(2,"====================================================================================================");
logger(2,"$scriptname ENDED...");
logger(2,"====================================================================================================");
echo "\r\n";

?>
