<?php
# set error reporting
error_reporting(E_ALL ^ E_NOTICE ^ E_STRICT);
# api params
$api_url    = "http://127.0.0.1/ipam/api/";     // server url
$api_app_id = "apiclient";                     // application id you set in http://[yourserver]/ipam/administration/api/
$api_key    = "yourapikey";                       // api key or application code - only for encrypted methods, otherwise must be false
# set username / password for authentication, not needed for encrypted communications
$api_username = " ";
$api_password = " ";
# save token or not ?
#   false => don't save, check each time
#   filename => will save token to filename provided
$token_file = "token.txt";
# set result format json/object/array/xml
$result_format = "json";
?>