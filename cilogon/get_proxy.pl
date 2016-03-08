#!/usr/bin/perl

# Sample script which gets the access token

use strict;
use DBI;
use LWP;
use JSON::XS;

# Ask for the clientID and client secret at aai-contact@elixir-europe.org
my $client_id = "myproxy...";
my $client_secret = ""; 
# Put here URL of this script
my $redirect_url = "https://login.elixir-czech.org/oidc/cb";
# DB for state and session storage
# CREATE TABLE sessions ( session_id varchar2, state varchar2, code varchar2, token varchar2);
my $db_file = "/var/tmp/cilogon.dbfile";

# Default proxy lifetime (12 hours), maximum is 1M seconds
my $proxy_lifetime = "43200";

# Request VOMS attributes for VO, don't forget to configure vomses on MyProxy server, optionally vomses attribute can be defined here.
# Also uncomment line 79 
my $vo_name = "vo.elixir-europe.org";

# Do not edit below this line
# -------------------------------------------------------------------------------
my $dbh = DBI->connect("dbi:SQLite:dbname=$db_file","","");

# Constants
my $cilogon_mp_token = "https://elixir-cilogon-mp.grid.cesnet.cz/mp-oa2-server/token";
my $cilogon_mp_proxy = "https://elixir-cilogon-mp.grid.cesnet.cz/mp-oa2-server/getproxy";
my $grant_type = "authorization_code";

my $session_id = $ARGV[0];

# Get the code from the DB
my $sth = $dbh->prepare("SELECT code FROM sessions WHERE session_id=?");
if (!$sth->execute($session_id)) {
	print STDERR $sth->errstr;
        exit -1;
}
my ($code) = $sth->fetchrow_array();
$sth->finish;

# Call the Master Portal to get the access token
my $ua = LWP::UserAgent->new();
my $json_response = $ua->post( $cilogon_mp_token, { 'grant_type' => $grant_type, 
	'code' => $code, 
	'client_id' => $client_id, 
	'client_secret' => $client_secret, 
	'redirect_uri' => $redirect_url } );


# Decode response
my $response = decode_json ( $json_response->content );

my $token = $response->{'access_token'};

# Validate ID token
my $id_token = $response->{'id_token'};
# TODO: finish this

# Store the access token into the DB
my $sth = $dbh->prepare("UPDATE sessions SET token=? WHERE session_id=?");
if (!$sth->execute($token, $session_id)) {
        print STDERR $sth->errstr;
        exit -1;
}
$sth->finish;

print "Token stored\n";

# Call the Master Portal to get the proxy
my $response = $ua->post( $cilogon_mp_proxy, {
        'access_token' => $token,
        'client_id' => $client_id,
        'client_secret' => $client_secret,
#       'voname' => $vo_name,
	'proxylifetime' => $proxy_lifetime} );

# Store proxy in the tmp file
open ( my $fh, ">", "/tmp/x509_$session_id") or die "Cannot open file /tmp/x509_$session_id.";
print $fh $response->content;
close $fh;

print "Proxy has been stored in /tmp/x509_" .  $session_id . "\n";
