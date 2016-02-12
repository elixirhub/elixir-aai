#!/usr/bin/perl

# Sample script which is used to get the code and state which then can be used to obtain proxy certificate from CILogon

use strict;
use Digest::SHA2;
use String::Random;
use CGI;
use DBI;

# Ask for the clientID at aai-contact@elixir-europe.org
my $client_id = "myproxy...";
# Put here URL of the callback
my $redirect_url = "https://";
# DB for state and session storage
# CREATE TABLE sessions ( session_id varchar2, state varchar2, code varchar2, token varchar2);
my $db_file = "/var/tmp/cilogon.dbfile";

# Do not edit below this line
# -------------------------------------------------------------------------------
my $q = CGI->new;
my $session_id_cookie_name = "session_id";
my $dbh = DBI->connect("dbi:SQLite:dbname=$db_file","","");

# Check if the user is already authorized
if ($q->param('code') && $q->param('state')) {
	my $session_id = $q->cookie($session_id_cookie_name);
	if (is_state_valid($q->param("state"), $session_id)) {
		my $code = $q->param('code');
		my $state = $q->param('state');

		# Store the access code
		my $sth = $dbh->prepare("UPDATE sessions SET code=? WHERE state=? and session_id=?");
        	if (!$sth->execute($code, $session_id, $state)) {
                	error($sth->errstr);
                	exit;
        	}
        	$sth->finish;
		print $q->header('text/html');
		print $q->h1("Code stored for session ID: $session_id");
		exit;
		# Now you can run script which will use the code to get the OAuth token
	} else {
		error("state is not valid");	
		exit;
	}
} elsif ($q->param('error')) {
	error($q->param('error_description'));
	exit;
} else {
	# User is not autheticated, so get the code and state
	# Constants
	my $cilogon_mp="https://elixir-cilogon-mp.grid.cesnet.cz/mp-oa2-server/authorize";
	my $response_type="code";
	my $scope="openid edu.uiuc.ncsa.myproxy.getcert";

	# Generate session id for the user and store it into the HttpOnly cookie
	my $session_id_generator = new String::Random;
	my $session_id = $session_id_generator->randpattern("sssssssssss");

	# Client session with token binding, do the hash of the session_id
	my $sha2obj = new Digest::SHA2;
	$sha2obj->add($session_id);
	my $nonce = $sha2obj->hexdigest();

	# Protection against CSRF
	my $sha2obj = new Digest::SHA2;
	$sha2obj->add($session_id . $client_id);
	my $state = $sha2obj->hexdigest();
	my $sth = $dbh->prepare("INSERT INTO sessions (session_id, state) VALUES (?,?)");
	if (!$sth->execute($session_id, $state)) {
		error($sth->errstr);
		exit;
	}
	$sth->finish;

	# Instruct user's browser to do the redirection to the CILogon Master Portal
	my $URL = "$cilogon_mp?response_type=$response_type&client_id=$client_id&redirect_uri=$redirect_url&scope=$scope&nonce=$nonce&state=$state";

	# Set the cookie which will hold the nonce and application session id
	my $cookie_session = $q->cookie(-name => "$session_id_cookie_name", -value => "$session_id", -httponly => 1, -secure => 1);
	print $q->redirect(-uri => "$URL", -cookie => $cookie_session);
	exit;
}

# Check if the returned state is valid, it is cross checked with the session id
sub is_state_valid {
	my $state = shift;
	my $session_id = shift;
	my $sth = $dbh->prepare("SELECT 1 FROM sessions WHERE state=? and session_id=?");
	$sth->execute($state, $session_id);
	my $ret = 0;
	if ($sth->fetch()) {
		$ret = 1;
	};
	$sth->finish;
	return $ret;
}

# Just print an error
sub error {
	my $errstr = shift;

	print $q->header('text/html');
	print $q->h1($errstr);
}
