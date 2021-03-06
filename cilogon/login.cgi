#!/usr/bin/perl

# Sample script which is used to get the code and state which then can be used to obtain proxy certificate from CILogon

use strict;
use Digest::SHA;
use String::Random;
use CGI;

# Ask for the clientID at aai-contact@elixir-europe.org
my $client_id = "myproxy...";
# Put here URL of the callback
my $redirect_url = "https://";

# Do not edit below this line
# -------------------------------------------------------------------------------
my $cilogon_mp = "https://elixir-cilogon-mp.grid.cesnet.cz/mp-oa2-server/authorize";
my $scope="openid edu.uiuc.ncsa.myproxy.getcert";
my $idp_entity_id="https://login.elixir-czech.org/idp/";

my $q = CGI->new;
my $session_id_cookie_name = "session_id";
my $code = $q->param('code');
my $state = $q->param('state');

# Check if the user is already authorized
if ($code && $state) {
	my $session_id = $q->cookie($session_id_cookie_name);
	# Check if the state is valid
	if (is_state_valid($state, $session_id)) {
		# Store the access code
		open( my $fh, ">", "/tmp/cilogon_ac_" . $session_id) or error("Cannot open /tmp/cilogon_ac_" . $session_id);
		print $fh $code;
		close($fh);

		print $q->header('text/html');
		print $q->h1("Code stored for session ID: $session_id");
		exit;
		# Now you can run script ./get_proxy.pl [session ID] which will use the code to get the proxy certificate
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
	my $response_type="code";

	my $session_id = $q->param('session_id');
	if (!$session_id) {
		# Generate session id for the user and store it into the HttpOnly cookie
		my $session_id_generator = new String::Random;
		$session_id = $session_id_generator->randpattern("ccCCnnccCCnnccnn");
	}

	# Client session with token binding, do the hash of the session_id
	my $sha2obj = new Digest::SHA-256;
	$sha2obj->add($session_id);
	my $nonce = $sha2obj->hexdigest();

	# Protection against CSRF
	my $sha2obj = new Digest::SHA-256;
	$sha2obj->add($session_id . $client_id);
	my $state = $sha2obj->hexdigest();
	open( my $fh, ">", "/tmp/cilogon_state_" . $session_id) or error("Cannot open /tmp/cilogon_state_" . $session_id);
        print $fh $state;
        close($fh);

	# Instruct user's browser to do the redirection to the CILogon Master Portal
	my $URL = "$cilogon_mp?response_type=$response_type&client_id=$client_id&redirect_uri=$redirect_url&scope=$scope&nonce=$nonce&state=$state&idphint=$idp_entity_id";

	# Set the cookie which will hold the nonce and application session id
	my $cookie_session = $q->cookie(-name => "$session_id_cookie_name", -value => "$session_id", -httponly => 1, -secure => 1);
	print $q->redirect(-uri => "$URL", -cookie => $cookie_session);
	exit;
}

# Check if the returned state is valid, it is cross checked with the session id
sub is_state_valid {
	my $state = shift;
	my $session_id = shift;

	open( my $fh, "<", "/tmp/cilogon_state_" . $session_id) or error("Cannot open /tmp/cilogon_state_" . $session_id);
	my $stored_state = <$fh>;
        close($fh);

	# Delete the file with state it won't be needed anymore.
	unlink("/tmp/cilogon_state_" . $session_id);

	if ($stored_state == $state) {
		return 1;	
	}
	return 0;
}

# Just print an error
sub error {
	my $errstr = shift;

	print $q->header('text/html');
	print $q->h1($errstr);
}
