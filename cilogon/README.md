# cilogon
Sample code for getting the proxy certificate via CILogon (https://wiki.nikhef.nl/grid/CILogon_Pre-Pilot_Work#Public_Demo). There is also simplified version which doesn't use DB to store the data. Use of simplified version is recommended. 

Required packages (Debian): libjson-xs-perl, libstring-random-perl, libdigest-sha-perl, libcrypt-ssleay-perl 

1. Register your client at https://elixir-cilogon-mp.grid.cesnet.cz/mp-oa2-server/register
2. Write an email to aai-contact@elixir-europe.org in order to approve your client
2. Put client ID into the login.cgi, also modify callback URL which must point to login.cgi on your server.
3. From your web application you can redirect user to login.cgi (you can pass your session ID to the login.cgi via GET parameter session_id).
4. Login.cgi will let user authenticate and after the successful authentication it stores the code into the DB (code can be retreived from the DB using session id).
5. Put the client ID and client secret into the get_proxy.pl.
6. Now you can run get_proxy.pl [session ID] from the CMD line to the the proxy certificate, proxy certificate will be stored in /tmp/x509_[session id].

Certificate of the CA, which issues proxy certificates, can be downloaded from http://rcauth.eu
