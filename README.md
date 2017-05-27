# check_ssl
Monitoring of SSL/TLS configurations.

Secure Sockets Layer (SSL) is a cryptographic protocol designed to ensure authenticity, confidentiality and integrity in the exchange of data between client/server applications, and has the successor to Transport Layer Security (TLS). This protocol uses digital certificates, which are authenticated electronic files with digital signature. SSL/TLS certificates can be revoked, being expired, using unsafe cryptographic protocols, being poorly configured, among other weaknesses susceptible to making communication insecure.

This Nagios plugin monitors the SSL/TLS settings, using the SSLLABS (https://www.ssllabs.com/) Web service, performs tests on certificates, seeking vulnerabilities, and in case of detection returns the warning or critical state, depending on the arguments defined, namely the domain name and the values for warning and critical, which are based on the classification table of the SSLLAB, and the quantity of days before the expiry of the certificate from which it is desirable to be notified.
By omission, the absence of 30 days less for the certificate expires, is notified with the warning state, regardless of the outcome of the Web tests service. Classifications C+, C-, C, D+, D, D- are by default considered critical, whereas ratings and E+, E, E-, F+, F, F-, T, M are interpreted as warning.

Mandatory arguments: The following arguments must be specified when the module is executed:

-H or --domain used to specify the domain name.

Optional arguments: The following arguments are optionally invoked, as required by the user:

-d or --days used to specify how many days before the expiration date should be displayed the warning state.

-c or --critical used to specify which classifications of ssllabs should be interpreted as critiques.

-w or --warning used to specify which classifications of ssllabs should be interpreted as warning.

-s or --sleep used to specify the time when the module should wait to continue executing.

-V or --version used to query the module version.

-A or --author used to query the author's data.

Example command-line execution:

./check_ssl.py -H www.amazon.com -c E+,E,E-,F+,F,F-,T,M -w C+,C-,C,D+,D,D- -d 15

