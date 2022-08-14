# Ashpool ########################################################################
#                                                                                #
## "Lines of light, ranged in the nonspace of the mind.." ########################
#                                                                                #
### Discovery ####################################################################
#                                                                                #
#### Scan, parse and strip the MAC addresses so we have a clean target list ######
##################################################################################

# [CmdletBinding()]
# param (
#     [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName = $true)]
#     [string]$cidr,
#     [string]$name
# )

$cidr = '10.215.0.0/24'
$name = 'cloud'
$scan = $name

# DEBUG: For seeing how long these scans take
$stopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
$stopWatch.Start()


# Make output directories and delete the damn SMB flood script
if(!(test-path /loot)){ mkdir /loot }
if(!(test-path /loot/$scan)){ mkdir /loot/$scan }
if( test-path /usr/share/nmap/scripts/smb-flood.nse ) { rm /usr/share/nmap/scripts/smb-flood.nse }
cd /loot/$scan

# Folder for XML files/ ugly data and one for vuln scan output. We will build the report in main folder to keep it clean
mkdir ScanData
mkdir Vulns

nmap -n -sn $cidr -oX alive
Start-Sleep -Seconds 10
nmap-parse-output ./alive all-hosts > hosts.txt
cat ./hosts.txt | select-string -pattern “[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}” > alive.txt

# Exclusion list, fragile/sensitive hosts that should be excluded
# We will have to do like a replace where it opens exclude file and looks for that ip in alive and replaces it with nothing?
# $exclude = cat ./exclude.txt

# Service scan of ports and services on target list
nmap -n -sV -p- -iL alive.txt --stats-every 30s -oX services 
Start-Sleep -Seconds 15

# Functionize this
# could have just one function nmap-parse-output services service $service > $service.txt and pass all these as arguments
# function nmap-parse-output {
#     nmap-parse-output services service $service > $service.txt
# }
# Another function to process into the input list format

# Parse ports and services, group by service and port and output to files
nmap-parse-output services ports > ports.txt
nmap-parse-output services ports blocked-ports > blocked-ports.txt
nmap-parse-output services service-names > services.txt
nmap-parse-output services group-by-ports > group-by-ports.txt
nmap-parse-output services group-by-service > group-by-service.txt

# Parse for HTTP ports and process into text file for scan input
nmap-parse-output services http-ports > http-ports.txt
$http = cat http-ports.txt; $http -replace '(.+?):.+','$1' > http-ports.txt

# Parse for TLS ports and process into text file for scan input
nmap-parse-output services tls-ports > tls-ports.txt
$tls = cat tls-ports.txt; $tls -replace '(.+?):.+','$1' > tls-ports.txt

# Parse for Proxies and process into text file for scan input
nmap-parse-output services service http-proxy > http-proxy.txt
$proxy = cat http-proxy.txt; $proxy -replace '(.+?):.+','$1' > http-proxy.txt

# Parse for MSRPC and process into text file for scan input
nmap-parse-output services service msrpc > msrpc.txt
$msrpc = cat msrpc.txt; $msrpc -replace '(.+?):.+','$1' > msrpc.txt

# Parse for SMB and process into text file for scan input
nmap-parse-output services service microsoft-ds > smb.txt
$smb = cat smb.txt; $smb -replace '(.+?):.+','$1' > smb.txt

# Parse for LDAP and process into text file for scan input
nmap-parse-output services service ldap > ldap.txt
$ldap = cat ldap.txt; $ldap -replace '(.+?):.+','$1' > ldap.txt

# Parse for NETBIOS and process into text file for scan input
nmap-parse-output services service netbios-ssn > netbios.txt
$netbios = cat netbios.txt; $netbios -replace '(.+?):.+','$1' > netbios.txt

# Parse for SSH and process into text file for scan input
nmap-parse-output services service ssh > ssh.txt
$ssh = cat ssh.txt; $ssh -replace '(.+?):.+','$1' > ssh.txt

# Parse for FTP and process into text file for scan input
nmap-parse-output services service ftp > ftp.txt
$ftp = cat ftp.txt; $ftp -replace '(.+?):.+','$1' > ftp.txt

# Parse for SMTP and process into text file for scan input
nmap-parse-output services service smtp > smtp.txt
$smtp = cat smtp.txt; $smtp -replace '(.+?):.+','$1' > smtp.txt

# Parse for SNMP and process into text file for scan input
nmap-parse-output services service snmp > snmp.txt
$snmp = cat snmp.txt; $snmp -replace '(.+?):.+','$1' > snmp.txt

# Parse for TELNET and process into text file for scan input
nmap-parse-output services service telnet > telnet.txt
$telnet = cat telnet.txt; $telnet -replace '(.+?):.+','$1' > telnet.txt

# Parse for MSSQL and process into text file for scan input
nmap-parse-output services service mssql > mssql.txt
$mssql = cat mssql.txt; $mssql -replace '(.+?):.+','$1' > mssql.txt

# Parse for MYSQL and process into text file for scan input
nmap-parse-output services service mysql > mysql.txt
$mysql = cat mysql.txt; $mysql -replace '(.+?):.+','$1' > mysql.txt

# Parse for RPC and process into text file for scan input
nmap-parse-output services service rpc > rpc.txt
$rpc = cat rpc.txt; $rpc -replace '(.+?):.+','$1' > rpc.txt

# Parse for DNS and process into text file for scan input
nmap-parse-output services service domain > dns.txt
$dns = cat dns.txt; $dns -replace '(.+?):.+','$1' > dns.txt

# Enumeration
touch enum-all.txt
# Enumerate HTTP, save output of script scan and also append the results to the main file for convenience
nmap -n -sV --stats-every 30s --script "http-trace,http-userdir-enum,http-enum,http-robots.txt,http-auth,http-auth-finder,http-brute,http-errors,http-csrf,http-cors,http-cross-domain-policy,http-exif-spider,http-fileupload-exploiter,http-form-brute,http-headers,http-methods,http-method-tamper,http-ntlm-info,http-open-redirect,http-passwd,http-phpmyadmin-dir-traversal,http-wordpress-enum,http-wordpress-brute,http-wordpress-users,http-xssed,https-redirect" -iL http-ports.txt -o enum-http-ports2.txt -d --stats-every 30s


### DEBUG:BREAK ###

nmap -n -sV --stats-every 30s --script "http-*" -iL http-ports.txt -o enum-http-ports.txt -d --stats-every 30s
$httpenum = cat enum-http-ports.txt; $httpenum2 = cat enum-http-ports2.txt; $httpenum >> enum-all.txt; $httpenum2 >> enum-all.txt

# Enumerate TLS
nmap -n -sV --stats-every 30s --script "tls-*,ssl-*" -iL tls.txt -o enum-tls.txt -d --stats-every 30s
$tls = cat enum-tls.txt; $tls >> enum-all.txt

# Enumerate MSRPC
nmap -n -sV --stats-every 30s --script "msrpc-*" -iL msrpc.txt -o enum-msrpc.txt
$msrpc = cat enum-msrpc.txt; $msrpc >> enum-all.txt

# Enumerate SMB, save output of script scan and also append the results to the main file for convenience
nmap -n -sV --stats-every 30s -p445 --script "smb2-*,smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-services.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse" -iL smb.txt -o enum-smb.txt
$enumsmb = cat enum-smb.txt; $enumsmb >> enum-all.txt


# Enumerate NETBIOS
nmap -n -sV -iL netbios.txt --script nbstat -o nbstat.txt -d --stats-every 30s
$nbstat = cat nbstat.txt; $nbstat >> enum-all.txt

# Enumerate SSH
nmap -n -Pn -sV -iL ssh.txt --script "ssh-*" -p22 -v -o enum-ssh.txt -d --stats-every 30s
$enumssh = cat enum-ssh.txt; $enumssh >> enum-all.txt

# Enumerate FTP, save output of script scan and also append the results to the main file for convenience
nmap -n -sV --script "ftp-*" -p21 -iL ftp.txt -o enum-ftp.txt -d --stats-every 30s
$ftp = cat enum-ftp.txt; $ftpenum >> enum-all.txt

# Enumerate SMTP, save output of script scan and also append the results to the main file for convenience
nmap -n -sV --script "smtp-*" -iL smtp.txt -o enum-smtp.txt -d --stats-every 30s
$smtp = cat enum-smtp.txt; $smtp >> enum-all.txt

# Enumerate SNMP, save output of script scan and also append the results to the main file for convenience
nmap -n -sV --script "snmp-*" -iL snmp.txt -o enum-snmp.txt -d --stats-every 30s
$snmp = cat enum-snmp.txt; $snmp >> enum-all.txt

# Enumerate TELNET, save output of script scan and also append the results to the main file for convenience
nmap -n -sV --script "telnet-*" -p23 -iL telnet.txt -o enum-telnet.txt -d --stats-every 30s
$telnet = cat enum-telnet.txt; $telnet >> enum-all.txt

# Enumerate MYSQL
nmap -n -sV --script "mysql-*" -iL alive.txt -o enum-mysql.txt -d --stats-every 30s
$mysql = cat enum-mysql.txt; $mysql >> enum-all.txt

# Enumerate MSSQL
nmap -n -sV --script "ms-sql-*" -iL alive.txt -o enum-mssql.txt -d --stats-every 30s 
$mssql = cat enum-mssql.txt; $mssql >> enum-all.txt

# Enumerate Kerberos
nmap -sUV --script krb5-enum-users -p88 -iL alive.txt -o enum-kerberos.txt
$kerberos = cat enum-kerberos.txt; $kerberos >> enum-all.txt

# Enumerate LDAP
nmap -n -sV --script ldap-rootdse -p389 -iL alive.txt -o enum-ldap.txt -d --stats-every 30s
$ldap = cat enum-ldap.txt; $ldap >> enum-all.txt


# Vuln scan alive hosts by ports with Vuln and Vulners
$ports = cat ports.txt
nmap -n -sV -sC -p $ports -iL alive.txt -oA default-scripts -d --stats-every 30s
nmap -n -sV --script vulners -p $ports -iL alive.txt -oA vulners-alive -d --stats-every 30s

# vuln scanning with nmap
# Scan for score 4 and above targeted at different services. Lets see how this goes. We always have the by host/port version below to catch everything.
nmap -n -Pn -sV --script "smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-cve-2017-7494.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse,smb-vuln-regsvc-dos.nse,smb-vuln-webexec.nse,smb-webexec-exploit.nse,smb2-vuln-uptime.nse,smb2-security-mode.nse" -p445 -iL smb.txt -oA vuln-smb-cve -d --stats-every 30s
nmap -n -Pn -sV --script vuln --script-args mincvss=4 -p445 -iL smb.txt -oA vuln-smb -d --stats-every 30s
nmap -n -Pn -sV --script vuln --script-args mincvss=4 -iL http-ports.txt -oA vuln-http-ports -d --stats-every 30s
nmap -n -Pn -sV --script vuln --script-args mincvss=4 -iL msrpc.txt -oA vuln-msrpc -d --stats-every 30s
nmap -n -Pn -sV --script vuln --script-args mincvss=4 -p22 -iL ssh.txt -oA vuln-ssh -d --stats-every 30s
nmap -n -Pn -sV --script vuln --script-args mincvss=4 -p21 -iL ftp.txt -oA vuln-ftp -d --stats-every 30s
nmap -n -Pn -sV --script vuln --script-args mincvss=4 -p23 -iL telnet.txt -oA vuln-telnet -d --stats-every 30s
nmap -n -Pn -sV --script vuln --script-args mincvss=4 -iL smtp.txt -oA vuln-smtp -d --stats-every 30s
nmap -n -Pn -sV --script vuln --script-args mincvss=4 -iL snmp.txt -oA vuln-snmp -d --stats-every 30s
nmap -n -Pn -sV --script vuln --script-args mincvss=4 -iL mysql.txt -oA vuln-mysql -d --stats-every 30s
nmap -n -Pn -sV --script vuln --script-args mincvss=4 -iL mssql.txt -oA vuln-mssql -d --stats-every 30s

mv vuln* /Vulns
mv *.xml /ScanData
mv *.gnmap /ScanData
mv *.nmap /ScanData

# DEBUG: End of Timer
$stopWatch.Stop()
Write-Output "Scan took: $stopwatch.Elapsed.TotalSeconds "




# nmap -n -sV --script=vulscan\vulscan.nse -p $ports -iL alive.txt -oA vulscan-alive

### UDP and RECON SCRIPT features ###



# # UDP discovery scans
# nmap -sU –top-ports 100 -iL alive.txt -oX udp-top --max-retries 2 -d --stats-every 30s
# nmap -sUV –top-ports 100 -iL alive.txt -oX udp-top-services --max-retries 2 -d --stats-every 30s

# # UDP Service Breakdown
# nmap-parse-output udp-top ports > udp-ports.txt
# nmap-parse-output udp-top group-by-ports > udp-group-by-ports.txt
# nmap-parse-output udp-top service-names > udp-services.txt

# nmap -sTUV –top-ports 200 -iL alive.txt -oX udp-mixed-top200 -d --stats-every 30s

# removed the -Pn, add back if its slow I guess
# nmap -vv -O -P0 -sTUV –top-ports 1000 -oX udp-mixed-top1000 $test -d --stats-every 30s
# 




