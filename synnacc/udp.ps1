
cd $folder

# Try without -n to to check speed
nmap -sUV -sC --top-ports 1000 -v -iL alive.txt -oX udp-services -d --stats-every 30s --max-retries 0 --min-rate 75
Start-Sleep -Seconds 15

# Parse ports and services, group by service and port and output to files
nmap-parse-output services ports > udp-ports.txt
nmap-parse-output services ports blocked-ports > udp-blocked-ports.txt
nmap-parse-output services service-names > udp-services.txt
nmap-parse-output services group-by-ports > udp-group-by-ports.txt
nmap-parse-output services group-by-service > udp-group-by-service.txt

# Scan for Vulnerabilities
$ports = cat ./ports.txt
nmap -n -A -sUV --script vulners -p $ports -iL alive.txt -oA UDPvulners -d --stats-every 30s --max-retries 2 --min-rate 100