nmap -n -sn $cidr -oX alive
Start-Sleep -Seconds 10
nmap-parse-output ./alive all-hosts > hosts.txt
cat ./hosts.txt | select-string -pattern “[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}” > alive.txt