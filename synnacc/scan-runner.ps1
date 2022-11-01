# Handler for the actual scans
# Add new scripts to the folder and create functions for running them
# THis could be done with json files k:v and a loop


function scan-dc {
    $cidr = '192.168.2.0/24'
    $scan = 'DC'
    ./scan.ps1 
}

function scan-beaver {
    $cidr = '192.168.3.0/24'
    $scan = 'Beaver'
    ./scan.ps1 
}

function scan-azure {
    $cidr = '10.215.0.0/24'
    $scan = 'Azure'
    ./scan.ps1 
}

function scan-forbes {
    $cidr = '172.16.8.0/24'
    $scan = 'Forbes'
    ./scan.ps1 
}

function udp-scan-dc {
    $folder = './loot/DC'
    $cidr = '192.168.2.0/24'
    $scan = 'UDP-DC'
    ./udp.ps1 
}

function udp-scan-beaver {
    $folder = './loot/Beaver'
    $cidr = '192.168.3.0/24'
    $scan = 'UDP-Beaver'
    ./udp.ps1 
}

function udp-scan-azure {
    $folder = './loot/Azure'
    $cidr = '10.215.0.0/24'
    $scan = 'UDP-Azure'
    ./udp.ps1 
}

function udp-scan-forbes {
    $folder = './loot/Forbes'
    $cidr = '172.16.8.0/24'
    $scan = 'UDP-Forbes'
    ./udp.ps1 
}

# scan-dc;
# scan-beaver;
# scan-azure;
# scan-forbes;
udp-scan-dc;
udp-scan-beaver;
udp-scan-azure;
udp-scan-forbes;

Write-Output "Scans completed at $(Get-Date)" > timestamp.txt

# We need something here to take our completed HTML reports and Scan data, move them and deploy webserver for report
# Maybe HUGO, we could have a simple template and generate a site with them.
# We would need a login page as well, though.