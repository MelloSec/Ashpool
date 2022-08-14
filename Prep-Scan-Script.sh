#!/bin/bash
apt update -y
apt install -y nmap
apt install -y xsltproc 
apt install -y unzip
apt install -y curl
# need to install the new golang bin manually so the install commands go through
curl -LO https://go.dev/dl/go1.19.linux-amd64.tar.gz
tar -C /usr/local -xzf https://go.dev/dl/go1.19.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin

apt install -y git
mkdir /loot

# Go tools for web
go install github.com/OJ/gobuster/v3@latest
go install github.com/jaeles-project/gospider@latest
go install github.com/sensepost/gowitness@latest

# install vulners
cd /usr/share/nmap/scripts/
git clone https://github.com/vulnersCom/nmap-vulners.git

# install vulscan
git clone https://github.com/scipag/vulscan
ln -s `pwd`/scipag_vulscan /usr/share/nmap/scripts/vulscan

# install the nmap parser
cd /loot
git clone https://github.com/ernw/nmap-parse-output.git
cd nmap-parse-output
./nmap-parse-output
apt update -y

export PATH="/loot:$PATH"
export PATH="/loot/nmap-parse-output:$PATH"

echo 'export PATH="/loot:$PATH"' >> /root/.bashrc
echo 'export PATH="/loot/nmap-parse-output:$PATH"' >> /root/.bashrc