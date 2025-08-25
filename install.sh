#!/bin/bash

# MagicRecon Installation Script

echo -e "\033[1;32m[*] Installing MagicRecon dependencies...\033[0m"

# Update system
sudo apt-get update
sudo apt-get upgrade -y

# Install basic tools
sudo apt-get install -y python3 python3-pip python3-venv git curl wget nmap dnsutils whois

# Install Python tools
pip3 install --upgrade pip
pip3 install requests beautifulsoup4 lxml dnspython

# Create directories
mkdir -p ~/tools ~/magicrecon_results

# Install Golang
if ! command -v go &> /dev/null; then
    wget https://golang.org/dl/go1.19.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.19.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    echo 'export GOPATH=$HOME/go' >> ~/.bashrc
    source ~/.bashrc
    rm go1.19.linux-amd64.tar.gz
fi

# Install recon tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/OWASP/Amass/v3/...@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/notify/cmd/notify@latest

# Copy Go tools to PATH
sudo cp ~/go/bin/* /usr/local/bin/

# Install other tools
sudo apt-get install -y whatweb dirsearch sqlmap aquatone theharvester

# Clone repositories
git clone https://github.com/projectdiscovery/nuclei-templates.git ~/tools/nuclei-templates
git clone https://github.com/danielmiessler/SecLists.git ~/tools/SecLists
git clone https://github.com/m4ll0k/SecretFinder.git ~/tools/SecretFinder
git clone https://github.com/s0md3v/Corsy.git ~/tools/Corsy

# Install Python requirements
pip3 install -r ~/tools/SecretFinder/requirements.txt
pip3 install -r ~/tools/Corsy/requirements.txt

echo -e "\033[1;32m[*] Installation completed! Don't forget to set your API tokens in configuration.cfg\033[0m"
