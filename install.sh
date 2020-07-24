#!/bin/sh
sudo apt-get install python3-pip
pip3 install python-nmap
sudo apt-get upgrade python
sudo apt-get upgrade nmap
alias python-nmap="python3 .backup.py"
