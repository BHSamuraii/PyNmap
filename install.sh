#!/bin/bash
sudo apt-get install python3-pip
pip3 install python-nmap
sudo pip3 install python3-nmap
sudo apt-get upgrade python
sudo apt-get upgrade nmap
filepath=`locate pynmap2.py`
alias pynmap="sudo python3 $filepath"
cd
echo alias pynmap="sudo python3 $filepath" >> .bashrc
