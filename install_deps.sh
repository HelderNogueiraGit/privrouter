#!/bin/bash
#install dependencies for debian systems

#update the system first
apt-get update
apt-get upgrade -y

#install dependencies
apt-get install -y iproute2 openssl cryptsetup openvpn iptables net-tools ssh 
