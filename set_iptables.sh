#/bin/bash
sudo iptables -A FORWARD -i enp0s3 -o enp0s8 -j ACCEPT
sudo iptables -A FORWARD -i enp0s8 -o enp0s3 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -t nat -A POSTROUTING -o enp0s8 -j MASQUERADE

