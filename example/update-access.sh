#!/usr/bin/env bash

LISTS=( mail forum )

user="$1"; shift
ip_addr="$1"; shift
gw_ip=10.8.0.1

echo "ifconfig-push $ip_addr $gw_ip" > /etc/openvpn/ccd/$user

for list in "${LISTS[@]}"; do
    /usr/sbin/ipset -! create $list hash:ip
    /usr/sbin/ipset -! del $list $ip_addr
done

for list in "$@"; do
    /usr/sbin/ipset -! add $list $ip_addr
done
