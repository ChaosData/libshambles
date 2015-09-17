#!/bin/sh

IPT="iptables"

$IPT -F
$IPT -X
$IPT -t nat -F
$IPT -t nat -X
$IPT -t mangle -F
$IPT -t mangle -X
$IPT -P INPUT ACCEPT
$IPT -P FORWARD ACCEPT
$IPT -P OUTPUT ACCEPT

$IPT -P INPUT DROP
$IPT -A INPUT -i lo -j ACCEPT

#allow established connections in
$IPT -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A FORWARD -i eth0 -o eth2 -m state --state ESTABLISHED,RELATED -j ACCEPT

#allow outgoing connections from internal (but not to 10.13.0.0/16)
$IPT -A INPUT -i eth2 -m state --state NEW -s 192.168.5.0/24 -j ACCEPT
$IPT -A FORWARD -i eth2 -o eth0 -d 10.13.0.0/16 -j DROP
$IPT -A FORWARD -i eth2 -o eth0 -s 192.168.5.0/24 -j ACCEPT

#nat
$IPT -t nat -A POSTROUTING -o eth0 ! -d 192.168.5.0/24 -j MASQUERADE

#DROP by default
$IPT -A INPUT -j REJECT
$IPT -A FORWARD -j DROP

#enable routing in case it is disabled
echo 1 > /proc/sys/net/ipv4/ip_forward

