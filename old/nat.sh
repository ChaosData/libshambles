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
$IPT -A FORWARD -i eth0 -o eth1 -m state --state ESTABLISHED,RELATED -j ACCEPT

#allow outgoing connections from internal
$IPT -A INPUT -i eth1 -m state --state NEW -s 192.168.108.0/24 -j ACCEPT
$IPT -A FORWARD -i eth1 -o eth0 -s 192.168.108.0/24 -j ACCEPT

#nat
$IPT -t nat -A POSTROUTING -o eth0 ! -d 192.168.108.0/24 -j MASQUERADE

#DROP by default
$IPT -A INPUT -j DROP
$IPT -A FORWARD -j DROP

#enable routing in case it is disabled
echo 1 > /proc/sys/net/ipv4/ip_forward

