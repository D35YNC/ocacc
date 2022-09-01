#!/bin/sh

if pidof tcpdump | grep [0-9] > /dev/null
then
    killall tcpdump
    /usr/bin/python3 /opt/ocacc/ocacc.py cron -i SERVER_IP -p 443 -f '/opt/ocacc/dump.pcap'
fi

sleep 5
/usr/sbin/tcpdump -i eth0 port 443 -w /opt/ocacc/dump.pcap -X