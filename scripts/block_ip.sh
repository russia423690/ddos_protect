#!/bin/bash

IP=$1
DURATION=$2

if [ -z "$IP" ]; then
    echo "Error: IP address required"
    echo "Usage: $0 <ip_address> <duration_in_seconds>"
    exit 1
fi

if [ -z "$DURATION" ]; then
    DURATION=3600
fi

if ! command -v iptables &> /dev/null; then
    echo "Error: iptables not found. Cannot block IP."
    exit 1
fi

sudo iptables -A INPUT -s $IP -j DROP

echo "$(date): Blocked IP $IP for $DURATION seconds" >> /tmp/ip_blocks.log

(
    sleep $DURATION
    sudo iptables -D INPUT -s $IP -j DROP
    echo "$(date): Unblocked IP $IP after $DURATION seconds" >> /tmp/ip_blocks.log
) &

echo "Successfully blocked $IP for $DURATION seconds"