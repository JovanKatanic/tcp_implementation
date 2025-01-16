#!/bin/bash
gcc -o inf state_machine.c infrastructure.c tcp.c -lpthread
ext=$?
if [[ $ext -ne 0 ]]; then
    exit $ext
fi

sudo setcap cap_net_admin=eip ./inf 

if ip link show tun0 > /dev/null 2>&1; then
    echo "Cleaning up existing tun0 interface..."
    sudo ip link delete tun0
fi

./inf &
pid=$!
sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set up dev tun0
trap "kill $pid" INT TERM
wait $pid