#!/bin/bash
#gcc -o tun_setup main.c -lnet
gcc -o inf state_machine.c -lpthread
ext=$?
if [[ $ext -ne 0 ]]; then
    exit $ext
fi

sudo setcap cap_net_admin=eip ./inf #./tun_setup

if ip link show tun0 > /dev/null 2>&1; then
    echo "Cleaning up existing tun0 interface..."
    sudo ip link delete tun0
fi

./inf & #./tun_setup &
pid=$!
sudo ip addr add 192.168.0.1/24 dev tun0
sudo ip link set up dev tun0
trap "kill $pid" INT TERM
wait $pid