#!/bin/bash
sudo ip link add upfedge0 type veth peer name upfedge1 2>/dev/null || true
sudo ip link set upfedge0 up
sudo ip link set upfedge1 up
ip addr show lo | grep "127.0.0.2" > /dev/null || sudo ip addr add 127.0.0.2/8 dev lo
echo "네트워크 준비 완료"
