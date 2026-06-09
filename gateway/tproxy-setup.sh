#!/bin/bash
# TProxy: traffic dari LAN eth2 → sing-box :7893
# Dipanggil oleh systemd sing-box.service (ExecStartPost / ExecStopPost)

TPROXY_PORT=7893
TPROXY_MARK=0x01
LAN_IF=eth2

flush() {
    iptables -t mangle -D PREROUTING -i $LAN_IF -j SING_BOX 2>/dev/null
    iptables -t mangle -F SING_BOX 2>/dev/null
    iptables -t mangle -X SING_BOX 2>/dev/null
    ip rule del fwmark $TPROXY_MARK table 100 2>/dev/null
    ip route del local default dev lo table 100 2>/dev/null
}

if [ "$1" = "stop" ]; then
    flush
    echo "TProxy rules removed"
    exit 0
fi

flush

ip rule add fwmark $TPROXY_MARK table 100
ip route add local default dev lo table 100

iptables -t mangle -N SING_BOX
iptables -t mangle -A SING_BOX -d 127.0.0.0/8 -j RETURN
iptables -t mangle -A SING_BOX -d 192.168.0.0/16 -j RETURN
iptables -t mangle -A SING_BOX -d 10.0.0.0/8 -j RETURN
iptables -t mangle -A SING_BOX -d 172.16.0.0/12 -j RETURN
iptables -t mangle -A SING_BOX -d 100.64.0.0/10 -j RETURN
iptables -t mangle -A SING_BOX -p tcp -j TPROXY --tproxy-mark $TPROXY_MARK --on-port $TPROXY_PORT
iptables -t mangle -A SING_BOX -p udp -j TPROXY --tproxy-mark $TPROXY_MARK --on-port $TPROXY_PORT
iptables -t mangle -A PREROUTING -i $LAN_IF -j SING_BOX

echo "TProxy rules applied"
