#!/bin/sh

set -eu

log() {
    echo "[*] $1"
}

fatal() {
    echo "[!] $1" >&2
    exit 1
}

log "Reading environment variables"

MY_IP_ADDR=${OPENVPN_SERVER_IP:-$(dig @ns1.google.com -t txt o-o.myaddr.l.google.com +short -4 | sed 's/"//g')}
OPENVPN_CLIENT_FILENAME=${OPENVPN_CLIENT_FILENAME:-netlab-$(date +%F)}
PERSISTED_DIRECTORY_NAME=${PERSISTED_DIRECTORY_NAME:-netlab-$(date +%F)}

PERSISTED_FOLDER_DIRECTORY="/data/$PERSISTED_DIRECTORY_NAME"
OUT_IFACE=$(ip route get 8.8.8.8 | awk '{print $5; exit}')

mkdir -p /etc/openvpn

check_ip_changed() {
    local client_file="$PERSISTED_FOLDER_DIRECTORY/$OPENVPN_CLIENT_FILENAME.ovpn"
    if [ -f "$client_file" ]; then
        OLD_IP=$(awk '/^remote / { print $2 }' "$client_file")
        if [ "$MY_IP_ADDR" != "$OLD_IP" ]; then
            log "IP address changed: $OLD_IP -> $MY_IP_ADDR"
            sed -i "s/^remote .*/remote $MY_IP_ADDR 1194/" "$client_file"
        else
            log "IP address unchanged"
        fi
    fi
}

apply_iptables_rules() {
    iptables -t nat -C POSTROUTING -s 10.0.0.0/24 -o "$OUT_IFACE" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o "$OUT_IFACE" -j MASQUERADE

    # Uncomment these if you need inter-interface forwarding
    #iptables -C FORWARD -i tun0 -o "$OUT_IFACE" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i tun0 -o "$OUT_IFACE" -j ACCEPT
    #iptables -C FORWARD -i "$OUT_IFACE" -o tun0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$OUT_IFACE" -o tun0 -j ACCEPT
}

enable_ip_forwarding() {
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/ipv4.conf
    sysctl -p /etc/sysctl.d/ipv4.conf
}

first_time_setup() {
    log "First-time setup: generating keys and configs"

    mkdir -p "$PERSISTED_FOLDER_DIRECTORY"

    [ -d /dev/net ] || mkdir -p /dev/net
    [ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200

    openssl dhparam -out /etc/openvpn/dh.pem 2048
    openssl genrsa -out /etc/openvpn/key.pem 2048
    chmod 600 /etc/openvpn/key.pem
    openssl req -new -key /etc/openvpn/key.pem -out /etc/openvpn/csr.pem -subj "/CN=OpenVPN/"
    openssl x509 -req -in /etc/openvpn/csr.pem -out /etc/openvpn/cert.pem -signkey /etc/openvpn/key.pem -days 24855

    cat <<EOF > "/root/client.ovpn"
data-ciphers AES-256-GCM:AES-128-GCM
data-ciphers-fallback AES-256-CBC
client
nobind
comp-lzo
dev tun
proto udp
ping 10
ping-restart 60
<key>
$(cat /etc/openvpn/key.pem)
</key>
<cert>
$(cat /etc/openvpn/cert.pem)
</cert>
<ca>
$(cat /etc/openvpn/cert.pem)
</ca>
<connection>
remote $MY_IP_ADDR 1194
</connection>
EOF

    cp /root/client.ovpn "$PERSISTED_FOLDER_DIRECTORY/$OPENVPN_CLIENT_FILENAME.ovpn"

    cat <<EOF > /etc/openvpn/openvpn.conf
server 10.0.0.0 255.255.255.0
verb 3
comp-lzo
key /etc/openvpn/key.pem
ca /etc/openvpn/cert.pem
cert /etc/openvpn/cert.pem
dh /etc/openvpn/dh.pem
topology subnet
keepalive 10 120
ifconfig-pool-persist ipp.txt
push "route 10.0.0.0 255.255.255.0"
persist-key
persist-tun
proto udp
port 1194
user nobody
group nobody
dev tun
data-ciphers AES-256-GCM:AES-128-GCM
data-ciphers-fallback AES-256-CBC
status /var/log/openvpn-status.log
log-append /var/log/openvpn.log
EOF

    mkdir -p "$PERSISTED_FOLDER_DIRECTORY/config"
    cp -a /etc/openvpn/. "$PERSISTED_FOLDER_DIRECTORY/config"
}

start_openvpn() {
    log "Starting OpenVPN"
    exec openvpn --config /etc/openvpn/openvpn.conf
}

# ========== Main Logic ==========
if [ ! -d "$PERSISTED_FOLDER_DIRECTORY" ]; then
    first_time_setup
else
    log "OpenVPN config found, restoring"
    cp -a "$PERSISTED_FOLDER_DIRECTORY/config/." /etc/openvpn/
    check_ip_changed
fi

enable_ip_forwarding
apply_iptables_rules

log "VPN client config is saved at $PERSISTED_FOLDER_DIRECTORY/$OPENVPN_CLIENT_FILENAME.ovpn"
log "Check logs: /var/log/openvpn-status.log and /var/log/openvpn.log"

start_openvpn
