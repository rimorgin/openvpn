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

MY_IP_ADDR=${OPENVPN_SERVER_IP:-$(dig @ns1.google.com -t txt o-o.myaddr.l.google.com +short -4 | sed 's/\"//g')}
OPENVPN_CLIENT_FILENAME=${OPENVPN_CLIENT_FILENAME:-netlab-$(date +%F)}
PERSISTED_DIRECTORY_NAME=${PERSISTED_DIRECTORY_NAME:-netlab-$(date +%F)}

PERSISTED_FOLDER_DIRECTORY="/data/$PERSISTED_DIRECTORY_NAME"
OUT_IFACE=$(ip route get 8.8.8.8 | awk '{print $5; exit}')

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
    iptables -t nat -A POSTROUTING -s 10.0.0.0/23 -o "$OUT_IFACE" -j MASQUERADE
    iptables -A FORWARD -i tun0 -o "$OUT_IFACE" -j ACCEPT
    iptables -A FORWARD -i "$OUT_IFACE" -o tun0 -j ACCEPT
}

enable_ip_forwarding() {
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/ipv4.conf
    sysctl -p /etc/sysctl.d/ipv4.conf
}

first_time_setup() {
    log "First-time setup: generating CA, server, and client keys and certs"

    mkdir -p "$PERSISTED_FOLDER_DIRECTORY"
    mkdir -p /etc/openvpn
    mkdir -p /dev/net
    [ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200

    # === Generate CA ===
    openssl genrsa -out /etc/openvpn/ca.key 4096
    openssl req -new -x509 -key /etc/openvpn/ca.key -out /etc/openvpn/ca.crt \
        -days 3650 -subj "/CN=OpenVPN-CA" \
        -extensions v3_ca -config <(cat <<-EOF
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
[ req_distinguished_name ]
[ v3_ca ]
basicConstraints = CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
EOF
)

    # === Generate Server Key and CSR ===
    openssl genrsa -out /etc/openvpn/server.key 4096
    openssl req -new -key /etc/openvpn/server.key -out /etc/openvpn/server.csr \
        -subj "/CN=OpenVPN-Server"

    # Sign Server Cert with Extensions
    openssl x509 -req -in /etc/openvpn/server.csr -CA /etc/openvpn/ca.crt \
        -CAkey /etc/openvpn/ca.key -CAcreateserial \
        -out /etc/openvpn/server.crt -days 3650 -sha256 \
        -extfile <(cat <<-EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:$MY_IP_ADDR
EOF
)

    # === Generate Client Key and CSR ===
    openssl genrsa -out /etc/openvpn/client.key 4096
    openssl req -new -key /etc/openvpn/client.key -out /etc/openvpn/client.csr \
        -subj "/CN=client"

    # Sign Client Cert with Extensions
    openssl x509 -req -in /etc/openvpn/client.csr -CA /etc/openvpn/ca.crt \
        -CAkey /etc/openvpn/ca.key -CAcreateserial \
        -out /etc/openvpn/client.crt -days 3650 -sha256 \
        -extfile <(cat <<-EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EOF
)

    # Generate tls-crypt key
    openvpn --genkey secret /etc/openvpn/tc.key

    # Build client config
    cat <<EOF > "/root/client.ovpn"
client
dev tun
proto udp
remote $MY_IP_ADDR 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
ping 10
ping-restart 60
verb 3
data-ciphers AES-256-GCM:AES-128-GCM
data-ciphers-fallback AES-256-CBC
<key>
$(cat /etc/openvpn/client.key)
</key>
<cert>
$(cat /etc/openvpn/client.crt)
</cert>
<ca>
$(cat /etc/openvpn/ca.crt)
</ca>
<tls-crypt>
$(cat /etc/openvpn/tc.key)
</tls-crypt>
EOF

    cp /root/client.ovpn "$PERSISTED_FOLDER_DIRECTORY/$OPENVPN_CLIENT_FILENAME.ovpn"

    # Create server config
    cat <<EOF > /etc/openvpn/openvpn.conf
server 10.0.0.0 255.255.254.0
verb 3
duplicate-cn
key /etc/openvpn/server.key
cert /etc/openvpn/server.crt
ca /etc/openvpn/ca.crt
dh /etc/openvpn/dh.pem
topology subnet
keepalive 10 120
tls-crypt /etc/openvpn/tc.key
persist-key
persist-tun
proto udp
port 1194
user nobody
group nobody
dev tun
data-ciphers AES-256-GCM:AES-128-GCM
data-ciphers-fallback AES-256-CBC
status /etc/openvpn/openvpn-status.log
log-append /etc/openvpn/openvpn.log
EOF

# Add full tunnel settings conditionally
if [ "${FULL_TUNNEL:-false}" = "true" ]; then
    cat <<EOT >> /etc/openvpn/openvpn.conf
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
EOT
fi

    openssl dhparam -out /etc/openvpn/dh.pem 2048

    cp -a /etc/openvpn/. "$PERSISTED_FOLDER_DIRECTORY/config"
}


start_openvpn() {
    log "Starting OpenVPN"
    touch /etc/openvpn/openvpn-status.log /etc/openvpn/openvpn.log
    openvpn --config /etc/openvpn/openvpn.conf &
    log "Started OpenVPN"
    tail -f /etc/openvpn/openvpn-status.log /etc/openvpn/openvpn.log
    wait
}

# ========== Main Logic ==========
if [ ! -d "$PERSISTED_FOLDER_DIRECTORY/config" ]; then  
    first_time_setup
else
    log "OpenVPN config found, restoring"
    cp -a "$PERSISTED_FOLDER_DIRECTORY/config/." /etc/openvpn/
    check_ip_changed
fi

enable_ip_forwarding
apply_iptables_rules

log "VPN client config is saved at $PERSISTED_FOLDER_DIRECTORY/$OPENVPN_CLIENT_FILENAME.ovpn"
log "Check logs: /etc/openvpn/openvpn-status.log and /etc/openvpn/openvpn.log"

start_openvpn
