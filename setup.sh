#!/bin/sh

set -eu

# Configuration constants
readonly SCRIPT_NAME="openvpn-setup"
readonly DEFAULT_DOMAIN="local.net"
readonly VPN_SUBNET="10.23.88.0/23" #10.23.88.0/23
readonly VPN_POOL_START="10.23.88.1"
readonly VPN_POOL_END="10.23.89.253"
readonly VPN_SERVER_IP="10.23.89.254" # server ip is the last usable ip in the subnet
readonly VPN_SERVER_HOSTNAME="openvpn-server"
readonly VPN_NETADDRESS="10.23.88.0"
readonly VPN_NETMASK="255.255.254.0"
readonly VPN_PORT="1194"
readonly DNS_SERVERS="1.1.1.1 8.8.8.8"

# Set/Get environment variables
MY_IP_ADDR="${OPENVPN_SERVER_IP:-$(get_public_ip)}"
ENABLE_DNS="${ENABLE_DNS:-false}"
STATIC_HOST_MAPPINGS="${STATIC_HOST_MAPPINGS:-none}"
DOMAIN="${DOMAIN:-$DEFAULT_DOMAIN}"
CLIENT_FILENAME="${CLIENT_FILENAME:-netlab-$(get_date)}"
DIR_NAME="${DIR_NAME:-netlab-$(get_date)}"
FULL_TUNNEL="${FULL_TUNNEL:-false}"

# Derived paths
PERSISTED_FOLDER_DIRECTORY="/data/$DIR_NAME"
OPENVPN_CONFIG_DIR="/etc/openvpn"
CLIENT_CONFIG_PATH="$PERSISTED_FOLDER_DIRECTORY/$CLIENT_FILENAME.ovpn"

# Logging functions
log_info() {
    echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') - $1" >&2
}

log_error() {
    echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - $1" >&2
}

log_fatal() {
    log_error "$1"
    exit 1
}

# Get current date in POSIX-compliant way
get_date() {
    date '+%Y-%m-%d'
}

# Environment variables with defaults
get_public_ip() {
    dig @ns1.google.com -t txt o-o.myaddr.l.google.com +short -4 | sed 's/"//g' 2>/dev/null || {
        echo "127.0.0.1"
    }
}

# Utility functions
get_default_interface() {
    ip route get 8.8.8.8 2>/dev/null | awk '{print $5; exit}' || {
        log_error "Could not determine default interface"
        echo "eth0"
    }
}

check_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        log_fatal "Required command '$1' not found"
    fi
}

wait_for_interface() {
    interface="$1"
    expected_ip="$2"
    max_attempts=30
    attempt=1

    log_info "Waiting for $interface to be ready with $expected_ip..."
    
    while [ $attempt -le $max_attempts ]; do
        if ip addr show "$interface" 2>/dev/null | grep -q "$expected_ip"; then
            log_info "$interface is ready with $expected_ip"
            return 0
        fi
        log_info "Attempt $attempt/$max_attempts: $interface not ready yet"
        sleep 2
        attempt=$((attempt + 1))
    done
    
    return 1
}

# Network configuration functions
enable_ip_forwarding() {
    log_info "Enabling IP forwarding"
    
    # Enable immediately
    echo 1 > /proc/sys/net/ipv4/ip_forward || log_fatal "Failed to enable IP forwarding"
    
    # Make persistent
    sysctl_file="/etc/sysctl.d/99-openvpn-forwarding.conf"
    echo "net.ipv4.ip_forward = 1" > "$sysctl_file"
    sysctl -p "$sysctl_file" > /dev/null 2>&1 || log_error "Failed to apply sysctl settings"
}

configure_firewall() {
    out_interface="$(get_default_interface)"
    
    log_info "Configuring firewall rules for interface: $out_interface"
    
    # Allow OpenVPN traffic
    iptables -A INPUT -p udp --dport "$VPN_PORT" -j ACCEPT || log_fatal "Failed to add INPUT rule"
    
    # NAT for VPN clients
    iptables -t nat -A POSTROUTING -s "$VPN_SUBNET" -o "$out_interface" -j MASQUERADE || log_fatal "Failed to add NAT rule"
    
    # Allow forwarding
    iptables -A FORWARD -i tun0 -o "$out_interface" -j ACCEPT || log_fatal "Failed to add FORWARD rule (tun0 -> $out_interface)"
    iptables -A FORWARD -i "$out_interface" -o tun0 -j ACCEPT || log_fatal "Failed to add FORWARD rule ($out_interface -> tun0)"
    
    log_info "Firewall rules configured successfully"
}

# Certificate management
generate_certificate_authority() {
    log_info "Generating Certificate Authority"
    
    openssl genrsa -out "$OPENVPN_CONFIG_DIR/ca.key" 4096 || log_fatal "Failed to generate CA key"
    
    # Create temporary config file for CA
    ca_config=$(mktemp)
    cat > "$ca_config" <<'EOF'
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
[req_distinguished_name]
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
EOF
    
    openssl req -new -x509 -key "$OPENVPN_CONFIG_DIR/ca.key" -out "$OPENVPN_CONFIG_DIR/ca.crt" \
        -days 3650 -subj "/CN=OpenVPN-CA" \
        -extensions v3_ca -config "$ca_config" || log_fatal "Failed to generate CA certificate"
    
    rm -f "$ca_config"
}

generate_server_certificate() {
    log_info "Generating server certificate"
    
    # Generate server key
    openssl genrsa -out "$OPENVPN_CONFIG_DIR/server.key" 4096 || log_fatal "Failed to generate server key"
    
    # Generate server CSR
    openssl req -new -key "$OPENVPN_CONFIG_DIR/server.key" -out "$OPENVPN_CONFIG_DIR/server.csr" \
        -subj "/CN=OpenVPN-Server" || log_fatal "Failed to generate server CSR"
    
    # Create temporary config file for server cert
    server_config=$(mktemp)
    cat > "$server_config" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:$MY_IP_ADDR
EOF
    
    # Sign server certificate
    openssl x509 -req -in "$OPENVPN_CONFIG_DIR/server.csr" -CA "$OPENVPN_CONFIG_DIR/ca.crt" \
        -CAkey "$OPENVPN_CONFIG_DIR/ca.key" -CAcreateserial \
        -out "$OPENVPN_CONFIG_DIR/server.crt" -days 3650 -sha256 \
        -extfile "$server_config" || log_fatal "Failed to sign server certificate"
    
    # Clean up
    rm -f "$OPENVPN_CONFIG_DIR/server.csr" "$server_config"
}

generate_client_certificate() {
    log_info "Generating client certificate"
    
    # Generate client key
    openssl genrsa -out "$OPENVPN_CONFIG_DIR/client.key" 4096 || log_fatal "Failed to generate client key"
    
    # Generate client CSR
    openssl req -new -key "$OPENVPN_CONFIG_DIR/client.key" -out "$OPENVPN_CONFIG_DIR/client.csr" \
        -subj "/CN=client" || log_fatal "Failed to generate client CSR"
    
    # Create temporary config file for client cert
    client_config=$(mktemp)
    cat > "$client_config" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
EOF
    
    # Sign client certificate
    openssl x509 -req -in "$OPENVPN_CONFIG_DIR/client.csr" -CA "$OPENVPN_CONFIG_DIR/ca.crt" \
        -CAkey "$OPENVPN_CONFIG_DIR/ca.key" -CAcreateserial \
        -out "$OPENVPN_CONFIG_DIR/client.crt" -days 3650 -sha256 \
        -extfile "$client_config" || log_fatal "Failed to sign client certificate"
    
    # Clean up
    rm -f "$OPENVPN_CONFIG_DIR/client.csr" "$client_config"
}

generate_diffie_hellman() {
    log_info "Generating Diffie-Hellman parameters (this may take a while...)"
    openssl dhparam -out "$OPENVPN_CONFIG_DIR/dh.pem" 2048 || log_fatal "Failed to generate DH parameters"
}

generate_tls_crypt_key() {
    log_info "Generating TLS-Crypt key"
    openvpn --genkey secret "$OPENVPN_CONFIG_DIR/tc.key" || log_fatal "Failed to generate TLS-Crypt key"
}

# Configuration generation
create_server_config() {
    log_info "Creating server configuration"
    
    config_file="$OPENVPN_CONFIG_DIR/openvpn.conf"
    
    cat > "$config_file" <<EOF
# OpenVPN Server Configuration
mode server
tls-server

# Allow multiple clients to use the same cert
duplicate-cn

# Network configuration
ifconfig $VPN_SERVER_IP $VPN_NETMASK
ifconfig-pool $VPN_POOL_START $VPN_POOL_END $VPN_NETMASK
topology subnet
route-gateway $VPN_SERVER_IP

# Subnet route
push "route $VPN_NETADDRESS $VPN_NETMASK"
push "route-gateway $VPN_SERVER_IP"

# Protocol and port
proto udp
port $VPN_PORT
dev tun

# Certificates and keys
ca $OPENVPN_CONFIG_DIR/ca.crt
cert $OPENVPN_CONFIG_DIR/server.crt
key $OPENVPN_CONFIG_DIR/server.key
dh $OPENVPN_CONFIG_DIR/dh.pem
tls-crypt $OPENVPN_CONFIG_DIR/tc.key

# Security
data-ciphers AES-256-GCM:AES-128-GCM
data-ciphers-fallback AES-256-CBC
user nobody
group nobody

# Connection settings
keepalive 10 120
persist-key
persist-tun

# Logging
status $OPENVPN_CONFIG_DIR/openvpn-status.log
log-append $OPENVPN_CONFIG_DIR/openvpn.log
verb 3

# Add conditional configurations to push to clients
push "topology subnet"
push "resolv-retry infinite"
push "data-ciphers AES-256-GCM:AES-128-GCM"
push "data-ciphers-fallback AES-256-CBC"
EOF

    # Add conditional configurations
    if [ "$FULL_TUNNEL" = "true" ]; then
        cat >> "$config_file" <<EOF

# Full tunnel configuration
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
EOF
    fi

    if [ "$ENABLE_DNS" = "true" ]; then
        cat >> "$config_file" <<EOF

# DNS configuration
push "dhcp-option DNS $VPN_SERVER_IP"
push "dhcp-option DOMAIN $DOMAIN"
EOF
    fi
}

create_client_config() {
    log_info "Creating client configuration"
    
    client_config="$PERSISTED_FOLDER_DIRECTORY/$CLIENT_FILENAME.ovpn"
    
    cat > "$client_config" <<EOF
# OpenVPN Client Configuration
client
dev tun
proto udp
remote $MY_IP_ADDR $VPN_PORT
nobind
remote-cert-tls server
ping 10
ping-restart 60
verb 3

<key>
$(cat "$OPENVPN_CONFIG_DIR/client.key")
</key>
<cert>
$(cat "$OPENVPN_CONFIG_DIR/client.crt")
</cert>
<ca>
$(cat "$OPENVPN_CONFIG_DIR/ca.crt")
</ca>
<tls-crypt>
$(cat "$OPENVPN_CONFIG_DIR/tc.key")
</tls-crypt>
EOF

    # Create Linux-specific config if DNS is enabled
    if [ "$ENABLE_DNS" = "true" ]; then
        linux_config="$PERSISTED_FOLDER_DIRECTORY/$CLIENT_FILENAME-LINUX.ovpn"
        cp "$client_config" "$linux_config"
        cat >> "$linux_config" <<EOF

# Linux-specific DNS configuration
script-security 2
setenv PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
up /etc/openvpn/update-systemd-resolved
down /etc/openvpn/update-systemd-resolved
down-pre
EOF
    fi
}

update_client_ip() {
    client_file="$CLIENT_CONFIG_PATH"
    
    if [ ! -f "$client_file" ]; then
        log_info "Client config not found, skipping IP update"
        return 0
    fi
    
    old_ip=$(awk '/^remote / { print $2; exit }' "$client_file")
    
    if [ -z "$old_ip" ]; then
        log_error "Could not find remote IP in client config"
        return 1
    fi
    
    if [ "$MY_IP_ADDR" != "$old_ip" ]; then
        log_info "Updating client config: $old_ip -> $MY_IP_ADDR"
        sed -i "s/^remote .*/remote $MY_IP_ADDR $VPN_PORT/" "$client_file"
    else
        log_info "Client config IP unchanged: $MY_IP_ADDR"
    fi
}

# DNS configuration
configure_dnsmasq() {
    log_info "Configuring dnsmasq"
    
    # Backup original config
    [ -f /etc/dnsmasq.conf ] && cp /etc/dnsmasq.conf /etc/dnsmasq.conf.backup
    
    cat > /etc/dnsmasq.conf <<EOF
# OpenVPN DNS Configuration
interface=tun0
no-dhcp-interface=tun0
listen-address=$VPN_SERVER_IP
domain=$DOMAIN
bind-interfaces
EOF

    # Add upstream DNS servers
    for dns in $DNS_SERVERS; do
        echo "server=$dns" >> /etc/dnsmasq.conf
    done
    
    # Add static host mappings
    if [ "$STATIC_HOST_MAPPINGS" != "none" ] && [ -n "$STATIC_HOST_MAPPINGS" ]; then
        log_info "Adding static host mappings"

        # Prepend the server's own mapping
        combined_mappings="${VPN_SERVER_IP} ${VPN_SERVER_HOSTNAME}.${DOMAIN};${STATIC_HOST_MAPPINGS}"
        # Use POSIX-compliant method to process mappings
        echo "$combined_mappings" | tr ';' '\n' | while IFS= read -r mapping; do
            if [ -n "$mapping" ]; then
                echo "$mapping" >> /etc/hosts
            fi
        done
    fi
}

start_dnsmasq() {
    if ! wait_for_interface "tun0" "$VPN_SERVER_IP"; then
        log_fatal "tun0 interface not ready, cannot start dnsmasq"
    fi
    
    log_info "Starting dnsmasq"
    dnsmasq --no-daemon &
    dnsmasq_pid=$!
    
    # Verify dnsmasq started successfully
    sleep 2
    if ! kill -0 "$dnsmasq_pid" 2>/dev/null; then
        log_fatal "dnsmasq failed to start"
    fi
    
    log_info "dnsmasq started successfully (PID: $dnsmasq_pid)"
}

# Setup functions
prepare_environment() {
    log_info "Preparing environment"
    
    # Check required commands
    check_command "openssl"
    check_command "openvpn"
    check_command "iptables"
    check_command "ip"
    
    # Create necessary directories
    mkdir -p "$PERSISTED_FOLDER_DIRECTORY" "$OPENVPN_CONFIG_DIR" /dev/net
    
    # Create TUN device if it doesn't exist
    [ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200
    
    # Set proper permissions
    chmod 700 "$OPENVPN_CONFIG_DIR"
    chmod 755 "$PERSISTED_FOLDER_DIRECTORY"
}

perform_initial_setup() {
    log_info "Performing initial OpenVPN setup"
    
    prepare_environment
    
    # Generate all certificates and keys
    generate_certificate_authority
    generate_server_certificate
    generate_client_certificate
    generate_tls_crypt_key
    generate_diffie_hellman
    
    # Create configurations
    create_server_config
    create_client_config
    
    # Backup configuration to persistent storage
    log_info "Backing up configuration to persistent storage"
    mkdir -p "$PERSISTED_FOLDER_DIRECTORY/config"
    cp -a "$OPENVPN_CONFIG_DIR/." "$PERSISTED_FOLDER_DIRECTORY/config/"
}

restore_configuration() {
    log_info "Restoring OpenVPN configuration from persistent storage"
    
    if [ ! -d "$PERSISTED_FOLDER_DIRECTORY/config" ]; then
        log_fatal "Persistent configuration directory not found"
    fi
    
    cp -a "$PERSISTED_FOLDER_DIRECTORY/config/." "$OPENVPN_CONFIG_DIR/"
    update_client_ip
}

start_openvpn_server() {
    log_info "Starting OpenVPN server"
    
    # Create log files if they don't exist
    touch "$OPENVPN_CONFIG_DIR/openvpn-status.log" "$OPENVPN_CONFIG_DIR/openvpn.log"
    
    # Start OpenVPN in background
    openvpn --config "$OPENVPN_CONFIG_DIR/openvpn.conf" &
    openvpn_pid=$!
    
    # Verify OpenVPN started successfully
    sleep 3
    if ! kill -0 "$openvpn_pid" 2>/dev/null; then
        log_fatal "OpenVPN failed to start"
    fi
    
    log_info "OpenVPN server started successfully (PID: $openvpn_pid)"
}

# Signal handling for graceful shutdown
cleanup() {
    log_info "Received shutdown signal, cleaning up..."
    exit 0
}

# Main execution
main() {
    log_info "Starting OpenVPN setup with IP: $MY_IP_ADDR"
    
    # Set up signal handlers
    trap cleanup TERM INT
    
    # Check if this is initial setup or restoration
    if [ ! -d "$PERSISTED_FOLDER_DIRECTORY/config" ]; then
        perform_initial_setup
    else
        restore_configuration
    fi
    
    # Configure system
    enable_ip_forwarding
    configure_firewall
    
    # Start OpenVPN
    start_openvpn_server
    
    # Configure DNS if enabled
    if [ "$ENABLE_DNS" = "true" ]; then
        configure_dnsmasq
        if [ "$STATIC_HOST_MAPPINGS" != "none" ]; then
            start_dnsmasq
        else
            log_info "DNS enabled but no static mappings configured"
        fi
    fi
    
    # Display important information
    log_info "Setup completed successfully!"
    log_info "Client configuration: $CLIENT_CONFIG_PATH"
    log_info "Server logs: $OPENVPN_CONFIG_DIR/openvpn.log"
    log_info "Status log: $OPENVPN_CONFIG_DIR/openvpn-status.log"
    
    # Follow logs
    tail -f "$OPENVPN_CONFIG_DIR/openvpn-status.log" "$OPENVPN_CONFIG_DIR/openvpn.log"
}

# Execute main function
main "$@"