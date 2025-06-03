# 🛡️ OpenVPN Docker Server (Full/Split Tunneling) with Dynamic Config

This project sets up an OpenVPN server inside a Docker container using Alpine Linux. It supports **full/split tunneling**, **dynamic public IP detection**, and **persistent configuration** storage using mounted volumes.

# 🚀 Features
### Core Functionality

🔐 Automated PKI Management: First-run automatic generation of TLS certificates, keys, and DH parameters

📱 Client Configuration: Generates ready-to-use .ovpn client files with embedded certificates

🔄 Dynamic IP Detection: Automatically detects and updates public IP address

💾 Persistent Storage: Configuration and certificates stored in mounted volumes

🌐 Network Routing: Configures IP forwarding and NAT for VPN subnet

### Tunneling Options

Split Tunneling (Default): Routes only VPN subnet traffic (10.0.0.0/23) through VPN

Full Tunneling (Optional): Routes all client traffic through VPN server

DNS Integration: Optional DNS server with custom domain support

Static Host Mapping: Custom hostname resolution for VPN clients


| Variable                | Description                                         | Default               |
|-------------------------|-----------------------------------------------------|-----------------------|
| `FULL_TUNNEL` | Enable full tunnel (fallbacks to false and split-tunnel) | `false`   |
| `OPENVPN_SERVER_IP`     | Public IP of this server (fallbacks to auto-detected IP) | Auto via `dig`        |
| `OPENVPN_CLIENT_FILENAME` | Name of the generated `.ovpn` config file           | `netlab-YYYY-MM-DD`   |
| `PERSISTED_DIRECTORY_NAME` | Subfolder under `/data/` to store generated keys/configs | `netlab-YYYY-MM-DD`   |
| `ENABLE_DNS` | Enable DNS server for VPN clients | `false` |
| `DOMAIN` | Custom domain for DNS resolution | `local.net `| 
| `STATIC_HOST_MAPPINGS` | Static hostname mappings | none |

# 📂 Directory Structure
Mounted volume /data will contain:
```plaintext
data/
└── netlab-YYYY-MM-DD/
  ├── netlab-YYYY-MM-DD.ovpn          ← Client config
  ├── netlab-YYYY-MM-DD-LINUX.ovpn    ← Linux/Unix Client config
  └── config/                         ← Server config backup # You may not be able to see contents of this folder as it requires root privilege
```

# 🧪 Usage
Clone this repo and build/start with Docker Compose:

## 📦 Docker Setup

Your `docker-compose.yml` should include something like this:

```yaml
services:
  openvpn:
    image: rimorgin/openvpn
    container_name: openvpn
    restart: unless-stopped
    cap_add:
      - NET_ADMIN
      - MKNOD
    privileged: true
    ports:
      - "1194:1194/udp"
    environment:
      - FULL_TUNNEL=true # Defaults to false, hence split tunnelling will be used
      - OPENVPN_SERVER_IP=10.15.20.34 # Defaults to public IP address if not set
      # Optional:
      - OPENVPN_CLIENT_FILENAME=custom-client-name # Defaults to netlab-YYYY-MM-DD
      - PERSISTED_DIRECTORY_NAME=custom-directory-name # Defaults to netlab-YYYY-MM-DD
      - ENABLE_DNS=true # Defaults to false
      - DOMAIN=local
      - STATIC_HOST_MAPPINGS=10.0.1.100 server.local;10.0.1.101 db.local # each entry must be separated by semi colon ; 
    devices:
      - /dev/net/tun:/dev/net/tun
    volumes:
      - ./data:/data
    healthcheck:
      test: ["CMD", "pgrep", "openvpn"]
      interval: 10s
      timeout: 5s
      retries: 5
```

```
docker-compose up -d
```

Grab your OpenVPN client file from:
./data/netlab-YYYY-MM-DD/netlab-YYYY-MM-DD.ovpn
