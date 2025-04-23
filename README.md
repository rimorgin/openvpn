# 🛡️ OpenVPN Docker Server (Split Tunneling) with Dynamic Config

This project sets up an OpenVPN server inside a Docker container using Alpine Linux. It supports **split tunneling**, **dynamic public IP detection**, and **persistent configuration** storage using mounted volumes.

# 🚀 Features
✨ First-run automatic PKI (TLS cert, key, dhparam) generation

📄 Generates a reusable OpenVPN .ovpn client file

🔁 Automatically updates client file if server IP changes

🔀 Enables IP forwarding and sets up NAT for VPN subnet

🔒 Split tunneling by default: only 10.0.0.0/24 is routed through the VPN


| Variable                | Description                                         | Default               |
|-------------------------|-----------------------------------------------------|-----------------------|
| `OPENVPN_SERVER_IP`     | Public IP of this server (fallbacks to auto-detected IP) | Auto via `dig`        |
| `OPENVPN_CLIENT_FILENAME` | Name of the generated `.ovpn` config file           | `netlab-YYYY-MM-DD`   |
| `PERSISTED_DIRECTORY_NAME` | Subfolder under `/data/` to store generated keys/configs | `netlab-YYYY-MM-DD`   |

# 📂 Directory Structure
Mounted volume /data will contain:

data/
└── netlab-YYYY-MM-DD/
    ├── netlab-YYYY-MM-DD.ovpn      ← Client config
    └── config/                     ← Server config backup

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
      - SYS_MODULE
    privileged: true
    ports:
      - "1194:1194/udp"
    environment:
      - OPENVPN_SERVER_IP=10.15.20.34 # default to public ip address
      # Optional: - OPENVPN_CLIENT_FILENAME=(defaults to netlab-datetoday)
      # Optional: - PERSISTED_DIRECTORY_NAME=(defaults to netlab-datetod
    devices:
      - /dev/net/tun
    volumes:
      - ./data:/data
```

```
docker-compose up -d
```

Grab your OpenVPN client file from:
./data/netlab-YYYY-MM-DD/netlab-YYYY-MM-DD.ovpn
