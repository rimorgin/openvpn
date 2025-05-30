# 🛡️ OpenVPN Docker Server (Full/Split Tunneling) with Dynamic Config

This project sets up an OpenVPN server inside a Docker container using Alpine Linux. It supports **full/split tunneling**, **dynamic public IP detection**, and **persistent configuration** storage using mounted volumes.

# 🚀 Features
✨ First-run automatic PKI (TLS cert, key, dhparam) generation

📄 Generates a reusable OpenVPN .ovpn client file

🔀 Enables IP forwarding and sets up NAT for VPN subnet

🔒 Split tunneling by default (Full tunnel can be enabled and optional): only 10.0.0.0/24 is routed through the VPN


| Variable                | Description                                         | Default               |
|-------------------------|-----------------------------------------------------|-----------------------|
| `FULL_TUNNEL` | Enable full tunnel (fallbacks to false and split-tunnel) | `false`   |
| `OPENVPN_SERVER_IP`     | Public IP of this server (fallbacks to auto-detected IP) | Auto via `dig`        |
| `OPENVPN_CLIENT_FILENAME` | Name of the generated `.ovpn` config file           | `netlab-YYYY-MM-DD`   |
| `PERSISTED_DIRECTORY_NAME` | Subfolder under `/data/` to store generated keys/configs | `netlab-YYYY-MM-DD`   |

# 📂 Directory Structure
Mounted volume /data will contain:
```plaintext
data/
└── netlab-YYYY-MM-DD/
  ├── netlab-YYYY-MM-DD.ovpn      ← Client config
  └── config/                     ← Server config backup
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
