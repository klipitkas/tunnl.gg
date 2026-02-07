# Tunnl.gg

A minimal SSH tunneling service. Expose your local apps to the internet with a single command.

```bash
ssh -t -R 80:localhost:8080 proxy.tunnl.gg
```

> **Note:** The `-t` flag is required to allocate a TTY, which allows the server to display your tunnel URL.

## Features

- Memorable subdomain per connection (e.g., `https://happy-tiger-a1b2c3d4.tunnl.gg`)
- Automatic SSL via Let's Encrypt
- WebSocket support
- Comprehensive rate limiting and abuse protection
- Phishing protection via interstitial warning page
- Built-in stats/metrics endpoint
- No authentication required
- Zero configuration for clients

### Limits & Protection

| Limit | Value | Description |
|-------|-------|-------------|
| Tunnels per IP | 3 | Max concurrent tunnels per IP address |
| Total tunnels | 1000 | Server-wide tunnel limit |
| Requests per tunnel | 10/s (burst 20) | Token bucket rate limiting |
| Request body size | 128 MB | Max upload size |
| Response body size | 128 MB | Max response size |
| WebSocket transfer | 1 GB per direction | Max data per WebSocket connection |
| WebSocket idle timeout | 2 hours | WebSocket closed after inactivity |
| SSH handshake timeout | 30 seconds | Max time for SSH handshake to complete |
| Connections per minute | 10 | New SSH connections per IP |
| Inactivity timeout | 2 hours | Tunnel closes after inactivity |
| Max tunnel lifetime | 24 hours | Absolute tunnel lifetime limit |
| Block duration | 1 hour | Temporary IP block after abuse |
| Violations before block | 10 | Rate limit violations before tunnel kill + IP block |

## Project Structure

```text
tunnl.gg/
├── cmd/tunnl/              # Application entry point
├── internal/
│   ├── config/             # Configuration and constants
│   │   └── config.go
│   ├── server/             # Server implementation
│   │   ├── server.go       # Server struct, tunnel registry
│   │   ├── ssh.go          # SSH connection handling
│   │   ├── http.go         # HTTP/HTTPS handlers
│   │   ├── stats.go        # Stats tracking and endpoint
│   │   └── abuse.go        # Abuse tracking and IP blocking
│   ├── subdomain/          # Subdomain generation/validation
│   │   └── subdomain.go
│   └── tunnel/             # Tunnel and rate limiter
│       ├── tunnel.go
│       └── ratelimiter.go
├── Dockerfile              # Multi-stage build (scratch image)
├── docker-compose.yml      # Production deployment
└── Makefile                # Build commands
```

## Quick Start with Docker

### Prerequisites

- Docker and Docker Compose
- A domain with DNS pointing to your server
- SSL certificates (see below)

### 1. DNS Configuration

```text
A    yourdomain.com      → YOUR_SERVER_IP
A    *.yourdomain.com    → YOUR_SERVER_IP
```

### 2. Obtain SSL Certificates

```bash
# Install certbot
sudo apt install certbot

# Get wildcard certificate (requires DNS challenge)
sudo certbot certonly --manual --preferred-challenges dns \
  -d yourdomain.com -d '*.yourdomain.com'

# Or use HTTP challenge for single domain first
sudo certbot certonly --standalone -d yourdomain.com
```

### 3. Deploy

```bash
# Clone the repository
git clone https://github.com/klipitkas/tunnl.gg.git
cd tunnl.gg

# Create data directories
mkdir -p data/certs

# Copy certificates
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem data/certs/
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem data/certs/
sudo chown -R $USER:$USER data/certs

# Start the service
docker compose up -d

# View logs
docker compose logs -f
```

### 4. Move Server SSH (Important!)

Your server's SSH likely uses port 22. Move it so tunnl can use it:

```bash
sudo nano /etc/ssh/sshd_config
# Change: Port 22 → Port 2222

sudo ufw allow 2222/tcp
sudo systemctl restart sshd
```

**Test the new port before closing your session:**

```bash
ssh -p 2222 user@your-server
```

## Manual Installation

### Build from Source

```bash
# Requires Go 1.24+
git clone https://github.com/klipitkas/tunnl.gg.git
cd tunnl.gg

# Build optimized binary (~6MB)
make build-small

# Or build for all platforms
make build-all
```

### Systemd Service

```bash
sudo nano /etc/systemd/system/tunnl.service
```

```ini
[Unit]
Description=Tunnl.gg SSH Tunnel Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/tunnl
ExecStart=/opt/tunnl/tunnl
Restart=always
RestartSec=5

Environment=SSH_ADDR=:22
Environment=HTTP_ADDR=:80
Environment=HTTPS_ADDR=:443
Environment=STATS_ADDR=127.0.0.1:9090
Environment=HOST_KEY_PATH=/opt/tunnl/host_key
Environment=TLS_CERT=/etc/letsencrypt/live/yourdomain.com/fullchain.pem
Environment=TLS_KEY=/etc/letsencrypt/live/yourdomain.com/privkey.pem
Environment=DOMAIN=yourdomain.com

NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/opt/tunnl

[Install]
WantedBy=multi-user.target
```

```bash
sudo mkdir -p /opt/tunnl
sudo cp bin/tunnl /opt/tunnl/
sudo chmod +x /opt/tunnl/tunnl
sudo systemctl daemon-reload
sudo systemctl enable --now tunnl
```

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `SSH_ADDR` | `:22` | SSH server listen address |
| `HTTP_ADDR` | `:80` | HTTP server listen address |
| `HTTPS_ADDR` | `:443` | HTTPS server listen address |
| `STATS_ADDR` | `127.0.0.1:9090` | Stats endpoint (localhost only) |
| `HOST_KEY_PATH` | `host_key` | Path to SSH host key |
| `TLS_CERT` | `/etc/letsencrypt/live/tunnl.gg/fullchain.pem` | TLS certificate path |
| `TLS_KEY` | `/etc/letsencrypt/live/tunnl.gg/privkey.pem` | TLS private key path |
| `DOMAIN` | `tunnl.gg` | Domain name for the service |

## Usage

### Basic

```bash
# Expose local port 8080
ssh -t -R 80:localhost:8080 proxy.tunnl.gg
```

### Expose a Different Host

```bash
ssh -t -R 80:192.168.1.100:3000 proxy.tunnl.gg
```

### Keep Connection Alive

```bash
ssh -t -R 80:localhost:8080 -o ServerAliveInterval=60 proxy.tunnl.gg
```

### Bypass Interstitial Warning

Browser requests show a phishing warning (cookie-based, lasts 1 day). To skip programmatically:

```bash
curl -H "tunnl-skip-browser-warning: 1" https://happy-tiger-a1b2c3d4.tunnl.gg
```

## Stats Endpoint

Query server statistics (localhost only):

```bash
# Basic stats
curl http://127.0.0.1:9090/

# Include active subdomains
curl "http://127.0.0.1:9090/?subdomains=true"
```

Response:

```json
{
  "active_tunnels": 3,
  "unique_ips": 2,
  "total_connections": 15,
  "total_requests": 1247,
  "blocked_ips": 1,
  "total_blocked": 5,
  "total_rate_limited": 23,
  "subdomains": ["happy-tiger-a1b2c3d4", "calm-eagle-e5f6a7b8", "swift-wolf-d9e0f1a2"]
}
```

## Makefile Commands

| Command | Description |
|---------|-------------|
| `make build` | Standard optimized build |
| `make build-small` | Maximum size optimization (~6MB) |
| `make build-tiny` | With UPX compression (if installed) |
| `make build-all` | Cross-compile for Linux/macOS |
| `make build-dev` | Fast build with debug symbols |
| `make test` | Run tests |
| `make clean` | Remove build artifacts |

## How It Works

```text
┌─────────────────────────────────────────────────────────────────┐
│                        TUNNL SERVER                             │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌───────────┐  ┌───────────┐ │
│  │ SSH :22     │  │ HTTP :80    │  │HTTPS :443 │  │Stats :9090│ │
│  │             │  │             │  │           │  │           │ │
│  │ Accepts -R  │  │ ACME + 301  │  │ TLS term  │  │ Metrics   │ │
│  │ connections │  │ redirect    │  │ Rev proxy │  │ (local)   │ │
│  └──────┬──────┘  └─────────────┘  └─────┬─────┘  └───────────┘ │
│         │                                │                      │
│         ▼                                ▼                      │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    Tunnel Registry                          ││
│  │              map[subdomain]*Tunnel                          ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
         │                                │
         ▼                                │
   ┌──────────┐     HTTPS request to      │
   │ SSH Conn │  ←─ happy-tiger-a1b2c3d4 ─────┘
   │ Client   │
   └────┬─────┘
        │
        ▼
   ┌──────────┐
   │ App:8080 │
   └──────────┘
```

1. Client runs `ssh -t -R 80:localhost:8080 proxy.tunnl.gg`
2. Server generates subdomain (e.g., `happy-tiger-a1b2c3d4`) and shows URL
3. Browser requests `https://happy-tiger-a1b2c3d4.tunnl.gg`
4. Server looks up tunnel, proxies request via SSH to client
5. Client forwards to `localhost:8080`

## Running Multiple Instances

You can run multiple instances on the same server using different ports:

```bash
# Instance 1 (production) - default ports
./tunnl

# Instance 2 (dev) - alternate ports
SSH_ADDR=:2223 HTTP_ADDR=:8080 HTTPS_ADDR=:8443 STATS_ADDR=127.0.0.1:9091 \
HOST_KEY_PATH=./host_key_dev ./tunnl
```

Connect to dev instance: `ssh -t -R 80:localhost:8080 proxy.tunnl.gg -p 2223`

## Troubleshooting

### Connection Refused

```bash
# Check service status
docker compose ps
# or
sudo systemctl status tunnl

# Check ports
sudo ss -tlnp | grep -E ':(22|80|443)'

# Check firewall
sudo ufw status
```

### Host Key Verification Failed

First-time clients must accept the host key:

```bash
ssh -t -R 80:localhost:8080 proxy.tunnl.gg
# Are you sure you want to continue connecting (yes/no)? yes
```

### No Output / Connection Hangs

The `-t` flag is **required**:

```bash
# Wrong
ssh -R 80:localhost:8080 proxy.tunnl.gg

# Correct
ssh -t -R 80:localhost:8080 proxy.tunnl.gg
```

### Certificate Issues

```bash
# Check certificate files
ls -la data/certs/

# Renew certificates
sudo certbot renew

# Copy renewed certs and restart
sudo cp /etc/letsencrypt/live/yourdomain.com/*.pem data/certs/
docker compose restart
```

## License

MIT
