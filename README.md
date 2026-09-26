<p align="center">
  <a href="https://tunnl.gg"><img src="https://tunnl.gg/github-banner.png" alt="tunnl.gg: your localhost, public in one command" width="100%"></a>
</p>

# Tunnl.gg

A minimal SSH tunneling service. Expose your local apps to the internet with a single command.

```bash
ssh -t -R 80:localhost:8080 proxy.tunnl.gg
```

> **Note:** The `-t` flag is required to allocate a TTY, which allows the server to display your tunnel URL.

## Features

- Memorable subdomain per connection (e.g., `https://happy-tiger-a1b2c3d4.tunnl.gg`)
- QR code of the URL in the terminal, for opening the tunnel on a phone
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
| Requests per visitor | 25/s (burst 200) | Per visitor IP (IPv6 by /64), per tunnel; excess gets 429 |
| Requests per tunnel | 50/s (burst 400) | Across all visitors; excess gets 429 |
| Request body size | 128 MB | Max upload size |
| Response body size | 128 MB | Max response size |
| In-flight requests | 256 per visitor, 512 per tunnel | Concurrent proxied requests; excess gets 429 (visitor) or 503 (tunnel) |
| Request idle timeout | 2 minutes | Proxied requests are canceled after 2 minutes without data in either direction; long polls and streams can run longer while data flows |
| WebSocket transfer | 1 GB per direction | Max data per WebSocket connection |
| WebSocket idle timeout | 2 hours | WebSocket closed after inactivity |
| WebSockets per tunnel | 100 | Max concurrent WebSockets per tunnel |
| WebSockets per visitor | 20 | Max concurrent WebSockets per visitor IP across all tunnels |
| SSH handshake timeout | 30 seconds | Max time for SSH handshake to complete |
| Concurrent handshakes | 3 per IP, 100 total | In-progress SSH handshakes; excess connections are dropped |
| Unanswered channel opens | 32 per tunnel | Connections the SSH client hasn't accepted yet; further requests wait up to 10 seconds for one |
| Connections per minute | 10 | New SSH connections per IP |
| Inactivity timeout | 2 hours | Tunnel closes after 2 hours with no requests or open WebSockets |
| Max tunnel lifetime | 24 hours | Absolute tunnel lifetime limit |
| Block duration | 1 hour | Temporary IP block after abuse |
| Violations before block | 10 | SSH connection rate violations before IP block |

## Project Structure

```text
tunnl.gg/
├── cmd/tunnl/              # Application entry point
├── internal/
│   ├── clientip/           # Visitor IP resolution behind trusted proxies
│   │   └── clientip.go
│   ├── config/             # Configuration and constants
│   │   └── config.go
│   ├── server/             # Server implementation
│   │   ├── server.go       # Server struct, tunnel registry
│   │   ├── ssh.go          # SSH connection handling
│   │   ├── http.go         # HTTP/HTTPS handlers
│   │   ├── stats.go        # Stats tracking and endpoint
│   │   ├── abuse.go        # Abuse tracking and IP blocking
│   │   ├── connlimit.go    # Concurrent connection limits
│   │   └── deadlines.go    # Idle timeouts for proxied requests
│   ├── subdomain/          # Subdomain generation/validation
│   │   └── subdomain.go
│   └── tunnel/             # Tunnel, SSH channels, and rate limiter
│       ├── tunnel.go
│       ├── channel.go
│       ├── ratelimiter.go
│       └── requestlogger.go
├── .golangci.yml           # Linter configuration
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
mkdir -p data/certs data/hostkey

# Copy certificates
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem data/certs/
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem data/certs/

# The container runs as UID 65534: let it read the certificates and
# store the SSH host key it generates on first start
sudo chown -R 65534:65534 data/certs data/hostkey

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
# Requires Go 1.26.8+
git clone https://github.com/klipitkas/tunnl.gg.git
cd tunnl.gg

# Build optimized binary (~6MB)
make build-small

# Or build for all platforms
make build-all
```

### Systemd Service

Run the service as a dedicated unprivileged user. It only needs the
`CAP_NET_BIND_SERVICE` capability to bind ports 22, 80, and 443.

```bash
# Service user, binary (root-owned so the service can't replace it),
# and a certificate directory readable by the service
sudo useradd --system --no-create-home --shell /usr/sbin/nologin tunnl
sudo install -d -m 0755 /opt/tunnl
sudo install -m 0755 bin/tunnl /opt/tunnl/tunnl
sudo install -d -o root -g tunnl -m 0750 /etc/tunnl
```

Let's Encrypt keys are only readable by root, so copy them for the service
with a certbot deploy hook, which also runs after every renewal:

```bash
sudo tee /etc/letsencrypt/renewal-hooks/deploy/tunnl.sh > /dev/null <<'HOOK'
#!/bin/sh
set -e
LINEAGE="${RENEWED_LINEAGE:-/etc/letsencrypt/live/yourdomain.com}"
install -o root -g tunnl -m 0644 "$LINEAGE/fullchain.pem" /etc/tunnl/fullchain.pem
install -o root -g tunnl -m 0640 "$LINEAGE/privkey.pem" /etc/tunnl/privkey.pem
systemctl try-restart tunnl
HOOK
sudo chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/tunnl.sh
sudo /etc/letsencrypt/renewal-hooks/deploy/tunnl.sh
```

```bash
sudo nano /etc/systemd/system/tunnl.service
```

```ini
[Unit]
Description=Tunnl.gg SSH Tunnel Service
After=network.target

[Service]
Type=simple
User=tunnl
Group=tunnl
ExecStart=/opt/tunnl/tunnl
Restart=always
RestartSec=5

# Stores the SSH host key in /var/lib/tunnl
StateDirectory=tunnl
WorkingDirectory=/var/lib/tunnl

Environment=SSH_ADDR=:22
Environment=HTTP_ADDR=:80
Environment=HTTPS_ADDR=:443
Environment=STATS_ADDR=127.0.0.1:9090
Environment=HOST_KEY_PATH=/var/lib/tunnl/host_key
Environment=TLS_CERT=/etc/tunnl/fullchain.pem
Environment=TLS_KEY=/etc/tunnl/privkey.pem
Environment=DOMAIN=yourdomain.com
# Only when behind a proxy, see "Behind a Proxy"
#Environment=TRUSTED_PROXIES=cloudflare

# Bind privileged ports without running as root
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
```

```bash
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
| `TRUSTED_PROXIES` | unset | Proxies whose headers identify visitors: CIDRs/IPs (`X-Forwarded-For`) and/or `cloudflare` (`CF-Connecting-IP`). See [Behind a Proxy](#behind-a-proxy) |

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

### Behind a Proxy

Rate limits, WebSocket limits, and the `X-Forwarded-For` header sent to tunneled apps
all use the visitor's IP address. By default the server trusts no proxies and uses the
address of the TCP connection, which is right when it faces the internet directly
(including most on-prem setups).

When HTTPS traffic reaches the server through proxies, list them in `TRUSTED_PROXIES`
so the visitor's address is taken from their headers:

| Setup | `TRUSTED_PROXIES` |
|-------|-------------------|
| Directly on the internet, or on-prem with no proxy | unset |
| Behind Cloudflare | `cloudflare` |
| Behind your own reverse proxy or load balancer | its IPs or CIDRs, e.g. `10.0.0.0/8` |
| Your proxy behind Cloudflare | `cloudflare,10.0.0.0/8` |

`cloudflare` trusts `CF-Connecting-IP` only from Cloudflare's published ranges
([cloudflare.com/ips](https://www.cloudflare.com/ips/), built in). Other entries trust
`X-Forwarded-For`, read right to left past trusted proxies, so addresses a visitor adds
themselves are ignored. Headers from any other address are ignored, so only list proxies
you control, and firewall ports 80 and 443 so only those proxies can reach the server.

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
  "active_websockets": 4,
  "active_requests": 12,
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
| `make dev` | Run a local server on unprivileged ports (see [Local Development](#local-development)) |
| `make test` | Run tests |
| `make lint` | Run golangci-lint (v2) |
| `make vuln` | Check reachable code for known vulnerabilities |
| `make clean` | Remove build artifacts |

## Local Development

`make dev` runs a server on your machine with a self-signed certificate and
`DOMAIN=localhost`, so you can try changes before deploying. In another terminal,
start something on port 3000 and open a tunnel to it:

```bash
ssh -p 2200 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -R 80:localhost:3000 localhost
```

The session shows the tunnel URL, e.g. `https://happy-tiger-a1b2c3d4.localhost`.
Add the dev HTTPS port to reach it: `curl -k https://happy-tiger-a1b2c3d4.localhost:8443`
(`*.localhost` resolves to your machine in browsers and curl).

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
