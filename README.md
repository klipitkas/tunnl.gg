<p align="center">
  <a href="https://tunnl.gg"><img src="https://tunnl.gg/github-banner.png" alt="tunnl.gg: your localhost, public in one command" width="100%"></a>
</p>

<p align="center">
  <a href="https://github.com/klipitkas/tunnl.gg/actions/workflows/ci.yml"><img src="https://github.com/klipitkas/tunnl.gg/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT license"></a>
</p>

# tunnl.gg

Expose a local web server to the internet with one SSH command. Nothing to install, no
account: you get a public HTTPS URL, and with `stable@` the same URL every time.

```bash
ssh -t -R 80:localhost:8080 proxy.tunnl.gg
```

This repository is the open-source (MIT) server behind [tunnl.gg](https://tunnl.gg). Use
the hosted service for free, or run your own.

**[Website](https://tunnl.gg)** · **[Docs](https://tunnl.gg/docs)** · **[Guides](https://tunnl.gg/guides)**

## Contents

- **Using tunnl.gg**
  - [Features](#features)
  - [Quick start](#quick-start)
  - [Keep the same URL](#keep-the-same-url)
  - [Options](#options)
  - [JSON output for scripts and agents](#json-output-for-scripts-and-agents)
  - [Recipes](#recipes)
  - [Limits and protection](#limits-and-protection)
- **Running your own server**
  - [How it works](#how-it-works)
  - [Before you start](#before-you-start)
  - [Install with Docker](#install-with-docker)
  - [Install with systemd](#install-with-systemd)
  - [Configuration](#configuration)
  - [Behind a proxy](#behind-a-proxy)
  - [Stats endpoint](#stats-endpoint)
  - [Troubleshooting](#troubleshooting)
- **Contributing**
  - [Local development](#local-development)
  - [Make commands](#make-commands)
  - [Project structure](#project-structure)
- [License](#license)

# Using tunnl.gg

## Features

- **One command, nothing to install:** uses the SSH client already on macOS, Linux and
  Windows 10+. No account, no auth token.
- **HTTPS and WebSockets** on a subdomain like `https://happy-tiger-a1b2c3d4.tunnl.gg`.
- **Stable URLs:** connect as `stable@` and your SSH key gets the same URL every time.
- **A live view in your terminal:** the URL, a QR code for phones, and a colored log of
  every request (path, status, size, timing, visitor), with plain-words explanations when
  one fails.
- **Options in the command:** Host header rewrite for dev servers, passwords, IP
  allowlists, CORS, and JSON output for scripts and AI agents.
- **Safe by default:** rate limits, abuse protection, a phishing warning page for
  browsers, and tunnels kept out of search engines.

## Quick start

```bash
# Expose the app on port 8080
ssh -t -R 80:localhost:8080 proxy.tunnl.gg
```

tunnl prints the public URL and a QR code, then logs requests as they arrive. Press
Ctrl+C to stop. The `-t` flag gives the session a terminal, which the server needs to show
the URL (for scripts, see [JSON output](#json-output-for-scripts-and-agents)).

## Keep the same URL

Each connection gets a new random URL. Connect as `stable` instead, and the URL is tied to
your SSH key and stays the same every time you reconnect:

```bash
ssh -t -R 80:localhost:8080 stable@proxy.tunnl.gg
```

- Any SSH key works; there's nothing to register. Without one, `stable@` is refused:
  create one with `ssh-keygen -t ed25519`.
- Each key has one live tunnel. Reconnecting with the same key (say, after your laptop
  slept) replaces the old connection, so two machines need two keys.
- The URL can't be worked out from your public key, but it changes if the server's host
  key changes.

## Options

Add options after the host, as `name=value`:

```bash
ssh -t -R 80:localhost:5173 proxy.tunnl.gg host=localhost auth=me:secret allow=203.0.113.7
```

| Option | What it does |
|--------|--------------|
| `host=localhost:3000` | Sends this `Host` header to your app instead of the public one. Fixes "Blocked request" from Vite, Django's `ALLOWED_HOSTS`, Rails and webpack-dev-server without changing their config. `X-Forwarded-Host` still carries the public host. |
| `auth=user:password` | Visitors must sign in with HTTP basic authentication. The password isn't passed on to your app. Each visitor gets 10 wrong passwords, then one every 10 seconds. |
| `allow=203.0.113.7,198.51.100.0/24` | Only visitors from these IPs or networks get through; others get 403. Repeat to add more. |
| `cors=https://app.example.com` | Lets pages on these sites call the tunnel from a browser, with cookies. tunnl answers CORS preflights, even on a password-protected tunnel, and adds the headers unless the app sets its own. `cors=*` allows any site, without cookies. Repeat to add more. |
| `output=json` | Prints JSON lines instead of the banner and request table. See [JSON output](#json-output-for-scripts-and-agents). |

`ssh ... proxy.tunnl.gg help` lists them. An invalid option ends the session with an error.
Options are visible to the server, and `auth=` ends up in your shell history like any
command. A server can restrict which options anonymous clients may use
(`Server.SetFreeLimits`; all are allowed by default). `output=` only changes what the
client sees, so every client may use it.

## JSON output for scripts and agents

With `output=json`, the session prints one JSON object per line instead of the banner, QR
code and table. Scripts, CI jobs and AI coding agents (Claude Code, Cursor, Codex) can read
the URL and watch requests without parsing terminal output. It works on every tunnel.

Run it in the background with `-n -T` (no input, no terminal) and read the URL from the
first line:

```bash
ssh -n -T -o ServerAliveInterval=30 -R 80:localhost:3000 stable@proxy.tunnl.gg output=json > tunnel.jsonl &
until grep -q '"event":"tunnel"' tunnel.jsonl 2>/dev/null; do sleep 1; done
head -1 tunnel.jsonl | jq -r .url
```

The first line describes the tunnel; then come one line per request, and notices such as
the warning before a time limit or the summary when tunnl closes the tunnel:

```json
{"event":"tunnel","url":"https://brave-fox-7c41e09b.tunnl.gg","subdomain":"brave-fox-7c41e09b","stable":true,"idle_timeout_seconds":7200,"max_lifetime_seconds":86400}
{"event":"request","time":"2026-10-09T08:14:03Z","method":"POST","path":"/webhooks/stripe","status":200,"bytes":2,"duration_ms":41,"visitor":"54.187.174.169"}
{"event":"notice","message":"Stopped. 1 request, 2 B served."}
```

| Field | Meaning |
|-------|---------|
| `event` | `tunnel` (first line), `request`, or `notice` |
| `url`, `subdomain` | Where the tunnel is reachable |
| `stable` | Whether the URL comes back on every reconnect (`stable@`, or an account's subdomain) |
| `idle_timeout_seconds`, `max_lifetime_seconds` | When the server closes the tunnel; `0` means never |
| `options` | Options in effect, like `host` or `auth` |
| `warning` | Set when the server ignored part of the request, like a subdomain name without an account |
| `status`, `bytes`, `duration_ms` | The app's response; left out when there was none |
| `from_tunnl` | `true` when tunnl answered the request itself (rate limit, warning page, wrong password) |
| `detail` | Why a request failed, like the app not answering |

Lines end in `\r\n`, which JSON parsers read as whitespace. Errors in the command itself,
like an unknown option, are printed as text before the session ends. The
[guide for AI coding agents](https://tunnl.gg/guides/ai-coding-agents) has instructions to
paste into `AGENTS.md` or `CLAUDE.md`.

## Recipes

**Expose another machine on your network:**

```bash
ssh -t -R 80:192.168.1.100:3000 proxy.tunnl.gg
```

**Reconnect automatically,** keeping the same URL through Wi-Fi drops and time limits:

```bash
while true; do
  ssh -t -o ServerAliveInterval=30 -o ExitOnForwardFailure=yes \
    -R 80:localhost:8080 stable@proxy.tunnl.gg
  sleep 5
done
```

To run it as a background service with launchd or systemd, see
[Keep a tunnel running](https://tunnl.gg/guides/keep-a-tunnel-running).

**Skip the warning page** that browsers see once a day, for your own tools and tests:

```bash
curl -H "tunnl-skip-browser-warning: 1" https://happy-tiger-a1b2c3d4.tunnl.gg
```

Webhooks, `curl` and other non-browser clients never see it.

**Choose a subdomain (deployments with accounts):** with `Server.SetAccounts`, an account's
key connects as `pro@` and gets its default subdomain. To open another of the account's
subdomains, name it as the bind address; each command is one tunnel:

```bash
ssh -t -R myapp:80:localhost:3000 pro@proxy.tunnl.gg
ssh -t -R api:80:localhost:8000 pro@proxy.tunnl.gg
```

A name the account doesn't have ends the session with an error. Anonymous clients keep
their random or stable URL; a name they give is ignored, and the banner says so.

## Limits and protection

| Limit | Value | Description |
|-------|-------|-------------|
| Tunnels per IP | 3 | Concurrent tunnels per IP address |
| Total tunnels | 1000 | Server-wide |
| Inactivity timeout | 2 hours | A tunnel closes after 2 hours with no requests or open WebSockets |
| Max tunnel lifetime | 24 hours | Absolute limit |
| Requests per visitor | 25/s (burst 200) | Per visitor IP (IPv6 by /64), per tunnel; excess gets 429 |
| Requests per tunnel | 50/s (burst 400) | Across all visitors; excess gets 429 |
| In-flight requests | 256 per visitor, 512 per tunnel | Concurrent proxied requests; excess gets 429 (visitor) or 503 (tunnel) |
| Request and response bodies | 128 MB each | |
| Request idle timeout | 2 minutes | A proxied request is canceled after 2 minutes without data either way; long polls and streams can run longer while data flows |
| WebSockets | 100 per tunnel, 20 per visitor IP | Concurrent connections |
| WebSocket transfer | 1 GB per direction | Per connection |
| WebSocket idle timeout | 2 hours | |
| SSH connections | 10 per minute per IP | New connections |
| SSH handshakes | 3 per IP, 100 total; 30 second timeout | In progress at once; excess connections are dropped |
| Unanswered channel opens | 32 per tunnel | Connections the SSH client hasn't accepted yet; further requests wait up to 10 seconds |
| Abuse blocks | 1 hour, after 10 violations | Temporary IP block after repeated SSH rate limit violations |

Browsers see a warning page before reaching a tunnel (once a day), to protect them from
phishing. Every response from a tunnel, the app's and tunnl's own, carries
`X-Robots-Tag: noindex, nofollow` whatever the app sends: a tunnel is someone's machine for
a while, not a website, and indexing it would make phishing pages easy to find.

# Running your own server

## How it works

```text
         ssh -R 80:localhost:8080          https://happy-tiger-a1b2c3d4.yourdomain.com
   ┌─────────────┐                            ┌─────────┐
   │ Your laptop │                            │ Browser │
   │  app :8080  │                            └────┬────┘
   └──────┬──────┘                                 │
          │ SSH (:22)                              │ HTTPS (:443)
          ▼                                        ▼
   ┌────────────────────────────────────────────────────────┐
   │                      tunnl server                      │
   │   SSH :22  ──►  tunnel registry  ◄──  HTTPS :443       │
   │                 subdomain → tunnel                     │
   │   HTTP :80 redirects to HTTPS · stats on 127.0.0.1:9090│
   └────────────────────────────────────────────────────────┘
```

1. The client runs `ssh -t -R 80:localhost:8080 proxy.yourdomain.com`.
2. The server picks a subdomain (random, or derived from the key for `stable@`) and prints
   the URL.
3. A browser requests `https://happy-tiger-a1b2c3d4.yourdomain.com`.
4. The server finds the tunnel and sends the request through the SSH connection.
5. The SSH client passes it to `localhost:8080` and the response travels back.

## Before you start

- **A server** with ports 22, 80 and 443 free. tunnl takes port 22, so move your own SSH
  first (below).
- **A domain** with both records pointing at the server:

  ```text
  A    yourdomain.com      → YOUR_SERVER_IP
  A    *.yourdomain.com    → YOUR_SERVER_IP
  ```

- **A wildcard TLS certificate** for `yourdomain.com` and `*.yourdomain.com`. tunnl doesn't
  obtain certificates itself. Wildcards need a DNS challenge, for example with certbot:

  ```bash
  sudo apt install certbot
  sudo certbot certonly --manual --preferred-challenges dns \
    -d yourdomain.com -d '*.yourdomain.com'
  ```

  `--manual` certificates don't renew on their own; a certbot DNS plugin for your DNS
  provider (such as `python3-certbot-dns-cloudflare`) renews them automatically.

- **Move your server's own SSH** off port 22. Test the new port before closing your
  session:

  ```bash
  sudo nano /etc/ssh/sshd_config   # change: Port 22 → Port 2222
  sudo ufw allow 2222/tcp
  sudo systemctl restart sshd
  ssh -p 2222 user@your-server     # in a new terminal
  ```

## Install with Docker

```bash
git clone https://github.com/klipitkas/tunnl.gg.git
cd tunnl.gg

mkdir -p data/certs data/hostkey
sudo cp /etc/letsencrypt/live/yourdomain.com/fullchain.pem data/certs/
sudo cp /etc/letsencrypt/live/yourdomain.com/privkey.pem data/certs/

# The container runs as UID 65534: let it read the certificates and
# store the SSH host key it generates on first start
sudo chown -R 65534:65534 data/certs data/hostkey

docker compose up -d
docker compose logs -f
```

Set `DOMAIN` in `docker-compose.yml` to your domain first. After renewing the certificate, copy
the new files into `data/certs/` and run `docker compose restart`. `docker compose up
tunnl-dev` starts a second instance on other ports for staging.

## Install with systemd

Build the binary (Go 1.26.8+):

```bash
git clone https://github.com/klipitkas/tunnl.gg.git
cd tunnl.gg
make build-small   # ~6 MB; make build-all cross-compiles for Linux and macOS
```

Run it as an unprivileged user. It only needs `CAP_NET_BIND_SERVICE` to bind ports 22, 80
and 443:

```bash
# Service user, binary (root-owned so the service can't replace it),
# and a certificate directory readable by the service
sudo useradd --system --no-create-home --shell /usr/sbin/nologin tunnl
sudo install -d -m 0755 /opt/tunnl
sudo install -m 0755 bin/tunnl /opt/tunnl/tunnl
sudo install -d -o root -g tunnl -m 0750 /etc/tunnl
```

Let's Encrypt keys are readable by root only, so copy them for the service with a certbot
deploy hook, which also runs after every renewal:

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

Save this as `/etc/systemd/system/tunnl.service`:

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
# Only when behind a proxy, see "Behind a proxy"
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

All settings are environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `DOMAIN` | `tunnl.gg` | The domain tunnels are served under |
| `SSH_ADDR` | `:22` | SSH listen address |
| `HTTP_ADDR` | `:80` | HTTP listen address (redirects to HTTPS) |
| `HTTPS_ADDR` | `:443` | HTTPS listen address |
| `STATS_ADDR` | `127.0.0.1:9090` | [Stats endpoint](#stats-endpoint); keep it on localhost |
| `HOST_KEY_PATH` | `host_key` | SSH host key, generated on first start. Keep it: stable URLs and clients' known_hosts depend on it |
| `TLS_CERT` | `/etc/letsencrypt/live/tunnl.gg/fullchain.pem` | TLS certificate |
| `TLS_KEY` | `/etc/letsencrypt/live/tunnl.gg/privkey.pem` | TLS private key |
| `TRUSTED_PROXIES` | unset | Proxies whose headers identify visitors. See [Behind a proxy](#behind-a-proxy) |

To run a second instance on the same machine, give it other ports and its own host key:

```bash
SSH_ADDR=:2223 HTTP_ADDR=:8080 HTTPS_ADDR=:8443 STATS_ADDR=127.0.0.1:9091 \
HOST_KEY_PATH=./host_key_dev ./tunnl
```

## Behind a proxy

Rate limits, WebSocket limits and the `X-Forwarded-For` header sent to apps all use the
visitor's IP address. By default the server trusts no proxies and uses the TCP
connection's address, which is right when it faces the internet directly (including most
on-prem setups). When HTTPS traffic arrives through proxies, list them in
`TRUSTED_PROXIES`:

| Setup | `TRUSTED_PROXIES` |
|-------|-------------------|
| Directly on the internet, or on-prem with no proxy | unset |
| Behind Cloudflare | `cloudflare` |
| Behind your own reverse proxy or load balancer | its IPs or CIDRs, e.g. `10.0.0.0/8` |
| Your proxy behind Cloudflare | `cloudflare,10.0.0.0/8` |

`cloudflare` trusts `CF-Connecting-IP` only from Cloudflare's published ranges (built in,
from [cloudflare.com/ips](https://www.cloudflare.com/ips/)). Other entries trust
`X-Forwarded-For`, read right to left past trusted proxies, so addresses a visitor adds
themselves are ignored. Headers from any other address are ignored too, so list only
proxies you control, and firewall ports 80 and 443 so only they can reach the server.

## Stats endpoint

Server statistics, on localhost only:

```bash
curl http://127.0.0.1:9090/
curl "http://127.0.0.1:9090/?subdomains=true"   # with the active subdomains
```

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

## Troubleshooting

**Connection refused.** Check that the service runs and listens, and that the firewall lets
the ports through:

```bash
docker compose ps                      # or: sudo systemctl status tunnl
sudo ss -tlnp | grep -E ':(22|80|443)'
sudo ufw status
```

**Host key verification.** The first connection asks you to accept the server's host key:
answer `yes`. If the host key ever changes, clients see a warning and stable URLs change
too, so keep `HOST_KEY_PATH` across upgrades.

**No URL shown, or the connection hangs.** Add `-t`, so the session has a terminal:

```bash
ssh -R 80:localhost:8080 proxy.tunnl.gg      # no URL
ssh -t -R 80:localhost:8080 proxy.tunnl.gg   # works
```

For scripts without a terminal, use `-T` with [`output=json`](#json-output-for-scripts-and-agents).

**Certificate errors.** Check that the files exist and haven't expired, then renew:

```bash
ls -la data/certs/                     # Docker; /etc/tunnl/ with systemd
sudo certbot renew                     # the systemd deploy hook copies the new files
sudo cp /etc/letsencrypt/live/yourdomain.com/*.pem data/certs/ && docker compose restart
```

# Contributing

## Local development

`make dev` runs a server on your machine with a self-signed certificate and
`DOMAIN=localhost`, so you can try changes before deploying. In another terminal, start
something on port 3000 and open a tunnel to it:

```bash
ssh -p 2200 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -R 80:localhost:3000 localhost
```

The session shows the URL, e.g. `https://happy-tiger-a1b2c3d4.localhost`. Add the dev
HTTPS port to reach it: `curl -k https://happy-tiger-a1b2c3d4.localhost:8443` (browsers and
curl resolve `*.localhost` to your machine).

## Make commands

| Command | Description |
|---------|-------------|
| `make build` | Optimized build |
| `make build-small` | Smallest build (~6 MB) |
| `make build-tiny` | Compressed with UPX, if installed |
| `make build-all` | Cross-compile for Linux and macOS |
| `make build-dev` | Fast build with debug symbols |
| `make dev` | Local server on unprivileged ports (see [Local development](#local-development)) |
| `make test` | Run the tests |
| `make lint` | Run golangci-lint (v2) |
| `make vuln` | Check reachable code for known vulnerabilities |
| `make clean` | Remove build artifacts |

## Project structure

```text
tunnl.gg/
├── cmd/tunnl/           # Entry point
├── pkg/
│   ├── serve/           # Server startup, shared with hosted builds
│   ├── server/          # SSH and HTTP handling, tunnel registry, accounts, abuse
│   │                    # protection, limits, stats
│   ├── tunnel/          # A tunnel: SSH channels, options, rate limits, request log
│   ├── subdomain/       # Subdomain generation and validation
│   ├── clientip/        # Visitor IPs behind trusted proxies
│   └── config/          # Configuration and limits
├── Dockerfile           # Multi-stage build (scratch image)
├── docker-compose.yml   # Production and dev instances
├── Makefile
└── .golangci.yml        # Linter configuration
```

`ARCHITECTURE.md` describes the design in more depth.

# License

[MIT](LICENSE)
