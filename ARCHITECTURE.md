# Tunnl.gg Architecture

## Overview

Tunnl.gg is a minimal SSH tunneling service that exposes local applications to the internet on their own subdomains over HTTPS.

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                              TUNNL.GG SERVER                                │
│                                                                             │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐  ┌─────────────┐   │
│  │  SSH Server   │  │  HTTP Server  │  │ HTTPS Server  │  │Stats Server │   │
│  │     :22       │  │     :80       │  │    :443       │  │    :9090    │   │
│  │               │  │               │  │               │  │             │   │
│  │  Accepts -R   │  │ ACME + 301    │  │ TLS terminate │  │  Metrics    │   │
│  │  connections  │  │ redirect      │  │ Reverse proxy │  │  (local)    │   │
│  └───────┬───────┘  └───────┬───────┘  └───────┬───────┘  └─────────────┘   │
│          │                  │                  │                            │
│          │                  └────────┬─────────┘                            │
│          │                           │                                      │
│          ▼                           ▼                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                         Tunnel Registry                             │    │
│  │                     map[subdomain]*Tunnel                           │    │
│  │                                                                     │    │
│  │   ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │    │
│  │   │happy-tiger-      │  │calm-eagle-       │  │swift-wolf-       │  │    │
│  │   │a1b2c3d4          │  │e5f6a7b8          │  │d9e0f1a2          │  │    │
│  │   │SSH conn          │  │SSH conn          │  │SSH conn          │  │    │
│  │   │RateLimiter       │  │RateLimiter       │  │RateLimiter       │  │    │
│  │   └────────┬─────────┘  └────────┬─────────┘  └────────┬─────────┘  │    │
│  └──────────┼─────────────────┼─────────────────┼──────────────────────┘    │
│             │                 │                 │                           │
└─────────────┼─────────────────┼─────────────────┼───────────────────────────┘
              │                 │                 │
              ▼                 ▼                 ▼
        ┌──────────┐      ┌──────────┐      ┌──────────┐
        │ SSH Conn │      │ SSH Conn │      │ SSH Conn │
        │ Client 1 │      │ Client 2 │      │ Client 3 │
        └────┬─────┘      └────┬─────┘      └────┬─────┘
             │                 │                 │
             ▼                 ▼                 ▼
        ┌──────────┐      ┌──────────┐      ┌──────────┐
        │ App:8080 │      │ App:3000 │      │ App:5000 │
        └──────────┘      └──────────┘      └──────────┘
```

## Package Structure

```text
tunnl.gg/
├── cmd/tunnl/main.go           # Entry point
└── pkg/
    ├── clientip/
    │   └── clientip.go         # Visitor IP resolution behind trusted proxies (Cloudflare, X-Forwarded-For)
    ├── config/
    │   └── config.go           # Constants and runtime configuration
    ├── serve/
    │   └── serve.go            # Server initialization from the environment, reusable by other binaries
    ├── server/
    │   ├── server.go           # Server struct, tunnel registry, rate limits
    │   ├── accounts.go         # Optional accounts (AccountStore) for hosted deployments
    │   ├── ssh.go              # SSH connection handling, port forwarding
    │   ├── http.go             # HTTP/HTTPS handlers, reverse proxy, WebSocket
    │   ├── stats.go            # Statistics tracking and endpoint
    │   ├── abuse.go            # Abuse tracking, IP blocking, connection rate limiting
    │   ├── connlimit.go        # Concurrent limits (WebSockets, in-flight requests, SSH handshakes)
    │   └── deadlines.go        # Idle timeouts replacing fixed read/write timeouts for proxied requests
    ├── subdomain/
    │   └── subdomain.go        # Memorable subdomain generation and validation
    └── tunnel/
        ├── tunnel.go           # Tunnel struct with activity tracking
        ├── channel.go          # forwarded-tcpip channels to the client, as net.Conn
        ├── ratelimiter.go      # Token bucket rate limiters (per tunnel and per visitor)
        └── requestlogger.go    # Request log streamed to the SSH session
```

## Components

### 1. SSH Server (`pkg/server/ssh.go`)

Listens on port 22 (configurable) and handles remote port forwarding requests.

**Flow:**

1. Client connects: `ssh -t -R 80:localhost:8080 tunnl.gg`
2. Server drops blocked IPs and enforces handshake concurrency limits, then performs the SSH handshake with a 30s timeout.
   No auth is required, except for the `stable` user, which must offer an SSH key (any key is accepted),
   and the `pro` user on a server with an `AccountStore`, whose key must belong to an account
3. Server sets `TCP_NODELAY` for low latency
4. Server assigns a memorable subdomain (e.g., `happy-tiger-a1b2c3d4`): random, or for the `stable` user
   derived from its key as `HMAC-SHA256(secret derived from the host key, public key)`, replacing any older
   connection with the same key. Accounts get the subdomain reserved for them, shared by all their keys, or
   else their key's, and their own limits (`config.Limits`) instead of the free ones
5. Server registers tunnel in registry when the client sends its `tcpip-forward` request
6. Server sends URL to client via session channel
7. For each proxied connection, the server opens a `forwarded-tcpip` channel to the client

**Key structures:**

```go
type tcpipForwardRequest struct {
    BindAddr string
    BindPort uint32
}

type forwardedTCPPayload struct {
    Addr       string  // "127.0.0.1"
    Port       uint32  // 80 (what client requested)
    OriginAddr string  // Incoming request IP
    OriginPort uint32  // Incoming request port
}
```

### 2. HTTP Server (`pkg/server/http.go`)

Listens on port 80 and serves two purposes:

- Redirects all traffic to HTTPS (301)
- Validates host before redirect (prevents open redirect)

### 3. HTTPS Server (`pkg/server/http.go`)

Listens on port 443 with pre-configured TLS certificates.

**Request flow:**

1. Extract subdomain from `Host` header (e.g., `happy-tiger-a1b2c3d4.tunnl.gg`)
2. Validate subdomain format (adjective-noun-hex pattern)
3. Look up tunnel in registry
4. Check rate limits (25 req/s per visitor IP, 50 req/s per tunnel); excess gets 429
5. Mark the request in flight (the tunnel can't go idle until it finishes)
6. Show interstitial warning for browser requests (first visit)
7. Handle WebSocket upgrade if requested
8. Reverse proxy request to the client over a new `forwarded-tcpip` SSH channel (no local listener or socket).
   At most 32 channel opens per tunnel can await the client's answer; further requests wait for one (up to the 10s dial timeout).
10. SSH client forwards to local application

### 4. Stats Server (`pkg/server/stats.go`)

Listens on `127.0.0.1:9090` (localhost only) and exposes metrics.

**Endpoint:** `GET /`

**Response:**

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
  "subdomains": ["happy-tiger-a1b2c3d4", "calm-eagle-e5f6a7b8"]
}
```

Add `?subdomains=true` to include active subdomain list.

### 5. Tunnel Registry (`pkg/server/server.go`)

Thread-safe map storing active tunnels.

```go
type Server struct {
    tunnels       map[string]*tunnel.Tunnel
    ipConnections map[string]int             // Concurrent tunnels per IP
    sshConns      map[string][]*ssh.ServerConn // SSH connections per IP (for forced closure)
    mu            sync.RWMutex
    sshConfig     *ssh.ServerConfig
    domain        string                     // Configurable domain (default: tunnl.gg)

    // Stats (atomic counters)
    totalConnections uint64
    totalRequests    uint64

    // Abuse protection
    abuseTracker *AbuseTracker
}
```

### 6. Tunnel (`pkg/tunnel/tunnel.go`)

Represents a single active tunnel.

```go
type Tunnel struct {
    Subdomain     string
    opener        ChannelOpener     // SSH connection used to open forwarded-tcpip channels
    CreatedAt     time.Time         // For max lifetime check
    LastActive    time.Time         // For inactivity timeout
    BindAddr      string            // Client's requested bind address
    BindPort      uint32            // Client's requested bind port
    ClientIP       string            // SSH client IP that created the tunnel
    mu             sync.Mutex
    rateLimiter    *RateLimiter      // Tunnel-wide rate limit across all visitors
    visitorLimiter *KeyedRateLimiter // Per-visitor rate limit
    transport      *http.Transport   // Reusable HTTP transport for proxying
}
```

### 7. Subdomain Generator (`pkg/subdomain/subdomain.go`)

Generates memorable, random subdomains.

**Format:** `adjective-noun-xxxxxxxx` (8 hex chars)

**Examples:** `happy-tiger-a1b2c3d4`, `calm-eagle-e5f6a7b8`, `swift-wolf-d9e0f1a2`

**Components:**

- 32 adjectives × 32 nouns × 4,294,967,296 hex combinations = ~4.4 trillion possible subdomains
- Whitelist-based validation prevents injection attacks

### 8. Rate Limiter (`pkg/tunnel/ratelimiter.go`)

Token bucket rate limiting for HTTP requests. Each tunnel has two limiters:

- `KeyedRateLimiter`: one bucket per visitor IP (IPv6 grouped by /64), 25 req/s with a burst of 200.
  At most 1024 visitors are tracked per tunnel; fully refilled buckets are pruned when the map is full,
  and any visitors beyond the cap share a single overflow bucket.
- `RateLimiter`: one bucket for the whole tunnel, 50 req/s with a burst of 400.

The visitor limit is checked first, so a throttled visitor cannot drain the tunnel-wide budget.
Exceeding either limit only returns `429 Too Many Requests` to the visitor. The tunnel owner is never
penalized, because visitors control the request rate.

### 9. Inactivity Monitor

Per-tunnel goroutine that checks every minute if the tunnel has been idle for 2 hours or if `CreatedAt` exceeds 24 hours (max lifetime).
A tunnel is idle only when no requests or WebSockets are in flight, so long-lived streams and WebSockets keep it alive.
If expired, closes the SSH connection, which triggers cleanup.

### 10. Abuse Tracker (`pkg/server/abuse.go`)

Tracks connection patterns and blocks abusive IPs.

```go
type AbuseTracker struct {
    mu sync.RWMutex

    // Connection timestamps per IP for rate limiting
    connectionTimes map[string][]time.Time

    // Blocked IPs with expiration time
    blockedIPs map[string]time.Time

    // Rate limit violation counts per IP
    violationCounts map[string]int

    // Callback when IP is blocked (closes existing tunnels)
    onBlock BlockCallback

    // Stats (atomic for thread safety)
    totalBlocked     atomic.Uint64
    totalRateLimited atomic.Uint64

    // Lifecycle management
    stopCleanup chan struct{}
    cleanupDone chan struct{}
}
```

**Features:**

- **Connection rate limiting**: Sliding window (1 minute) tracking new SSH connections per IP
- **Auto-blocking**: IPs repeatedly exceeding the SSH connection rate limit are blocked for 1 hour
- **Pre-handshake rejection**: Blocked IPs are dropped before the SSH handshake, without a message, so they cost no key exchange work
- **Connection closure**: All SSH connections (and their tunnels) are forcibly closed when an IP is blocked
- **Memory cleanup**: Background goroutine removes stale entries every 5 minutes
- **Graceful shutdown**: `Stop()` method for clean server shutdown

## Data Flow

### Incoming HTTP Request

```text
Browser                    Server                         Client
   │                         │                              │
   │  GET /api/users         │                              │
   │  Host: abc123.tunnl.gg  │                              │
   ├────────────────────────►│                              │
   │                         │  1. TLS terminate            │
   │                         │  2. Validate subdomain       │
   │                         │  3. Check rate limit         │
   │                         │  4. Lookup tunnel            │
   │                         │  5. Open SSH channel to      │
   │                         │     the client               │
   │                         ├─────────────────────────────►│
   │                         │  forwarded-tcpip channel     │
   │                         │                              │
   │                         │                              │  6. Forward to
   │                         │                              │     localhost:8080
   │                         │                              │
   │                         │◄─────────────────────────────┤
   │                         │  Response via SSH channel    │
   │◄────────────────────────┤                              │
   │  HTTP Response          │                              │
```

## Security Considerations

1. **No SSH Authentication**: Anyone can create tunnels. This is intentional for a free service.

2. **Subdomain Isolation**: Each tunnel gets an unguessable subdomain, random or keyed from the client's SSH key, making enumeration impractical (~4.4 trillion combinations).

3. **Subdomain Validation**: Strict whitelist-based validation prevents injection attacks.

4. **TLS Termination**: All public traffic is encrypted. Internal traffic (server↔SSH client) is also encrypted via SSH.

5. **Host Validation**: Only requests to `*.domain` are accepted (domain is configurable).

6. **SSH Handshake Limits**: 30-second deadline prevents malicious clients from holding connections indefinitely during handshake,
   and at most 3 handshakes per IP (100 server-wide) can be in progress at once.

7. **Rate Limiting**:
   - Per IP: Max 3 concurrent tunnels
   - Per visitor per tunnel: 25 requests/second, 200 burst
   - Per tunnel: 50 requests/second, 400 burst
   - Per IP: Max 10 new connections per minute
   - Global: Max 1000 total tunnels

7. **Abuse Protection**:
   - HTTP rate limits only throttle visitors (429); visitor traffic never kills a tunnel or blocks its owner
   - SSH connection rate limiting: 10 connections/minute per IP; 10 violations block the IP for 1 hour
   - All SSH connections forcibly closed when IP is blocked (tunnels cleaned up automatically)
   - Blocked IPs dropped before the SSH handshake
   - Memory-safe cleanup of tracking data

8. **Request/Response Limits**:
   - Max request body: 128 MB
   - Max response body: 128 MB
   - Max in flight: 256 concurrent proxied requests per visitor IP (across tunnels) and 512 per tunnel
   - Idle timeout: proxied requests replace the fixed HTTPS read/write timeouts with a 2-minute idle timeout
     (extended on every body read and response write), so long polls, streams and slow uploads work while data flows

9. **WebSocket Limits**:
   - Max transfer: 1 GB per direction per connection (client can reconnect)
   - Idle timeout: 2 hours (per-read deadline reset)
   - Max concurrent: 100 per tunnel, 20 per visitor IP across all tunnels (excess gets 429)

10. **Tunnel Lifetime**:
    - Inactivity timeout: 2 hours
    - Max lifetime: 24 hours (regardless of activity)

11. **IP Spoofing Prevention**: Visitor IPs come from the TCP connection unless it is from a proxy listed in `TRUSTED_PROXIES`:
    `CF-Connecting-IP` from Cloudflare's ranges, or `X-Forwarded-For` (read right to left past trusted proxies) from others.
    Backends receive `X-Forwarded-For`, `X-Forwarded-Host`, and `X-Forwarded-Proto` set by the server; visitor-supplied
    forwarding headers, and `CF-Connecting-IP` not from Cloudflare, are removed.

12. **Phishing Protection**: Browser requests show interstitial warning page (cookie-based, 1 day).

13. **Security Headers**: Server-generated responses (errors, redirects) include `X-Content-Type-Options`, `X-Frame-Options: DENY`,
    and `Referrer-Policy`. Proxied responses keep the app's own headers; `X-Content-Type-Options` and `Referrer-Policy`
    are added only when the app omits them, and framing is left to the app so it can be embedded.

14. **Stats Endpoint**: Only accessible from localhost (127.0.0.1, ::1).

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SSH_ADDR` | `:22` | SSH server address |
| `HTTP_ADDR` | `:80` | HTTP server address |
| `HTTPS_ADDR` | `:443` | HTTPS server address |
| `STATS_ADDR` | `127.0.0.1:9090` | Stats endpoint address |
| `HOST_KEY_PATH` | `host_key` | SSH host key path |
| `TLS_CERT` | `/etc/letsencrypt/live/tunnl.gg/fullchain.pem` | TLS certificate |
| `TLS_KEY` | `/etc/letsencrypt/live/tunnl.gg/privkey.pem` | TLS private key |
| `DOMAIN` | `tunnl.gg` | Domain name for the service |
| `TRUSTED_PROXIES` | unset | Proxies whose headers identify visitors (CIDRs/IPs and/or `cloudflare`) |

## Limitations

- No custom subdomains (random, or stable per SSH key via the `stable` user), except ones a hosted
  deployment reserves for accounts
- No accounts of its own: a deployment that wants them builds its own binary with an `AccountStore`
  (`Server.SetAccounts`), which maps SSH keys to accounts with their own limits
- Single server (no horizontal scaling)
- Certificates must be pre-configured (no automatic ACME)
- Stats reset on restart (no persistence)
