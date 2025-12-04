# Tunnl.gg Architecture

## Overview

Tunnl.gg is a minimal SSH tunneling service that exposes local applications to the internet via random subdomains with automatic SSL.

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
│  │   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │    │
│  │   │happy-tiger-  │  │calm-eagle-   │  │swift-wolf-   │    ...       │    │
│  │   │a1b2          │  │c3d4          │  │e5f6          │              │    │
│  │   │Listener:X    │  │Listener:Y    │  │Listener:Z    │              │    │
│  │   │RateLimiter   │  │RateLimiter   │  │RateLimiter   │              │    │
│  │   └──────┬───────┘  └──────┬───────┘  └──────┬───────┘              │    │
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
├── cmd/tunnl/main.go           # Entry point, server initialization
└── internal/
    ├── config/
    │   └── config.go           # Constants and runtime configuration
    ├── server/
    │   ├── server.go           # Server struct, tunnel registry, rate limits
    │   ├── ssh.go              # SSH connection handling, port forwarding
    │   ├── http.go             # HTTP/HTTPS handlers, reverse proxy, WebSocket
    │   ├── stats.go            # Statistics tracking and endpoint
    │   └── abuse.go            # Abuse tracking, IP blocking, connection rate limiting
    ├── subdomain/
    │   └── subdomain.go        # Memorable subdomain generation and validation
    └── tunnel/
        ├── tunnel.go           # Tunnel struct with activity tracking
        └── ratelimiter.go      # Token bucket rate limiter
```

## Components

### 1. SSH Server (`internal/server/ssh.go`)

Listens on port 22 (configurable) and handles remote port forwarding requests.

**Flow:**

1. Client connects: `ssh -t -R 80:localhost:8080 tunnl.gg`
2. Server performs SSH handshake (no auth required)
3. Server sets `TCP_NODELAY` for low latency
4. Server generates memorable subdomain (e.g., `happy-tiger-a1b2`)
5. Server creates internal TCP listener for tunnel
6. Server registers tunnel in registry
7. Server sends URL to client via session channel
8. Server waits for `forwarded-tcpip` channel requests

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

### 2. HTTP Server (`internal/server/http.go`)

Listens on port 80 and serves two purposes:

- Redirects all traffic to HTTPS (301)
- Validates host before redirect (prevents open redirect)

### 3. HTTPS Server (`internal/server/http.go`)

Listens on port 443 with pre-configured TLS certificates.

**Request flow:**

1. Extract subdomain from `Host` header (e.g., `happy-tiger-a1b2.tunnl.gg`)
2. Validate subdomain format (adjective-noun-hex pattern)
3. Look up tunnel in registry
4. Check rate limit (10 req/s per tunnel)
5. Touch tunnel to reset inactivity timer
6. Show interstitial warning for browser requests (first visit)
7. Handle WebSocket upgrade if requested
8. Reverse proxy request to tunnel's internal listener
9. Internal listener forwards to SSH client via `forwarded-tcpip` channel
10. SSH client forwards to local application

### 4. Stats Server (`internal/server/stats.go`)

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
  "subdomains": ["happy-tiger-a1b2", "calm-eagle-c3d4"]
}
```

Add `?subdomains=true` to include active subdomain list.

### 5. Tunnel Registry (`internal/server/server.go`)

Thread-safe map storing active tunnels.

```go
type Server struct {
    tunnels       map[string]*tunnel.Tunnel
    ipConnections map[string]int             // Concurrent tunnels per IP
    sshConns      map[string][]*ssh.ServerConn // SSH connections per IP (for forced closure)
    mu            sync.RWMutex
    sshConfig     *ssh.ServerConfig

    // Stats (atomic counters)
    totalConnections uint64
    totalRequests    uint64

    // Abuse protection
    abuseTracker *AbuseTracker
}
```

### 6. Tunnel (`internal/tunnel/tunnel.go`)

Represents a single active tunnel.

```go
type Tunnel struct {
    Subdomain   string
    Listener    net.Listener  // Internal listener (127.0.0.1:random)
    CreatedAt   time.Time     // For max lifetime check
    LastActive  time.Time     // For inactivity timeout
    BindAddr    string        // Client's requested bind address
    BindPort    uint32        // Client's requested bind port
    mu          sync.Mutex
    rateLimiter *RateLimiter  // Per-tunnel rate limiting
}
```

### 7. Subdomain Generator (`internal/subdomain/subdomain.go`)

Generates memorable, random subdomains.

**Format:** `adjective-noun-xxxx` (4 hex chars)

**Examples:** `happy-tiger-a1b2`, `calm-eagle-c3d4`, `swift-wolf-e5f6`

**Components:**

- 32 adjectives × 32 nouns × 65536 hex combinations = ~67 million possible subdomains
- Whitelist-based validation prevents injection attacks

### 8. Rate Limiter (`internal/tunnel/ratelimiter.go`)

Token bucket algorithm for per-tunnel request limiting.

```go
type RateLimiter struct {
    tokens     float64  // Current tokens
    maxTokens  float64  // Burst size (20)
    refillRate float64  // Tokens per second (10)
    lastRefill time.Time
    mu         sync.Mutex
}
```

### 9. Inactivity Monitor

Per-tunnel goroutine that checks every minute if `LastActive` exceeds 30 minutes or if `CreatedAt` exceeds 24 hours (max lifetime).
If expired, closes the SSH connection, which triggers cleanup.

### 10. Abuse Tracker (`internal/server/abuse.go`)

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
- **Auto-blocking**: IPs exceeding rate limits 5 times are blocked for 1 hour
- **Block notification**: Users see block expiry time when attempting to connect
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
   │                         │  5. Connect to internal      │
   │                         │     listener                 │
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

2. **Subdomain Isolation**: Each tunnel gets a random subdomain, making enumeration impractical (~67M combinations).

3. **Subdomain Validation**: Strict whitelist-based validation prevents injection attacks.

4. **TLS Termination**: All public traffic is encrypted. Internal traffic (server↔SSH client) is also encrypted via SSH.

5. **Host Validation**: Only requests to `*.tunnl.gg` are accepted.

6. **Rate Limiting**:
   - Per IP: Max 3 concurrent tunnels
   - Per tunnel: 10 requests/second, 20 burst
   - Per IP: Max 10 new connections per minute
   - Global: Max 1000 total tunnels

7. **Abuse Protection**:
   - Auto-block after 5 rate limit violations (1-hour block)
   - All SSH connections forcibly closed when IP is blocked (tunnels cleaned up automatically)
   - Users notified of block expiry time
   - Memory-safe cleanup of tracking data

8. **Request/Response Limits**:
   - Max request body: 128 MB
   - Max response body: 128 MB

9. **Tunnel Lifetime**:
   - Inactivity timeout: 30 minutes
   - Max lifetime: 24 hours (regardless of activity)

10. **IP Spoofing Prevention**: X-Forwarded-For header is not trusted (service runs directly on internet).

11. **Phishing Protection**: Browser requests show interstitial warning page (cookie-based, 1 day).

12. **Security Headers**: All responses include `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy`.

13. **Stats Endpoint**: Only accessible from localhost (127.0.0.1, ::1).

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

## Limitations

- No custom subdomains (random only)
- No authentication/accounts
- Single server (no horizontal scaling)
- Certificates must be pre-configured (no automatic ACME)
- Stats reset on restart (no persistence)
