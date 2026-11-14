---
name: expose-localhost
description: Give a local dev server a public HTTPS URL with tunnl.gg (one ssh command, nothing to install, no account). Use when the user wants to expose localhost, get a public URL for a local port, receive webhooks (Stripe, GitHub, Slack...) locally, register an OAuth callback, share a dev preview, test on a phone, or asks for ngrok / Cloudflare Tunnel / localtunnel-style tunneling.
---

# Expose a local port with tunnl.gg

`ssh -R 80:localhost:PORT proxy.tunnl.gg` gives `localhost:PORT` a public HTTPS URL
(`https://<name>.tunnl.gg`, WebSockets work too). It uses the system `ssh`; there is
nothing to install and no account. The session is long-running: the tunnel lives
exactly as long as the ssh process.

## 1. Before starting

- Check `command -v ssh`. Missing: OpenSSH client is built into macOS, Linux and
  Windows 10+; ask the user to install/enable it rather than switching tools.
- Make sure the app is already listening on the port (e.g. `curl -sI localhost:3000`).
  The tunnel opens anyway, but every request then fails with 502.
- Pick the user name:
  - `proxy.tunnl.gg`: new random URL on every connection. Fine for a quick share.
  - `stable@proxy.tunnl.gg`: the same URL every time for this machine's SSH key. Use it
    whenever the URL is registered somewhere else (webhook endpoint, OAuth redirect
    URI, a mobile build) so restarts don't break it. Needs an SSH key: if
    `ls ~/.ssh/id_*.pub` finds none, ask the user before creating one with
    `ssh-keygen -t ed25519`. One live tunnel per key: a second `stable@` connection
    with the same key replaces the first.
  - `pro@proxy.tunnl.gg`: only if the user says they have a tunnl.gg account linked to
    their key (own subdomain, no time limits).

## 2. Start it in the background and read the URL

Never run it in the foreground (it never exits) and never scrape the text banner. Use
`output=json` with `-n -T` and read the first JSON line:

```bash
PORT=3000
LOG="${TMPDIR:-/tmp}/tunnl-$PORT.jsonl"
ssh -n -T -o ServerAliveInterval=30 -o ExitOnForwardFailure=yes \
  -o StrictHostKeyChecking=accept-new \
  -R 80:localhost:$PORT stable@proxy.tunnl.gg output=json >"$LOG" 2>"$LOG.err" &
echo $! >"$LOG.pid"
for i in $(seq 1 30); do                       # wait up to 30s
  grep -q '"event":"tunnel"' "$LOG" 2>/dev/null && break
  kill -0 "$(cat "$LOG.pid")" 2>/dev/null || break   # ssh exited: an error
  sleep 1
done
URL=$(grep -m1 '"event":"tunnel"' "$LOG" | grep -o '"url":"[^"]*"' | cut -d'"' -f4)
if [ -n "$URL" ]; then echo "$URL"; else cat "$LOG" "$LOG.err"; fi
```

Use the agent's background-process facility if it has one; the `&` form above also
works. If no URL appears, the log holds the reason in plain text (see Troubleshooting).
Report the URL to the user, and keep `$LOG` for the rest of the session.

The first line looks like:

```json
{"event":"tunnel","url":"https://pearl-ocean-79cd8a18.tunnl.gg","subdomain":"pearl-ocean-79cd8a18","stable":true,"idle_timeout_seconds":7200,"max_lifetime_seconds":86400,"daily_transfer_bytes":5368709120,"transfer_used_bytes":102,"options":["host"]}
```

`stable` says whether the URL survives a reconnect. `warning` appears if the server
ignored part of the request. Then one line per request, plus `notice` lines:

```json
{"event":"request","time":"2026-11-14T05:18:30Z","method":"POST","path":"/webhooks/stripe","status":200,"bytes":2,"duration_ms":41,"visitor":"54.187.174.169"}
{"event":"request","time":"2026-11-14T05:18:40Z","method":"GET","path":"/","status":502,"bytes":12,"duration_ms":82,"visitor":"203.0.113.9","detail":"your local app didn't accept the connection: connection refused"}
{"event":"notice","message":"..."}
```

To confirm a webhook arrived: `grep '"event":"request"' "$LOG" | tail -5`. `detail`
explains failures; `from_tunnl: true` means tunnl answered itself (rate limit, warning
page, wrong password), not the app.

## 3. Stop it

```bash
kill "$(cat "$LOG.pid")" && rm -f "$LOG" "$LOG.err" "$LOG.pid"
```

Stop tunnels you started when the task is done, unless the user wants it kept open.
The URL returns 404 once the tunnel is gone.

## Options (after the host, as name=value)

| Option | Use |
|--------|-----|
| `host=localhost:3000` | Send this `Host` header to the app. Fixes "Blocked request" / "Invalid Host header" from Vite (`server.allowedHosts`), webpack-dev-server, Django `ALLOWED_HOSTS`, Rails host authorization, without editing their config. `X-Forwarded-Host` still has the public host. |
| `auth=user:password` | Pro. Visitors must sign in (HTTP basic auth): protects a shared preview. |
| `allow=203.0.113.7,198.51.100.0/24` | Pro. Only these IPs/networks get through. |
| `cors=*` or `cors=https://app.example.com` | Pro. Let browser pages on other origins call the tunnel. |
| `output=json` | JSON lines as above. Always use it from an agent. |

`host=` and `output=json` work for everyone. On the free tier, `auth=`, `allow=` and
`cors=` end the session with `ERROR: auth= isn't available for this tunnel...`; tell
the user they need tunnl.gg Pro (`pro@`) rather than retrying. Any unknown or invalid
option also ends the session with `ERROR: ...` and the option list.

If the app builds absolute URLs (OAuth `redirect_uri`, asset links), set its base
URL/public URL setting to the tunnel URL, or have it honor
`X-Forwarded-Host`/`X-Forwarded-Proto`. For Next.js dev, add the tunnel host to
`allowedDevOrigins` if it warns about cross-origin dev requests.

## Limits and the browser warning page (free tier)

- A tunnel closes after 2 h without requests, and after 24 h in any case; the ssh
  process exits then. Restart it (with `stable@` the URL stays the same). The JSON line
  gives the exact `idle_timeout_seconds` / `max_lifetime_seconds` (`0` = none).
- Browsers (requests with a browser User-Agent) are sent once a day to a phishing
  warning page before reaching the app; a person clicks through it. Webhooks, curl and
  SDKs never see it. When scripting requests with a browser-like User-Agent, or
  driving a headless browser, add the header `tunnl-skip-browser-warning: 1`:
  `curl -H "tunnl-skip-browser-warning: 1" "$URL/api/health"`.
- 3 tunnels at once per IP, 5 GB transfer per day, 64 MB per request/response body,
  rate limits per visitor (429 when exceeded).

## Security

- The URL is public: anyone who has it reaches the app. Never put secrets, tokens or
  passwords in the URL or the path you share. To restrict access, use `auth=`/`allow=`
  (Pro), or don't open the tunnel at all.
- `auth=` credentials end up in shell history and are visible to the server; use a
  throwaway password, never a real one.
- Don't expose admin panels, databases or debug consoles without asking the user.
- `accept-new` trusts the host key on first use. It can be checked with
  `ssh-keygen -lF proxy.tunnl.gg`: ED25519 `SHA256:5uQ6VobmUpY4wyMmm5jnAwFtt3aX06WYDDM4ER+2WUw`.

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `ssh: command not found` | Install the OpenSSH client (Windows: Settings > Optional features > OpenSSH Client). |
| No URL after 30 s, `$LOG` empty, ssh still running | Missing `output=json`, or the network blocks outbound port 22 (check `$LOG.err`). |
| `ERROR: ... isn't available for this tunnel` | `auth=`/`allow=`/`cors=` need Pro; drop the option or ask the user. |
| `Host key verification failed` | Run with `-o StrictHostKeyChecking=accept-new`, or the known_hosts entry is stale. |
| `stable@ ... has no key to offer` / `Permission denied (publickey...)` | No SSH key: `ssh-keygen -t ed25519` (with the user's OK), or use the random URL. |
| Requests get 502, `detail: your local app didn't accept the connection`, `$LOG.err` shows `connect_to localhost port N: failed` | Nothing listens on that port, or the app listens only on another interface: start it / fix the port. If it binds to one address only, forward to that address (`-R 80:127.0.0.1:PORT`, `-R 80:[::1]:PORT`); for another machine, `-R 80:192.168.1.100:PORT`. |
| App answers "Blocked request" / "Invalid Host header" / 400 | Add `host=localhost:PORT`. |
| Browser shows a tunnl.gg warning page | Expected once a day for people; click through, or send `tunnl-skip-browser-warning: 1` from scripts. |
| ssh exited later on its own | Idle (2 h) or lifetime (24 h) limit, network drop, or another `stable@` session with the same key took over. Restart it. |
| 429 | Rate or daily transfer limit; slow down or wait (resets 00:00 UTC). |
