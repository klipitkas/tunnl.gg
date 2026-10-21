# Channel reuse — October 21, 2026

The tunnel HTTP transport now retains at most 32 idle channels instead of 10,
with the existing 90-second idle expiry. This addresses repeated concurrent
bursts where the backend keeps its HTTP connections open. Channels are opened
on demand, and both the per-host and total per-tunnel idle caps are 32.
Active-request limits, pending channel-open limits and timeouts are unchanged.

The change is local, not deployed. Current production pool-closure telemetry
was not available locally, so the following establishes a controlled mechanism
and its resource tradeoff, not a production-wide latency or capacity gain.

## Hypothesis and experiment

The original transport already reused connections. The hypothesis was that
retaining only ten after a larger burst forces avoidable SSH channel opens
on the next burst. A larger pool should reduce both open attempts and latency
when channels remain reusable, with no useful benefit below the old cap or
when the backend closes connections between bursts.

`pkg/tunnel/reuse_test.go` uses a real loopback SSH connection, forwarded
channels, and a TCP HTTP backend. Its opener adds 130 ms before opening a
channel, and the backend takes 50 ms to answer. **Only opens are delayed**;
this is not a WAN emulator and does not add delay to payload packets. These
are explicit synthetic assumptions, not measurements of current users.

Each case has one warm-up burst followed by four measured bursts. Cases:

- Eight concurrent requests, with persistent backend connections.
- 32 concurrent requests, with persistent backend connections.
- 32 concurrent requests with a 30 ms backend idle timeout; a gap of at
  least 60 ms between bursts makes those connections unusable next time.

The short timeout in the last case models backend-driven expiry without
waiting seconds between every sample. Dials that outlive a request are allowed
to finish before the next burst. Every response's status and complete body
are checked; connection-open errors or corrupt responses fail the experiment.

`httptrace.GotConn` counts requests using reused connections, and
`PutIdleConn` counts reported pool-full rejections. The fixture also counts
every channel-open attempt and the existing `ChannelObserver` close events,
separating relay-initiated and backend-initiated closes. Backend connection
state independently measures the number of retained connections. See
[Go's HTTP tracing API](https://pkg.go.dev/net/http/httptrace).

Go 1.26.9, darwin/arm64, Apple M1 Pro, `CGO_ENABLED=0`, `GOMAXPROCS=8`.
All pool sizes use the same binary. Ten samples alternate pool order between
10/16/32 and 32/16/10, without other validation jobs running alongside them.
There were 8,640 measured requests and 2,160 warm-up requests; all succeeded.
The measurements bypass the public handler and therefore exclude TLS,
request logging, admission limits and frontend scheduling.

## Results

Values are medians across ten samples. Open counts cover the four measured
bursts, excluding warm-up. Each 32-concurrency sample has 128 measured requests.

| Persistent backend, 32 concurrent | Pool 10 | Pool 16 | Pool 32 |
| --- | ---: | ---: | ---: |
| p50 latency | 103.14 ms | 102.76 ms | 51.89 ms |
| p95 latency | 183.35 ms | 103.75 ms | 52.29 ms |
| p99 latency | 185.10 ms | 104.15 ms | 52.36 ms |
| Additional channel-open attempts | 88 | 64 | 0 |
| Requests served on reused connections | 127.5 | 128 | 128 |
| Relay-initiated closes | 88 | 64 | 0 |
| Backend-initiated closes | 0 | 0 | 0 |
| Retained channels after the bursts | 10 | 16 | 32 |

Pool 32 reduced p95 by 71.48% and p50 by 49.69% in this scenario
(`p<0.001` in benchstat). Pool 16 improved the tail but still opened and
discarded 64 channels. Pool 32 is the smallest tested size that eliminated
the extra opens for this burst shape; it is not established as optimal for
every workload.

A request reuse counter alone would miss much of this churn. Go's transport
can start a dial while waiting, then hand the request an older connection that
becomes free first. The pending dial still completes and may be discarded if
the pool is full. That explains 100% request reuse alongside 64 new opens with
pool 16. `PutIdleConn` callbacks also miss these unused dial completions;
channel-open and channel-close counts expose them.

| Control | Pool 10 p95 | Pool 32 p95 | Additional opens, both sizes |
| --- | ---: | ---: | ---: |
| Eight concurrent, persistent backend | 51.72 ms | 51.71 ms | 0 |
| 32 concurrent, backend closes between bursts | 185.35 ms | 185.12 ms | 128 |

Neither control showed a significant latency difference. When the app closes
connections before the next request, increasing tunnl's pool cannot restore
those connections. This change does not address that source of channel opens.

## Resource cost and boundaries

The larger pool can retain 22 additional channels after a busy burst, until
the backend closes them or their 90-second idle timeout expires. Quiet tunnels
do not preallocate the new capacity. The aggregate and per-host caps prevent
different spellings of the HTTP host from multiplying the per-tunnel bound.

After the 32-request burst, median retained heap growth measured across the
whole fixture was 1.138 MiB with pool 10 and 2.975 MiB with pool 32. Additional
live goroutines across the fixture were 95 and 271, respectively. Both numbers
include the SSH client, its forwarding copies, the backend, and the relay.
They are **not isolated relay heap/RSS or goroutine costs**. Garbage collection
and shared pools also add variability. Low-concurrency cases retained eight
channels with every pool size; backend-expiry cases retained zero.

Retaining channels trades memory and idle backend sockets for fewer opens
and less queuing on subsequent bursts. It is justified here for repeated
bursts, not as a universal reduction in resource consumption. Production
verification should compare near-zero-idle relay closures, channel-open
counts and latency, error rate, and relay RSS/goroutines under matched traffic.
The existing `tunnl_pooled_channel_closed_by_tunnl_idle_seconds` and
`tunnl_pooled_channel_closed_by_app_idle_seconds` histograms separate useful
investigation paths; near-zero relay closes can also reflect failed requests,
so error counts matter. A high request-reuse fraction alone is insufficient.

## Reproduction and validation

The opt-in harness is checked in. Run ten samples, alternating
`TUNNL_REUSE_REVERSE` between 0 and 1:

```sh
GOWORK=off GOTOOLCHAIN=go1.26.9 CGO_ENABLED=0 GOMAXPROCS=8 \
  TUNNL_REUSE_PERF=1 TUNNL_REUSE_REVERSE=0 \
  go test ./pkg/tunnel -run '^TestChannelReusePerformance$' -count=1 -v
```

Raw samples, the exact measured binary, a comparison script, and environment
metadata are retained in ignored [`.dev/channel-reuse-20261021`](../../.dev/channel-reuse-20261021/).
The script separates pool sizes into equivalent benchmark names for benchstat:

- [Statistical comparison](../../.dev/channel-reuse-20261021/benchstat.txt).
- Raw [pool 10](../../.dev/channel-reuse-20261021/pool-10.txt),
  [pool 16](../../.dev/channel-reuse-20261021/pool-16.txt), and
  [pool 32](../../.dev/channel-reuse-20261021/pool-32.txt) measurements.
- [Comparison script](../../.dev/channel-reuse-20261021/compare.py) and
  [environment / binary hash](../../.dev/channel-reuse-20261021/environment.json).

Normal regression tests hold the first responses until every request reaches
the backend, avoiding sleep-based assumptions about concurrency. They verify
reuse after bursts of 8 and 24, a bounded idle pool after 40 simultaneous
requests, pool cleanup on tunnel close, and successful reopening after idle
expiry. The 40-request case also confirms that 32 is not an active-request cap.

Passed after the default changed:

- Full `go test -race ./...`.
- All nine performance scenarios under the race detector (excluded from timing results).
- `go vet ./...`, `CGO_ENABLED=0 go build ./...`.
- golangci-lint 2.14.0: zero issues.

The preceding proxy-allocation changes remain in the checkout; this experiment
varies only the tunnel transport's pool sizes and does not depend on those changes.
