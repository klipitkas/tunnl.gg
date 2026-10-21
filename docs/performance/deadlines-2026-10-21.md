# Proxy deadline allocations — October 21, 2026

The proxy's response writer, response controller, deadline state and optional
request-body wrapper now share one request-owned allocation. Cleanup uses a
method on that object instead of allocating a returned closure.

The baseline is the saved working tree after the activity-guard optimization,
including all earlier performance changes. Both versions use identical handler
and TLS/SSH benchmarks. No timer, cancellation, idle-timeout or rate-limit
policy changed.

## Mechanism and behavior

Previously, setup allocated deadline state, a response controller, a response
writer and a cleanup closure separately, plus a wrapper when the body was
neither nil nor `http.NoBody`.
`proxyDeadlines` now implements the response-writer methods directly, owns its
controller by value, and embeds the optional body wrapper. The HTTP handler
uses `defer dw.stop()` at the same cleanup point as before.

The initial hypothesis was three fewer allocations for a recognized empty
body and four fewer for a wrapped body. The object contains unused body-wrapper
space on empty requests, but removes several other objects. It is not pooled.
The timer still calls the same context cancellation function and does not
capture the combined wrapper.

Body reads and response writes reset the same watchdog and apply the same
connection deadlines. EOF clears the read deadline; nil and `http.NoBody`
remain unwrapped. Context composition still copies the request once, preserves
origin metadata, and propagates parent cancellation. Stopping still stops the
timer and cancels the proxied context. Concurrent cleanup and progress retain
the existing timer semantics; this change does not introduce a new terminal
state that prevents a later progress call from resetting the timer.

`Header`, `WriteHeader`, `Write` and `Unwrap` still reach the original response
writer. Controller operations such as flushing continue through `Unwrap`.

## Validation coverage

New tests exercise empty-body identity, request-copy ownership, uploaded
contents, EOF deadline clearing, forwarding `Close`, repeated cleanup, parent
context isolation, status/header/body forwarding, flushing, and simultaneous
upload progress, response progress and cleanup. All proxy deadline tests
passed ten repetitions under the race detector.

Existing tests also exercise cancellation after idle time, progress keeping a
request alive, composed-context cancellation, slow uploads outliving the
server read timeout, and streaming responses outliving the server write
timeout. The latter two use real SSH forwarding.

## Measurements

Go 1.26.9, darwin/arm64, Apple M1 Pro, `GOMAXPROCS=8`, `CGO_ENABLED=0`,
`GOWORK=off`. Ten sequential samples per version, alternating version order
within pairs. Handler samples use 20,000 iterations per case. Profiling and
validation run separately from timing comparisons on this shared desktop.

The handler benchmark includes the real handler with an in-process backend,
but excludes TLS, SSH and logging. The unchanged relay harness includes
certificate-verified local TLS, HTTP/1.1 and HTTP/2, SSH forwarding, a TCP
backend and terminal logs delivered through the SSH session. Each relay
sample warms 16 requests and schedules 180 at 100/s with four workers: 90%
empty GETs returning 1 KiB, 10% POSTs uploading 16 KiB and returning 64 KiB.
It checks complete payloads, identities, status, protocol and every log.
Every exit status is retained; failures are not retried or replaced.

| Handler case | Allocations/request before → after |
| --- | ---: |
| GET, 1 KiB, IPv6 | 66 → 63 |
| GET, 1 KiB, IPv4 | 64 → 61 |
| GET, 64 KiB | 67 → 64 |
| POST, 16 KiB upload | 74 → 70 |
| Inspected response, 16 KiB or 15,000 bytes | 74 → 71 |
| Missing tunnel, control | 26 → 26 |

These counts were identical across all ten samples per version. Handler
elapsed-time differences were inconclusive except for uploads (7.827 →
7.630 µs, `p=0.023`). One result among several comparisons does not establish
a general latency improvement.

All 20 candidate protocol samples in the forwarding comparison passed. Three
baseline subcases failed the arrival-drop check: HTTP/1.1 sample 3 dropped 18
arrivals, HTTP/2 sample 5 dropped two, and HTTP/1.1 sample 6 dropped two. All
raw output and exit statuses are retained. These failures prevent treating
the successful-sample summaries as a complete before/after latency comparison.

| Full-process metric, median of successful samples | HTTP/1.1 before → after | HTTP/2 before → after |
| --- | ---: | ---: |
| Successful samples | 8 → 10 | 9 → 10 |
| Allocations/request | 238.8 → 239.5 | 269.4 → 265.3 |
| p50 latency | 1.603 → 1.605 ms | 1.745 → 1.746 ms |
| p95 latency | 3.073 → 4.016 ms | 5.544 → 5.368 ms |
| p99 latency | 5.722 → 7.369 ms | 9.096 → 9.469 ms |

The clients, backend and relay share the process, so these allocation totals
are not relay-only costs. HTTP/2 allocations fell 1.51% (`p<0.001` among
successful samples); HTTP/1.1 totals and allocated bytes were inconclusive.
No p50/p95/p99 difference was significant, but that does not establish equal
tails or rule out a regression. The full-path timing evidence is noisy and
incomplete. No general latency, CPU, RSS or capacity gain is claimed. The
fixed short-run arrival rate fits burst budgets and does not measure maximum
or sustainable throughput.

## Allocation attribution

Separate full-allocation profiles confirm the mechanism independently of
process-wide noise. In the handler profile, 2,001 GETs and 2,001 uploads
(including benchmark calibration) previously allocated 18,009 wrapper/controller
objects; the candidate allocated 4,002. This removes exactly three objects
per GET and four per upload.

Both instrumented TLS/SSH runs also passed, each forwarding 392 requests with
warmups. Setup's directly attributed wrapper/controller objects fell from
1,783 to 392, removing 1,391 objects. The fixture's HTTP/2 server requests have
non-`http.NoBody` bodies even for its empty GETs, so those still receive a body
wrapper and save four allocations. The HTTP/1.1 mix saves three per empty GET
and four per upload. Unrelated response-controller allocations remain.
Instrumented timings are excluded from the comparison.

## Checks and reproduction

The full race suite, vet, build and golangci-lint 2.14.0 passed. The opt-in
comparison had the baseline generator failures recorded above; it is not
reported as an entirely passing comparison. No commit or deployment was made.
Earlier uncommitted performance work is preserved.

The ignored directory [`.dev/deadlines-20261021`](../../.dev/deadlines-20261021/)
contains the incremental baseline snapshot, SHA-256 source manifest,
environment and binary hashes, raw measurements, profiles and validation logs.

- [Handler comparison](../../.dev/deadlines-20261021/handler-benchstat.txt),
  [TLS/SSH comparison](../../.dev/deadlines-20261021/relay-benchstat.txt), and
  [all exit statuses](../../.dev/deadlines-20261021/exits.json).
- [Alternating-run script](../../.dev/deadlines-20261021/compare.py),
  [profiling script](../../.dev/deadlines-20261021/profile.sh), and
  [environment and binary hashes](../../.dev/deadlines-20261021/environment.json).
- [Full-path deadline attribution before](../../.dev/deadlines-20261021/relay-before-deadlines.txt)
  and [after](../../.dev/deadlines-20261021/relay-after-deadlines.txt).

Build `./pkg/server` with `go test -c` in the saved baseline and candidate
checkouts, setting `GOWORK=off`, `GOTOOLCHAIN=go1.26.9`, and `CGO_ENABLED=0`.
Use identical handler and relay harnesses. Run sequentially with `GOMAXPROCS=8`,
alternating version order for ten pairs:

```sh
./server-before.test -test.run '^$' -test.bench '^BenchmarkRequestAllocations$' \
  -test.benchtime=20000x -test.count=1
TUNNL_PERF=1 TUNNL_PERF_JSON=0 ./server-before.test \
  -test.run '^TestRelayPerformance$' -test.v
```

Keep all failures and compare raw outputs with `benchstat`. Collect profiles
separately with `-test.memprofile=... -test.memprofilerate=1`; do not include
instrumented runs in timing comparisons.
