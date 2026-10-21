# Response accounting consolidation — October 21, 2026

The proxy's status writer and response-size limiter now live inside the
existing per-request callback state. Successful responses allocate one object
for these three pieces of state instead of three. Their methods, response
limits, and error handling are unchanged; nothing is pooled or reused across
requests.

## Evidence and measurements

The preceding handler allocation profile showed separate allocations for
callback state, `statusCaptureWriter`, and `limitedReadCloser` on every
successful proxied request. The baseline for this change includes all earlier
optimizations, including IPv6 visitor-key formatting. Both versions use
identical benchmarks and the new lifecycle tests.

Go 1.26.9, darwin/arm64, Apple M1 Pro, `GOMAXPROCS=8`, `CGO_ENABLED=0`,
`GOWORK=off`. Ten sequential before/after pairs alternated version order,
running 10,000 iterations per handler case. All 20 invocations passed.
Profiling and validation ran separately after timing.

| Handler case | Allocations per request before → after |
| --- | ---: |
| IPv6 GET, 1 KiB response | 62 → 60 |
| IPv4 GET, 1 KiB response | 61 → 59 |
| IPv6 GET, 64 KiB response | 63 → 61 |
| IPv6 upload, 16 KiB | 69 → 67 |
| IPv6 inspected response, 16 KiB | 70 → 68 |
| IPv6 inspected response, 15,000 bytes | 70 → 68 |
| Missing-tunnel control | 26 → 26 |

Counts were consistent across all samples. The benchmark invokes the real
handler with an in-process backend; it includes request and response-recorder
construction, with tunnel setup outside the timer.

Separate full-sampling allocation profiles over 2,001 IPv6 GETs (including
calibration) attribute 6,003 objects to these three pieces of state before,
and 2,001 objects to the combined state after. The old allocations occupy
64 + 48 + 48 bytes per successful request; the combined object occupies 144
bytes, saving 16 bytes as well as two allocations on this platform.

Handler timing differences were not statistically significant. Whole-handler
allocated bytes include unrelated buffer allocation and were less consistent
than the counts. No end-to-end latency, throughput, retained-heap, or RSS
improvement is claimed.

## Ownership and failure-path tradeoff

The writer and body limiter already share the callback state's request
lifetime. References now point to fields of that state; the state is never
copied after those references are taken. The deferred accounting still runs
on normal returns and panics. Before a response body is installed, the limiter
has a nil error, which gives the same cutoff explanation as the former nil
pointer.

On paths that fail before installing a response body, the combined object
reserves storage that was previously allocated only on success. For these
three pieces of state, that changes 112 bytes in two allocations to 144 bytes
in one allocation: 32 extra bytes for fewer objects. Early local responses,
such as a missing tunnel, never create this state and are unchanged. Optional
upload counting remains separately allocated only when a request has a body.

## Correctness and validation

The new lifecycle tests pass on both baseline and candidate. They exercise
known and unknown response lengths, declared oversized responses, backend
failure before a response, an upstream read failure, and a failed visitor
write. Assertions cover response status, exact body-close counts, expected
`http.ErrAbortHandler` propagation, successful payloads, and inspector status,
body capture, and failure explanations. Existing size-limit tests cover exact
and exceeded limits; existing tests cover request logs and writer behavior.

One baseline and one candidate run of the real TLS/SSH fixture both passed
HTTP/1.1 and HTTP/2. Each version completed 392 requests including warmup,
checking complete payloads, uploads, status, protocol, request IDs, and log
delivery. These runs validate integration; one run per version is insufficient
for a network performance claim.

The full `go test -race ./...` suite, `go vet ./...`,
`CGO_ENABLED=0 go build ./...`, golangci-lint 2.14.0, and `git diff --check`
passed. Earlier changes and the unrelated `ROADMAP.md` are preserved.
No commit or deployment was made.

## Reproduction and artifacts

The ignored [`.dev/response-state-20261021`](../../.dev/response-state-20261021/)
directory contains baseline/candidate source snapshots, a baseline hash
manifest, environment and binary hashes, raw samples, profiles, and validation
output.

- [Benchmark comparison](../../.dev/response-state-20261021/benchstat.txt),
  [runner](../../.dev/response-state-20261021/compare.py), and
  [exit statuses](../../.dev/response-state-20261021/exits.json).
- Allocation attribution [before](../../.dev/response-state-20261021/alloc_objects-before.txt)
  and [after](../../.dev/response-state-20261021/alloc_objects-after.txt).
- TLS/SSH output [before](../../.dev/response-state-20261021/relay-before.txt)
  and [after](../../.dev/response-state-20261021/relay-after.txt).

Build each snapshot's `./pkg/server` binary with `go test -c` in the environment
above. Run ten alternating pairs of:

```sh
GOMAXPROCS=8 ./server-before.test -test.run '^$' \
  -test.bench '^BenchmarkRequestAllocations$' -test.benchtime=10000x
```

Use the candidate binary for the other half of each pair. Collect separate
profiles of `BenchmarkRequestAllocations/GET1KiB$` with `-test.benchtime=2000x`,
`-test.memprofile=...`, and `-test.memprofilerate=1`.
