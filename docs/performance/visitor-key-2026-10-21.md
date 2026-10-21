# IPv6 visitor-key formatting — October 21, 2026

IPv6 rate-limit keys now use `netip.Prefix.AppendTo` with a local 42-byte
buffer, followed by one string conversion. This removes the intermediate
address string allocated by `Prefix.String`. The resulting key still uses
the masked `/64`; limits and address resolution are unchanged.

The preceding handler allocation profile identified two allocations per
IPv6 request in this formatting path. This change is deliberately small:
one fewer allocation for each request that reaches unzoned IPv6 visitor-key
construction. IPv4, mapped IPv4, and zoned IPv6 keep their existing paths.
There is no shared buffer, cache, pool, or additional retained state.

## Measurements

Go 1.26.9, darwin/arm64, Apple M1 Pro, `GOMAXPROCS=8`, `CGO_ENABLED=0`,
`GOWORK=off`. The baseline includes all preceding performance changes,
including connection-history reuse. It is a snapshot of the working tree,
not HEAD. Baseline and candidate use identical tests and benchmarks.

Ten sequential pairs per benchmark group alternated version order. Formatting
cases ran for 200 ms each; handler cases ran for 2,000 requests each. All 40
benchmark invocations passed. Profiling and full validation ran after timing.

| Case | Allocations before → after | Bytes before → after | Median time before → after |
| --- | ---: | ---: | ---: |
| IPv6 key (`2001:db8:1234:5678::1`) | 2 → 1 | 48 → 24 | 123.10 → 80.32 ns |
| IPv6 key (`::1`) | 2 → 1 | 8 → 5 | 144.7 → 107.2 ns |
| IPv4 key | 1 → 1 | 16 → 16 | No significant change |
| Mapped IPv4 key | 1 → 1 | 16 → 16 | No significant change |
| Zoned IPv6 key | 1 → 1 | 16 → 16 | No significant change |

Benchstat reports significant reductions for the two IPv6 formatting cases
(`p<0.001`). The byte saving depends on the formatted address length; it is
not universally 24 bytes. These are isolated formatting timings, not network
latency measurements.

The existing handler benchmark exercises the real request handler with an
in-process backend. Request and response-recorder construction are included
identically on both sides; tunnel setup is outside the timer.

| Handler case | Allocations per request before → after |
| --- | ---: |
| IPv6 GET, 1 KiB response | 63 → 62 |
| IPv6 GET, 64 KiB response | 64 → 63 |
| IPv6 upload, 16 KiB | 70 → 69 |
| IPv6 inspected response, 16 KiB | 71 → 70 |
| IPv6 inspected response, 15,000 bytes | 71 → 70 |
| IPv4 GET control | 61 → 61 |
| Missing-tunnel control | 26 → 26 |

Allocation counts were consistent across all samples. Separate full-sampling
allocation profiles attribute 4,002 objects to `visitorKeyAddr` before and
2,001 after over 2,001 IPv6 GETs (including the benchmark calibration request).
The candidate allocates only the final key string in this function.

Handler timings were noisy and showed no statistically significant changes.
Whole-handler allocated bytes also varied with unrelated buffer allocation.
No improvement in end-to-end latency, throughput, retained heap, or RSS is
claimed. The TLS/SSH performance fixture was not rerun for this local formatting
change; the full functional suite includes SSH forwarding and proxy tests.

## Correctness and validation

Compatibility tests compare the result with the previous `Prefix.String`
expression for invalid addresses, zero and maximum addresses, mapped IPv4,
zoned IPv6, and 1,000 deterministic random addresses with IPv4 and zoned
variants. They also verify that changing host bits preserves the key and
crossing the `/64` boundary changes it. Existing visitor-grouping and
rate-limit tests remain in place.

`go test -race ./...`, `go vet ./...`, `CGO_ENABLED=0 go build ./...`,
golangci-lint 2.14.0, and `git diff --check` passed. Earlier working-tree changes
and the unrelated `ROADMAP.md` are preserved. No commit or deployment was made.

## Reproduction and raw artifacts

The ignored [`.dev/visitor-key-20261021`](../../.dev/visitor-key-20261021/)
directory contains baseline/candidate source snapshots, the baseline hash
manifest, binary hashes and environment, raw samples, profiles, validation
output, and the alternating-pair runner.

- [Formatting comparison](../../.dev/visitor-key-20261021/format-benchstat.txt)
  and [handler comparison](../../.dev/visitor-key-20261021/handler-benchstat.txt).
- [Runner](../../.dev/visitor-key-20261021/compare.py) and
  [exit statuses](../../.dev/visitor-key-20261021/exits.json).
- [Allocation attribution before](../../.dev/visitor-key-20261021/allocs-before.txt)
  and [after](../../.dev/visitor-key-20261021/allocs-after.txt).

Build each snapshot's `./pkg/server` test binary with `go test -c`, using the
environment above. Run ten alternating pairs of:

```sh
GOMAXPROCS=8 ./server-before.test -test.run '^$' \
  -test.bench '^BenchmarkVisitorKeyFormatting$' -test.benchtime=200ms
GOMAXPROCS=8 ./server-before.test -test.run '^$' \
  -test.bench '^BenchmarkRequestAllocations$' -test.benchtime=2000x
```

Use the candidate binary for the other half of each pair. Collect separate
profiles of `BenchmarkRequestAllocations/GET1KiB$` with
`-test.memprofile=... -test.memprofilerate=1`; do not compare profiled timings.
