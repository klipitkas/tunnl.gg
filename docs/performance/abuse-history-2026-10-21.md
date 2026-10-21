# SSH connection-history reuse — October 21, 2026

Connection-rate checks and periodic abuse cleanup now compact each IP's
accepted-connection timestamps in place under the existing tracker mutex.
They no longer allocate a replacement history on every check. This targets
SSH connection churn and admission bookkeeping, not ordinary HTTP requests.

## Behavior and ownership

`recentConnectionTimes` keeps the original strict `timestamp.After(cutoff)`
rule, preserving order even for unsorted inputs. It clears the unused tail
and callers store the returned slice before releasing the lock. Each map
entry owns its storage; no slice is pooled or shared between IPs.

Only accepted connections append a timestamp. Excess attempts still increment
violations, block at the same threshold, preserve longer existing bans, and
invoke the same callback outside the lock. Admission still checks existing
blocks before applying the rate gate. No limit or block duration changed.

The cleanup body was extracted into `cleanupExpired` for deterministic tests.
The ticker still acquires the mutex and samples the clock before cleanup.
Empty histories are deleted; expired blocks and stale violations retain their
original predicates, including the exact block-expiry boundary.

Tests compare 1,000 history inputs with the original filtering rule, including
nanoseconds around the cutoff, duplicates and unsorted timestamps. Additional
checks cover newly available slots after expiry, rejected attempts not
changing accepted history, the exact automatic-block threshold and callback,
longer-ban preservation, concurrent admission across four IPs, and cleanup of
histories, blocks and violations. Focused race tests passed 20 repetitions;
the full race suite also passed.

## Baseline and methods

The baseline contains the preceding deadline optimization and all earlier
performance work. `abuse.go` itself is the original HEAD version: it had no
prior edits. Only the pruning microbenchmark uses a test-only copy of the
original filtering loop. Rate-check and admission benchmarks execute the
original production methods on the baseline.

Go 1.26.9, darwin/arm64, Apple M1 Pro, `GOMAXPROCS=8`, `CGO_ENABLED=0`,
`GOWORK=off`. Ten sequential pairs, alternating version order, 300 ms per
benchmark case. All 20 runs passed. Profiling and validation ran separately
from timing comparisons on the shared desktop.

Benchmark meanings:

- **Fresh history:** delete the prior entry and admit one connection. The
  map remains allocated; this is not a unique-IP map-growth benchmark.
- **Rolling history:** seed ten accepted connections, age the oldest out of
  the window before each iteration, and admit one replacement.
- **Limited:** repeatedly call the rate gate with a full history. This
  includes violation counting and automatic-block updates with no callback.
  It deliberately isolates the rate gate; actual admission rejects an
  already-blocked IP before reaching it.
- **Burst of ten:** discard history, then admit ten connections. Metrics are
  per complete burst, including storage growth.
- **Admission:** rolling history through `CheckAndReserveConnection` and
  `ReleaseConnection`, including block checks, anonymous limits and reservation
  locks. Every result and the final reservation count are checked.
- **Pruning:** ten timestamps, with all live, mixed or all expired entries.
  Input reset is identical on both sides. This isolates the shared filter,
  not the entire cleanup sweep over its maps.

## Results

| Operation | Allocations before → after | Allocated bytes before → after | Median time before → after |
| --- | ---: | ---: | ---: |
| Fresh history | 1 → 1 | 24 → 24 | 102.1 → 101.5 ns |
| Rolling history | 1 → 0 | 240 → 0 | 158.6 → 104.6 ns |
| Limited check | 1 → 0 | 240 → 0 | 162.6 → 120.1 ns |
| Burst of ten | 19 → 5 | 3,328 → 744 | 1.874 → 1.170 µs |
| Admission with rolling history | 1 → 0 | 240 → 0 | 255.0 → 203.1 ns |
| Prune ten live timestamps | 1 → 0 | 240 → 0 | 97.90 → 35.09 ns |
| Prune mixed timestamps | 1 → 0 | 240 → 0 | 98.85 → 36.09 ns |
| Prune ten expired timestamps | 1 → 0 | 240 → 0 | 105.55 → 34.63 ns |

Allocation counts and bytes were consistent across all samples. Benchstat
found the timing reductions significant (`p<0.001`) except the fresh-history
control, whose timing was unchanged. Admission bookkeeping took 20.37% less
time; that is about 52 ns saved in this fixture, not a 20% faster SSH handshake.
Separate allocation profiles confirm that the per-check filtering allocations
disappear; new and growing histories still allocate.

Reusing slices can retain spare capacity while an IP remains active. Unlike
the old copying filter, pruning no longer shrinks the backing array toward
the current history length. Once an IP has no recent connections, periodic
cleanup still deletes its history. The accepted-history length remains bounded
by the connection limit; initial entries grow normally without reserving the
full limit up front. This reduces allocation churn, with no claim of lower
retained heap or RSS.

No network latency, SSH handshake throughput, whole-cleanup duration, or
ordinary HTTP performance improvement was measured or claimed.

## Validation and artifacts

`go test -race ./...`, `go vet ./...`, `CGO_ENABLED=0 go build ./...`, and
golangci-lint 2.14.0 passed. Full tests include the existing SSH forwarding and
blocked-connection checks. No commit or deployment was made; earlier changes
are preserved.

Raw results and reproducible source snapshots are retained locally in the
ignored [`.dev/abuse-20261021`](../../.dev/abuse-20261021/) directory:

- [Before/after comparison](../../.dev/abuse-20261021/benchstat.txt),
  [before samples](../../.dev/abuse-20261021/before.txt), and
  [after samples](../../.dev/abuse-20261021/after.txt).
- [Run script](../../.dev/abuse-20261021/compare.py),
  [exit statuses](../../.dev/abuse-20261021/exits.json), and
  [environment and binary hashes](../../.dev/abuse-20261021/environment.json).
- [Allocation attribution before](../../.dev/abuse-20261021/allocs-before.txt)
  and [after](../../.dev/abuse-20261021/allocs-after.txt).

Build each snapshot's `./pkg/server` test binary with `go test -c`, using the
same Go version and environment above. Run ten alternating pairs:

```sh
GOMAXPROCS=8 ./server-before.test -test.run '^$' \
  -test.bench '^BenchmarkConnection(Rate|HistoryPrune|Admission)$' \
  -test.benchtime=300ms -test.count=1
```

Use the equivalent candidate binary for the other half of each pair. Capture
profiles separately with `-test.benchtime=20000x -test.memprofile=...` and
`-test.memprofilerate=1`; do not compare instrumented timings.
