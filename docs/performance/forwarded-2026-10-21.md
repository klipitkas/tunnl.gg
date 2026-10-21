# Forwarded visitor-chain scanning — October 21, 2026

Requests arriving through configured `X-Forwarded-For` proxies now scan header
values directly from right to left. Previously the resolver split every line
into a slice and flattened all hops before examining the trusted suffix.
The new scan removes those temporary slices and avoids scanning unused entries
to the left of the first untrusted address.

This affects generic trusted-proxy deployments. Direct connections and the
dedicated Cloudflare `CF-Connecting-IP` path are unchanged. Proxy configuration,
address parsing, trust checks, malformed-entry behavior, and public APIs are
unchanged. No caching, pooling, or persistent state was introduced.

## Baseline and method

The baseline contains all preceding performance work, including response-state
consolidation. Both versions contain the same new benchmarks and compatibility
tests. Source snapshots and binary hashes are retained locally.

Go 1.26.9, darwin/arm64, Apple M1 Pro, `GOMAXPROCS=8`, `CGO_ENABLED=0`,
`GOWORK=off`. Ten sequential pairs per benchmark group alternated version order.
Resolver cases ran for 150 ms each; handler cases ran for 10,000 iterations
each. All 40 invocations passed. Profiling, fuzzing, and validation ran after
timing comparisons.

Resolver benchmarks call the public `Resolve` method, including peer parsing
and trust checks. Headers are constructed outside timing. Each fixture checks
the expected visitor address before timing.

## Results

| Resolver fixture | Allocations before → after | Bytes before → after |
| --- | ---: | ---: |
| One visitor | 3 → 1 | 48 → 16 |
| Visitor plus two trusted proxies | 5 → 3 | 144 → 48 |
| Three header lines | 9 → 3 | 272 → 48 |
| 1,024 unused entries before visitor and trusted proxy | 4 → 2 | 36,896 → 32 |
| 32 trusted hops | 34 → 32 | 1,536 → 512 |
| Malformed entry after a trusted hop | 5 → 3 | 176 → 80 |
| Untrusted peer control | 0 → 0 | 0 → 0 |
| Cloudflare control | 2 → 2 | 32 → 32 |

Allocation counts and bytes were consistent across all samples. Address
parsing still allocates; removing the hop slices does not make the entire
resolver allocation-free.

The long-unused-prefix fixture's median resolver time fell from 23.172 µs to
444.3 ns (`p<0.001`). This deliberately stresses the discarded-prefix work;
it is not representative of ordinary short chains. The multiple-header
fixture fell from 736.8 to 537.6 ns (`p=0.001`). Other resolver timing changes
were not statistically significant. The shared machine showed substantial
timing variation, including in unchanged control paths.

The full handler benchmark, using an in-process backend, confirms the saving
for a three-hop trusted-proxy request:

| GET with 1 KiB response | Allocations before → after |
| --- | ---: |
| Trusted proxy, three-hop XFF | 67 → 65 |
| Direct IPv6 control | 60 → 60 |
| Direct IPv4 control | 59 → 59 |

Request and recorder construction are included identically on both sides;
tunnel setup is outside timing. No handler timing change was statistically
significant. Whole-handler bytes include unrelated buffer allocation and are
less stable than counts.

A separate full-sampling profile over 2,001 trusted-proxy GETs (including
calibration) attributes 10,005 objects to the forwarding-chain resolver before
and 6,003 after. The 4,002 split/append objects disappear; the 6,003 address
parser allocations remain. This confirms the source of the two-object saving
in the handler, rather than attributing unrelated changes to this patch.

No end-to-end latency, network throughput, retained-heap, or RSS gain is
claimed. This change was not tested with a production traffic distribution.

## Compatibility and validation

A test-only copy of the original split-and-flatten implementation serves as
the oracle for differential fuzzing. Seeds cover empty entries, leading and
trailing commas, malformed entries, multiple header lines, empty middle
lines, fully trusted chains, Cloudflare hops, IPv6 with ports and zones,
mapped IPv4, and Unicode whitespace. Both implementations must return the
same address for every generated input.

A 15-second, four-worker fuzz run completed 1,404,357 executions with no
mismatch. Existing resolver tests independently assert trust boundaries,
spoofed-header rejection, multiple-header order, missing headers, and nil
resolver behavior. The full race suite includes the server's SSH forwarding
tests for on-prem proxies, Cloudflare resolution, and visitor rate limiting.

`go test -race ./...`, `go vet ./...`, `CGO_ENABLED=0 go build ./...`,
golangci-lint 2.14.0, and `git diff --check` passed. Earlier working-tree changes
and the unrelated `ROADMAP.md` are preserved. No commit or deployment was made.

## Reproduction and raw evidence

The ignored [`.dev/forwarded-20261021`](../../.dev/forwarded-20261021/) directory
contains baseline/candidate sources, a baseline manifest, environment and
binary hashes, raw samples, profiles, and validation output.

- [Resolver comparison](../../.dev/forwarded-20261021/resolver-benchstat.txt)
  and [handler comparison](../../.dev/forwarded-20261021/handler-benchstat.txt).
- [Runner](../../.dev/forwarded-20261021/compare.py),
  [exit statuses](../../.dev/forwarded-20261021/exits.json), and
  [fuzz output](../../.dev/forwarded-20261021/fuzz.txt).
- Allocation attribution [before](../../.dev/forwarded-20261021/alloc_objects-before.txt)
  and [after](../../.dev/forwarded-20261021/alloc_objects-after.txt).

Build `./pkg/clientip` and `./pkg/server` test binaries from each snapshot with
`go test -c` in the environment above. Run ten alternating pairs:

```sh
GOMAXPROCS=8 ./clientip-before.test -test.run '^$' \
  -test.bench '^BenchmarkForwardedFor$' -test.benchtime=150ms
GOMAXPROCS=8 ./server-before.test -test.run '^$' \
  -test.bench '^BenchmarkRequestAllocations/GET1KiB(IPv4|TrustedProxy)?$' \
  -test.benchtime=10000x
```

Use candidate binaries for the other half of each pair. Run compatibility
fuzzing with:

```sh
GOMAXPROCS=4 go test ./pkg/clientip -run '^$' \
  -fuzz '^FuzzForwardedForCompatibility$' -fuzztime=15s -parallel=4
```
