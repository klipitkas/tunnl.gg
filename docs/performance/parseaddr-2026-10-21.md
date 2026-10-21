# Visitor-address parser selection — October 21, 2026

Visitor-address parsing now selects `netip.ParseAddr` or `netip.ParseAddrPort`
from the input syntax. Previously every bare address in a forwarding header
first incurred a failed address-and-port parse, allocating an error before
the successful address parse. The previous forwarding-chain profile attributed
three such allocations to each three-hop request.

IPv4 with a port has one colon; IPv6 with a port must start with a bracket.
Other inputs go directly to the address parser. Validation still uses Go's
standard parsers, and IPv4-mapped addresses are still unmapped. No trust rules,
proxy configuration, header handling, or public APIs changed.

## Baseline and method

The baseline contains all preceding performance changes, including direct
right-to-left XFF scanning. Tests and benchmarks are identical in both
versions. Go 1.26.9, darwin/arm64, Apple M1 Pro, `GOMAXPROCS=8`,
`CGO_ENABLED=0`, `GOWORK=off`.

Ten sequential pairs per group alternated version order: 150 ms per parser
or resolver case, and 10,000 iterations per handler case. All 60 invocations
passed. Profiles, fuzzing, and validation ran separately after timing.

## Results and tradeoff

| Parser input | Allocations before → after | Bytes before → after | Median time before → after |
| --- | ---: | ---: | ---: |
| Bare IPv4 | 1 → 0 | 16 → 0 | 48.69 → 29.62 ns |
| Bare IPv6 | 1 → 0 | 48 → 0 | 90.61 → 43.48 ns |
| Mapped IPv4 | 4 → 0 | 144 → 0 | 348.50 → 50.76 ns |
| Zoned IPv6 | 4 → 0 | 120 → 0 | 287.05 → 66.08 ns |
| IPv4 with port | 0 → 0 | 0 → 0 | 37.90 → 42.69 ns |
| IPv6 with port | 0 → 0 | 0 → 0 | No significant change |
| Malformed `not-an-ip` | 2 → 1 | 64 → 48 | 55.12 → 35.49 ns |

These measurements use specific inputs recorded in `BenchmarkParseAddr`.
The zoned-address case repeats a warmed fixed zone; it does not establish
zero allocation for previously unseen zones. Invalid inputs can still allocate
parser errors.

Selecting the parser adds work for an already valid address-and-port input.
IPv4-with-port parsing took about 4.8 ns more, a statistically significant
12.63% increase in that isolated helper (`p<0.001`). This is an explicit
tradeoff for avoiding the failed parse on forwarded addresses. The direct
resolver control and direct-request handler cases showed no statistically
significant timing change.

The public resolver benchmarks include peer parsing and trust checks:

| Resolver fixture | Allocations before → after | Bytes before → after |
| --- | ---: | ---: |
| Single XFF visitor | 1 → 0 | 16 → 0 |
| Three-hop XFF chain | 3 → 0 | 48 → 0 |
| Three XFF header lines | 3 → 0 | 48 → 0 |
| Long unused prefix, two examined hops | 2 → 0 | 32 → 0 |
| 32 trusted hops | 32 → 0 | 512 → 0 |
| Malformed XFF entry | 3 → 1 | 80 → 48 |
| Untrusted peer control | 0 → 0 | 0 → 0 |
| Cloudflare visitor | 2 → 1 | 32 → 16 |

The three-hop resolver median fell from 429.1 to 361.1 ns (`p=0.001`). The
32-hop case fell from 1.683 to 1.141 µs (`p<0.001`). Resolver gains are not
claims about complete network requests.

In the real handler with an in-process backend, a three-hop trusted-proxy GET
with a 1 KiB response fell from **65 to 62 allocations**. Direct IPv6 remained
at 60 and direct IPv4 at 59. Counts were consistent across all samples.
Request and recorder creation are included identically, with tunnel setup
outside timing. No handler timing difference was statistically significant.

Separate full-sampling profiles over 2,001 trusted-proxy requests (including
calibration) show 6,003 error allocations under `parseAddr` before and none
after. Resolver configuration allocations remain outside the request path.
There is no claim of lower retained heap, RSS, end-to-end latency, or increased
network throughput.

## Compatibility and validation

A test-only copy of the original parser is the differential fuzz oracle.
Seeds cover IPv4 and IPv6, mapped IPv4, bracket rules, zero and maximum ports,
port overflow, signs and leading zeros, malformed inputs, whitespace, zones,
and punctuation within zones. The forwarding-chain oracle also now uses the
original parser, checking both optimizations together against the old behavior.

Two four-worker fuzz runs, each requested for 15 seconds, passed:

- Parser compatibility: 985,255 executions.
- Complete forwarding-chain compatibility: 1,416,639 executions.

Existing resolver tests independently assert expected visitors and proxy trust
boundaries. The full `go test -race ./...` suite passed, including server
integration tests for on-prem proxies, Cloudflare visitor resolution, and
visitor rate limiting. `go vet ./...`, `CGO_ENABLED=0 go build ./...`,
golangci-lint 2.14.0, and `git diff --check` also passed.

Earlier working-tree changes and unrelated `ROADMAP.md` are preserved.
No commit or deployment was made.

## Reproduction and artifacts

The ignored [`.dev/parseaddr-20261021`](../../.dev/parseaddr-20261021/) directory
contains baseline/candidate snapshots, source and binary hashes, environment,
raw benchmark samples, profiles, and validation output.

- [Parser comparison](../../.dev/parseaddr-20261021/parser-benchstat.txt),
  [resolver comparison](../../.dev/parseaddr-20261021/resolver-benchstat.txt),
  and [handler comparison](../../.dev/parseaddr-20261021/handler-benchstat.txt).
- [Runner](../../.dev/parseaddr-20261021/compare.py) and
  [exit statuses](../../.dev/parseaddr-20261021/exits.json).
- Allocation profiles [before](../../.dev/parseaddr-20261021/alloc_objects-before.txt)
  and [after](../../.dev/parseaddr-20261021/alloc_objects-after.txt).
- Fuzz output for [parser](../../.dev/parseaddr-20261021/fuzz-parser.txt)
  and [forwarding chain](../../.dev/parseaddr-20261021/fuzz-forwarded.txt).

Build `./pkg/clientip` and `./pkg/server` test binaries from each snapshot with
`go test -c` in the environment above, then use `compare.py` for ten alternating
pairs. Fuzz with:

```sh
GOMAXPROCS=4 go test ./pkg/clientip -run '^$' \
  -fuzz '^FuzzParseAddrCompatibility$' -fuzztime=15s -parallel=4
GOMAXPROCS=4 go test ./pkg/clientip -run '^$' \
  -fuzz '^FuzzForwardedForCompatibility$' -fuzztime=15s -parallel=4
```
