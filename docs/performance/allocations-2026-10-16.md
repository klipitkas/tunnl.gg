# Request allocation improvements — October 16, 2026

Compared with engine `5a47138`, this change removes work repeated by ordinary
HTTP requests without changing admission limits or tuning the garbage collector.

## Changes

- Ready tunnels return their current options without creating a timeout context
  or timer. Requests still wait up to 15 seconds during initial negotiation,
  and closed tunnels and canceled requests remain refused. Saved account
  options are read on every request, so updates remain immediate.
- Security headers are added when tunnl generates an error, redirect or
  preflight response, rather than added and then deleted on every proxied
  response. The tunneled app's headers and proxy defaults retain their behavior.
- The resolved visitor address is formatted once for normal forwarding and
  logging. The HTTP rate-limit path derives IPv6 grouping from the parsed
  address rather than converting through strings and parsing again. Existing
  IPv4, mapped IPv4, scoped-address and IPv6 /64 behavior is preserved.
- Empty bodies retain `http.NoBody` and avoid size-limit, capture and deadline
  wrappers. Real uploads, including unknown-length uploads, retain size limits.
- Finished inspector captures transfer their buffer into the recorded exchange
  instead of copying it. The snapshot API still copies. Subsequent capture
  reads cannot overwrite transferred data. Inspector retention now counts
  buffer capacity, including spare storage, against its 1 MiB body budget.
  This may release an older body earlier than length-only accounting; the
  latest 50 exchange records are still retained. The history layout is unchanged.

## Local measurement

Go 1.26.9, darwin/arm64, Apple M1 Pro, default benchmark GOMAXPROCS of 8.
`GOWORK=off` was set for both versions. The baseline was extracted from the
unchanged commit into an isolated directory and given the exact same benchmark.

`BenchmarkRequestAllocations` exercises the real `Server.ServeHTTP` and
`httputil.ReverseProxy` paths with an in-process backend. Request construction
and the recording response writer are included in both versions. It checks
status and response size, and the backend checks upload size. Tunnel setup is
excluded from measurement and repeated every 100 requests to avoid measuring
rate-limit rejections. The inspector fills its history and exceeds its byte
budget within each such batch.

These are local handler measurements, not production allocation rates or
capacity estimates. There is no TLS, SSH, socket traffic or request logger in
the timed path. In particular, the recorder buffers response bodies and makes
the 64 KiB case's byte totals much larger than a streaming production writer.

Each case ran 20,000 iterations per sample, with ten samples per version.
Run order was baseline/candidate/candidate/baseline, five samples per group,
to reduce order effects. Values below are medians; byte medians are rounded.
IPv6 visitors were used except for the explicitly labeled IPv4 case.

| Request | Allocations before → after | Bytes before → after | Bytes change | Time before → after |
|---|---:|---:|---:|---:|
| GET, 1 KiB response | 98 → 82 | 11,988 → 11,347 | −5.3% | 8.50 → 7.27 µs |
| GET, 1 KiB, IPv4 | 96 → 80 | 11,900 → 11,282 | −5.2% | 8.06 → 6.99 µs |
| GET, 64 KiB response | 101 → 85 | 110,004 → 109,332 | −0.6% | 23.21 → 21.89 µs |
| POST, 16 KiB upload | 111 → 97 | 12,695 → 12,126 | −4.5% | 9.92 → 8.77 µs |
| Inspected, 16 KiB response | 109 → 90 | 62,118 → 44,796 | −27.9% | 18.87 → 14.43 µs |
| Inspected, 15,000-byte response | 109 → 90 | 62,136 → 44,804 | −27.9% | 18.75 → 14.58 µs |
| Missing tunnel, HTTP 404 | 27 → 26 | 6,645 → 6,581 | −1.0% | 2.46 → 2.46 µs |

Ordinary GETs save 16 allocations, uploads save 14, and inspected GETs save
19 in this harness. Local median handler time improved about 13–14% for small
GETs and 22–24% for inspected responses. Timing on a developer machine remains
subject to scheduling noise; the allocation reductions are the primary result.
These percentages must not be presented as production throughput improvements.

Reproduce from each checkout, using the same benchmark file and toolchain:

```sh
GOWORK=off go test ./pkg/server -run '^$' \
  -bench '^BenchmarkRequestAllocations$' -benchtime=20000x -count=5
```

Private raw outputs are under `.dev/allocations-20261016/` in the development
checkout. No live load test or production configuration change was needed.

## Validation

Regression coverage includes initial options waiting and timeouts, live saved
options, cancellation, closed tunnels, visitor grouping, local security headers,
bodyless read deadlines, unknown-length upload limits, capture ownership and
retained-capacity accounting. Existing real SSH end-to-end tests also cover
forwarding headers, app headers, streaming, slow uploads, WebSockets and
inspector replay.

The complete engine race suite, `go vet ./...`, `go build ./...`, and
golangci-lint 2.14.0 passed with `GOWORK=off`. The cloud application's complete
race suite also passed using a temporary module-file replacement pointing at
this engine checkout. Its committed dependency pin was not changed. Production
was not deployed as part of this local optimization pass.

## Follow-up allocation audit (isolated prototypes only)

A fresh allocation profile of the updated code, recording every allocation,
plus compiler escape analysis identified additional avoidable work. The
`ReverseProxy` value itself does not escape; its callback closures and six
separately captured variables do. Four of those variables hold inspector state
and allocate even when inspection is disabled.

Prototypes were tested through Go's `-overlay` mechanism under
`.dev/allocations-20261016/remaining/`. They have not been applied to the source
changes described above or deployed.

| Candidate | Measured additional saving |
|---|---:|
| Group the captured request variables into one per-request struct | 5 allocations/request |
| Create the upload counter only for actual bodies | 1 allocation/bodyless request |
| Return on nil before declaring the error-unwrapping target | 1 allocation/successful request |
| Skip `SplitHostPort` for ordinary hostnames without a port | 1 allocation/request on this path |
| Use the canonical `Cf-Connecting-Ip` spelling when deleting the header | 1 allocation/direct request on this path |
| Store optional JSON numeric values inside their encoding record and encode its pointer | JSON logging: 4 → 2 allocations/event; 320 → 184 bytes/event |

For the request prototypes, a deadline-capable recorder was used on both sides.
The original recorder returns unsupported-operation errors from deadline
calls, adding allocations that must not be mistaken for production work.
Both test writers remain simplified models of real HTTP writers. This audit's
absolute counts therefore differ from the earlier table; compare within a
single harness only. Fixture setup and recording allocations are still present.

Three 20,000-iteration samples per version yielded:

| Case | Updated source | Four small fixes | Plus grouped callback state |
|---|---:|---:|---:|
| IPv6 GET | 77 allocs/op | 73 | 68 |
| IPv4 GET | 75 allocs/op | 71 | 66 |
| Upload | 84 allocs/op | 81 | 76 |

The combined request prototype passed the server race suite. The independent
JSON prototype passed the tunnel race suite, retaining the existing encoder
and optional-field behavior. Its benchmark waits for every log write, so
queue drops cannot account for the improvement; three 30,000-event samples
all reported the same allocation and byte counts. No timing or production
capacity claim is made for this exploratory audit.

Other candidates remain unmeasured: the activity guard's closure and
`sync.Once` allocate twice per request; deadline setup has several separately
allocated wrapper objects; WebSocket copies allocate a 32 KiB buffer in each
direction per connection; abuse tracking copies its timestamp slice on each
SSH connection check. Buffer reuse would reduce WebSocket connection churn,
not the memory needed for simultaneously active connections. These should be
prioritized after the measured candidates and preserve cancellation, idempotent
completion and abuse-limit behavior.
