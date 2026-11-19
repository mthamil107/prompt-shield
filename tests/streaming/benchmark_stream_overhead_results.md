# StreamGuard overhead benchmark

- Timestamp: 2026-11-19 10:04:22 UTC
- Platform: win32 (AMD64, Intel64 Family 6 Model 197 Stepping 2, GenuineIntel)
- Python: 3.14.2 (tags/v3.14.2:df79316, Dec  5 2025, 17:18:21) [MSC v.1944 64 bit (AMD64)]
- Optional extras importable: transformers: yes, optimum: no
- Fixture: 100 benign chunks of 20 chars; warmup 3, iterations 20; fresh guard per iteration
- Guard config: `StreamGuard(mode="flag")`, default stream-safe scanner set

| variant | median us/100 chunks | p95 us/100 chunks | min us/100 chunks | median delta us/chunk | p95 delta us/chunk |
|---|---:|---:|---:|---:|---:|
| raw_passthrough | 1.6 | 2.2 | 1.4 | 0.00 | 0.00 |
| stream_guard_flag | 22321.8 | 60523.4 | 18966.9 | 223.20 | 605.21 |

Median guarded/raw ratio: 14401.2x.

Per-chunk overhead: median 223.20 us, p95 605.21 us on Windows AMD64. Informational only; not a release gate.
