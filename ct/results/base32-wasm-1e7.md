# WebAssembly base32_decode at 10^7 measurements

Run on the LANBox (2026-10-30T06:50:47Z) on the wasm-opt -Oz module of ct/dudect, with the 8 repetitions inside a measurement that the runner uses for short targets:

`CT_ONLY=base32_decode CT_REPEAT=5 FERRET_CT_N=10000000 scripts/lanbox.sh --exec ct/run.sh dudect-wasm`

Why: with one repetition per measurement the bench gave |t| of 5 to 14 in some runs at 10^6 to 10^8 (see ct/TRIAGE.md R7); the fix was first shown at 10^6, and the gate reruns at 10^7. Five runs, host Intel i7-9700K, CPU chosen as the least busy; every gated line is below 4.5 and none needed a rerun.

```text
dudect wasm in Node: {"node":"v22.23.4","v8":"12.4.254.21-node.57","measurements":10000000,"cpu":"3","host":"132dfebce4f7","imports":["__wbindgen_placeholder__.__wbindgen_describe","__wbindgen_externr
[run n=10000000] bench base32_decode                    n == 8.605M, max t = +1.41554
[ok] base32_decode
[run n=10000000] bench base32_decode                    n == 2.464M, max t = +1.35120
[ok] base32_decode
[run n=10000000] bench base32_decode                    n == 4.746M, max t = -2.59918
[ok] base32_decode
[run n=10000000] bench base32_decode                    n == 9.006M, max t = -1.57221
[ok] base32_decode
[run n=10000000] bench base32_decode                    n == 8.876M, max t = +1.79256
[ok] base32_decode
```

Also, the native unpad bench after the allocation order of the two classes was randomised (LANBox, same day): unpad_ct 10^6 x 5: -2.33, +1.44, +2.11, +1.87, -2.00; info_unpad_random_pair 10^7 x 5: +2.33, -2.02, +1.88, -2.66, +1.91; info_unpad_same 10^7 x 5: -2.33, -1.61, -1.77, -1.78, +3.24.
