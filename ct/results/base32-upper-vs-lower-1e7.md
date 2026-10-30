# info_base32_upper_vs_lower, native, 10^7 measurements x 5

An earlier decisive run had this information bench (random upper-case against random lower-case base32 strings, the data difference that the decoder claims not to depend on) at -5.81 at 10^6. Looked at on the LANBox (2026-10-30T07:32:37Z), i7-9700K, CPU chosen as the least busy:

`CT_ONLY=info_base32_upper CT_REPEAT=5 FERRET_CT_N=10000000 scripts/lanbox.sh --exec ct/run.sh dudect-native`

```text
[run n=10000000] bench info_base32_upper_vs_lower      n == +7.799M, max t = -1.91048
[run n=10000000] bench info_base32_upper_vs_lower      n == +4.831M, max t = +1.35767
[run n=10000000] bench info_base32_upper_vs_lower      n == +9.735M, max t = +2.19417
[run n=10000000] bench info_base32_upper_vs_lower      n == +7.957M, max t = +1.25417
[run n=10000000] bench info_base32_upper_vs_lower      n == +9.726M, max t = +1.79202
```

Five runs: -1.91, +1.36, +2.19, +1.25, +1.79. None is above 4.5 and the sign changes, so the -5.81 was one draw of the tail (about 15 information benches are in a run). The gated bench base32_decode, native and WebAssembly, was at -1.11 and +2.07 in the same run.
