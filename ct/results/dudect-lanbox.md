# Decisive dudect run on the LANBox

Written by `scripts/lanbox-ct.sh all` (2026-10-30T05:53:00Z). Plan section 10 point 5:
|t| < 4.5 after 10^6 measurements, a bench over 4.5 measured again with 10^7. Every
line of the two outputs is below, runs and reruns included.

- commit: `0afddb90471ff92648e3767d7cdda161e4f6ee33 (with uncommitted changes)`
- exit status of the run: 0 for every check (`scripts/lanbox.sh` returned 2 only because `tar` warned about a clock difference of 0.2 s between the LANBox and this PC when it unpacked the results; the export now ignores that warning)
- measurements per bench: 1000000

## Native

```text
dudect native: n=1000000 per bench (rerun with 10000000 when |t| >= 4.5), cpu=1, 2026-10-30T05:35:21Z
host: 3b85320f1128, model name	: Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz
rustc: rustc 1.99.1 (58cf8f9c3 2026-10-13)
load: 1.89 1.24 1.47 1/1123 4231
[run n=1000000] bench control_null                    ... : n == +0.050M, max t = +2.16715, max tau = +0.00973, (5/tau)^2 = 263966
[ok] control_null
[run n=1000000] bench control_leaky                   ... : n == +0.683M, max t = +78073.21945, max tau = +94.47713, (5/tau)^2 = 0
[ok] control_leaky: the setup sees an early-exit comparison
[run n=1000000] bench control_unpad_leaky             ... : n == +0.532M, max t = -49896.88694, max tau = -68.39221, (5/tau)^2 = 0
[ok] control_unpad_leaky: the setup sees an early-exit comparison
[run n=1000000] bench commit_check                    ... : n == +0.999M, max t = +2.90787, max tau = +0.00291, (5/tau)^2 = 2953258
[ok] commit_check
[run n=1000000] bench mac_verify                      ... : n == +0.527M, max t = +2.58265, max tau = +0.00356, (5/tau)^2 = 1974032
[ok] mac_verify
[run n=1000000] bench key_eq                          ... : n == +0.782M, max t = +2.80511, max tau = +0.00317, (5/tau)^2 = 2484941
[ok] key_eq
[run n=1000000] bench crockford_decode                ... : n == +1.000M, max t = +3.09997, max tau = +0.00310, (5/tau)^2 = 2601512
[ok] crockford_decode
[run n=1000000] bench unpad_ct                        ... : n == +0.112M, max t = -1.69322, max tau = -0.00505, (5/tau)^2 = 978371
[ok] unpad_ct
[run n=1000000] bench base32_decode                   ... : n == +0.869M, max t = +2.78878, max tau = +0.00299, (5/tau)^2 = 2792415
[ok] base32_decode
[run n=1000000] bench kek_pw_commit_path              ... : n == +0.810M, max t = +2.80257, max tau = +0.00311, (5/tau)^2 = 2578516
[ok] kek_pw_commit_path
[run n=1000000] bench info_unwrap_valid_vs_bad_commit ... : n == +0.767M, max t = +39117.30061, max tau = +44.67300, (5/tau)^2 = 0
[info] info_unwrap_valid_vs_bad_commit is reported, not gated
[run n=1000000] bench info_unpad_position_zeros       ... : n == +0.693M, max t = -3.03638, max tau = -0.00365, (5/tau)^2 = 1878991
[info] info_unpad_position_zeros is reported, not gated
[run n=1000000] bench info_unpad_content              ... : n == +0.999M, max t = -1.98206, max tau = -0.00198, (5/tau)^2 = 6357463
[info] info_unpad_content is reported, not gated
[run n=1000000] bench info_unpad_random_pair          ... : n == +0.459M, max t = -4.76750, max tau = -0.00703, (5/tau)^2 = 505360
[info] info_unpad_random_pair is reported, not gated
[run n=1000000] bench info_unpad_same                 ... : n == +0.998M, max t = -3.35271, max tau = -0.00336, (5/tau)^2 = 2219074
[info] info_unpad_same is reported, not gated
[run n=1000000] bench info_base32_a_vs_z              ... : n == +0.993M, max t = +1.40747, max tau = +0.00141, (5/tau)^2 = 12533554
[info] info_base32_a_vs_z is reported, not gated
[run n=1000000] bench info_base32_upper_vs_lower      ... : n == +0.994M, max t = +2.56845, max tau = +0.00258, (5/tau)^2 = 3766576
[info] info_base32_upper_vs_lower is reported, not gated
[run n=1000000] bench info_base32_random_pair         ... : n == +0.038M, max t = +1.21415, max tau = +0.00625, (5/tau)^2 = 639530
[info] info_base32_random_pair is reported, not gated
```

## WebAssembly in Node (wasm-opt -Oz)

```text
dudect wasm in Node: {"node":"v22.23.4","v8":"12.4.254.21-node.57","measurements":1000000,"cpu":"2","host":"3b85320f1128","imports":["__wbindgen_placeholder__.__wbindgen_describe","__wbindgen_externref_xform__.__wbindgen_externref_table_grow","__wbindgen_externref_xform__.__wbindgen_externref_table_set_null"]}, 2026-10-30T05:36:26.155Z
module: ct/results/wasm/ferret_ct_opt.wasm, 128487 bytes, targets: commit_check mac_verify key_eq crockford_decode unpad_ct info_unpad_position_zeros info_unpad_content info_unpad_random_pair info_unpad_same base32_decode info_base32_a_vs_z info_base32_upper_vs_lower info_base32_random_pair kek_pw_commit_path info_unwrap_valid_vs_bad_commit control_unpad_leaky control_null control_leaky
[run n=1000000] bench control_null                     ... : n == 0.784M, max t = +1.77360
[ok] control_null
[run n=1000000] bench control_unpad_leaky              ... : n == 0.875M, max t = -143407.68854
[ok] control_unpad_leaky: the setup sees an early-exit comparison
[run n=1000000] bench control_leaky                    ... : n == 0.778M, max t = +60283.73735
[ok] control_leaky: the setup sees an early-exit comparison
[run n=1000000] bench commit_check                     ... : n == 0.811M, max t = +2.18472
[ok] commit_check
[run n=1000000] bench mac_verify                       ... : n == 0.999M, max t = +2.75794
[ok] mac_verify
[run n=1000000] bench key_eq                           ... : n == 0.622M, max t = -2.14013
[ok] key_eq
[run n=1000000] bench crockford_decode                 ... : n == 0.996M, max t = +2.23120
[ok] crockford_decode
[run n=1000000] bench unpad_ct                         ... : n == 0.692M, max t = -2.90353
[ok] unpad_ct
[run n=1000000] bench info_unpad_position_zeros        ... : n == 0.695M, max t = -2.71054
[info] info_unpad_position_zeros is reported, not gated
[run n=1000000] bench info_unpad_content               ... : n == 0.993M, max t = -1.95640
[info] info_unpad_content is reported, not gated
[run n=1000000] bench info_unpad_random_pair           ... : n == 0.193M, max t = +2.85600
[info] info_unpad_random_pair is reported, not gated
[run n=1000000] bench info_unpad_same                  ... : n == 0.783M, max t = -2.76696
[info] info_unpad_same is reported, not gated
[run n=1000000] bench base32_decode                    ... : n == 0.204M, max t = +1.35084
[ok] base32_decode
[run n=1000000] bench info_base32_a_vs_z               ... : n == 0.672M, max t = -2.08996
[info] info_base32_a_vs_z is reported, not gated
[run n=1000000] bench info_base32_upper_vs_lower       ... : n == 0.390M, max t = +1.93373
[info] info_base32_upper_vs_lower is reported, not gated
[run n=1000000] bench info_base32_random_pair          ... : n == 0.389M, max t = +2.05662
[info] info_base32_random_pair is reported, not gated
[run n=1000000] bench kek_pw_commit_path               ... : n == 0.131M, max t = -1.63358
[ok] kek_pw_commit_path
[run n=1000000] bench info_unwrap_valid_vs_bad_commit  ... : n == 0.732M, max t = +116918.84388
[info] info_unwrap_valid_vs_bad_commit is reported, not gated
```

