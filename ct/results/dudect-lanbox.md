# Decisive dudect run on the LANBox

Written by `scripts/lanbox-ct.sh all` (2026-10-30T07:11:22Z). The limit is
|t| < 4.5 after 10^6 measurements, a bench over 4.5 measured again with 10^7. Every
line of the two outputs is below, runs and reruns included.

- commit: `5bf5d5011fef3a1a7a7bf86e7eacd014f0e7c212`
- exit status of the run: 0
- measurements per bench: 1000000

## Native

```text
dudect native: n=1000000 per bench (rerun with 10000000 when |t| >= 4.5), cpu=1, 2026-10-30T06:52:46Z
host: ec260f6debfd, model name	: Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz
rustc: rustc 1.99.1 (58cf8f9c3 2026-10-13)
load: 5.84 3.60 2.14 2/1222 4442
[run n=1000000] bench control_null                    ... : n == +0.996M, max t = +2.15290, max tau = +0.00216, (5/tau)^2 = 5372709
[ok] control_null
[run n=1000000] bench control_leaky                   ... : n == +0.531M, max t = +68382.47429, max tau = +93.88070, (5/tau)^2 = 0
[ok] control_leaky: the setup sees an early-exit comparison
[run n=1000000] bench control_unpad_leaky             ... : n == +0.581M, max t = -71023.27819, max tau = -93.14226, (5/tau)^2 = 0
[ok] control_unpad_leaky: the setup sees an early-exit comparison
[run n=1000000] bench commit_check                    ... : n == +0.903M, max t = +1.83189, max tau = +0.00193, (5/tau)^2 = 6728051
[ok] commit_check
[run n=1000000] bench mac_verify                      ... : n == +0.999M, max t = -1.37925, max tau = -0.00138, (5/tau)^2 = 13128068
[ok] mac_verify
[run n=1000000] bench key_eq                          ... : n == +0.948M, max t = +1.80792, max tau = +0.00186, (5/tau)^2 = 7254654
[ok] key_eq
[run n=1000000] bench crockford_decode                ... : n == +0.998M, max t = +1.71994, max tau = +0.00172, (5/tau)^2 = 8433176
[ok] crockford_decode
[run n=1000000] bench unpad_ct                        ... : n == +0.844M, max t = +1.77935, max tau = +0.00194, (5/tau)^2 = 6664648
[ok] unpad_ct
[run n=1000000] bench base32_decode                   ... : n == +0.995M, max t = -1.10837, max tau = -0.00111, (5/tau)^2 = 20244054
[ok] base32_decode
[run n=1000000] bench kek_pw_commit_path              ... : n == +0.999M, max t = +2.22394, max tau = +0.00223, (5/tau)^2 = 5049390
[ok] kek_pw_commit_path
[run n=1000000] bench info_unwrap_valid_vs_bad_commit ... : n == +0.565M, max t = +20939.43614, max tau = +27.86429, (5/tau)^2 = 0
[info] info_unwrap_valid_vs_bad_commit is reported, not gated
[run n=1000000] bench info_unpad_position_zeros       ... : n == +0.419M, max t = +2.75281, max tau = +0.00425, (5/tau)^2 = 1382389
[info] info_unpad_position_zeros is reported, not gated
[run n=1000000] bench info_unpad_content              ... : n == +0.668M, max t = -2.18953, max tau = -0.00268, (5/tau)^2 = 3484320
[info] info_unpad_content is reported, not gated
[run n=1000000] bench info_unpad_random_pair          ... : n == +0.726M, max t = +2.58346, max tau = +0.00303, (5/tau)^2 = 2721248
[info] info_unpad_random_pair is reported, not gated
[run n=1000000] bench info_unpad_same                 ... : n == +0.956M, max t = +3.18879, max tau = +0.00326, (5/tau)^2 = 2349544
[info] info_unpad_same is reported, not gated
[run n=1000000] bench info_base32_a_vs_z              ... : n == +0.966M, max t = +2.70671, max tau = +0.00275, (5/tau)^2 = 3297983
[info] info_base32_a_vs_z is reported, not gated
[run n=1000000] bench info_base32_upper_vs_lower      ... : n == +0.860M, max t = -5.80894, max tau = -0.00626, (5/tau)^2 = 637306
[info] info_base32_upper_vs_lower is reported, not gated
[run n=1000000] bench info_base32_random_pair         ... : n == +0.818M, max t = -2.81036, max tau = -0.00311, (5/tau)^2 = 2588596
[info] info_base32_random_pair is reported, not gated
```

## WebAssembly in Node (wasm-opt -Oz)

```text
dudect wasm in Node: {"node":"v22.23.4","v8":"12.4.254.21-node.57","measurements":1000000,"cpu":"3","host":"ec260f6debfd","imports":["__wbindgen_placeholder__.__wbindgen_describe","__wbindgen_externref_xform__.__wbindgen_externref_table_grow","__wbindgen_externref_xform__.__wbindgen_externref_table_set_null"]}, 2026-10-30T06:53:59.943Z
module: ct/results/wasm/ferret_ct_opt.wasm, 129107 bytes, targets: commit_check mac_verify key_eq crockford_decode unpad_ct info_unpad_position_zeros info_unpad_content info_unpad_random_pair info_unpad_same base32_decode info_base32_a_vs_z info_base32_upper_vs_lower info_base32_random_pair kek_pw_commit_path info_unwrap_valid_vs_bad_commit control_unpad_leaky control_null control_leaky
[run n=1000000] bench control_null                     ... : n == 0.998M, max t = -3.29768
[ok] control_null
[run n=1000000] bench control_unpad_leaky              ... : n == 0.594M, max t = -67182.56656
[ok] control_unpad_leaky: the setup sees an early-exit comparison
[run n=1000000] bench control_leaky                    ... : n == 0.500M, max t = +29507.35687
[ok] control_leaky: the setup sees an early-exit comparison
[run n=1000000] bench commit_check                     ... : n == 0.130M, max t = +1.92138
[ok] commit_check
[run n=1000000] bench mac_verify                       ... : n == 0.969M, max t = +1.61601
[ok] mac_verify
[run n=1000000] bench key_eq                           ... : n == 0.996M, max t = +2.44293
[ok] key_eq
[run n=1000000] bench crockford_decode                 ... : n == 0.503M, max t = +2.55714
[ok] crockford_decode
[run n=1000000] bench unpad_ct                         ... : n == 0.131M, max t = -1.80838
[ok] unpad_ct
[run n=1000000] bench info_unpad_position_zeros        ... : n == 0.534M, max t = +1.45535
[info] info_unpad_position_zeros is reported, not gated
[run n=1000000] bench info_unpad_content               ... : n == 0.650M, max t = +2.85393
[info] info_unpad_content is reported, not gated
[run n=1000000] bench info_unpad_random_pair           ... : n == 0.534M, max t = -1.63798
[info] info_unpad_random_pair is reported, not gated
[run n=1000000] bench info_unpad_same                  ... : n == 0.293M, max t = +2.67404
[info] info_unpad_same is reported, not gated
[run n=1000000] bench base32_decode                    ... : n == 0.912M, max t = +2.07175
[ok] base32_decode
[run n=1000000] bench info_base32_a_vs_z               ... : n == 0.860M, max t = +2.31886
[info] info_base32_a_vs_z is reported, not gated
[run n=1000000] bench info_base32_upper_vs_lower       ... : n == 0.788M, max t = -1.35384
[info] info_base32_upper_vs_lower is reported, not gated
[run n=1000000] bench info_base32_random_pair          ... : n == 0.962M, max t = -3.56807
[info] info_base32_random_pair is reported, not gated
[run n=1000000] bench kek_pw_commit_path               ... : n == 0.243M, max t = +1.40852
[ok] kek_pw_commit_path
[run n=1000000] bench info_unwrap_valid_vs_bad_commit  ... : n == 0.565M, max t = +90388.47895
[info] info_unwrap_valid_vs_bad_commit is reported, not gated
```

