# Decisive dudect run on the build host

Written by `scripts/lanbox-ct.sh all` (2026-11-25T06:44:28Z). The limit is
|t| < 4.5 after 1000000 measurements; a bench over 4.5 is measured again with ten
times as many, except at 10^7 or more, where it fails. Every line of the two outputs is
below, runs and reruns included.

- commit: `7f304d38dcba29456519e5e4740d02b8d219119a`
- exit status of the run: 0
- measurements per bench: 1000000

## Native

```text
dudect native: n=1000000 per bench (rerun with 10000000 when |t| >= 4.5), cpu=0, 2026-11-25T05:49:25Z
host: 9278fb79249d, model name	: Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz
rustc: rustc 1.99.1 (58cf8f9c3 2026-10-13)
profile: opt-level s (ct/dudect/Cargo.toml), lto, codegen-units 1, panic abort, overflow checks
load: 1.93 1.87 1.77 1/619 9269
timed-asm stored_for: 14 lines, conditional jumps 0
timed-asm choose_answer: 26 lines, conditional jumps 0
timed-asm pick_account: 5 lines, conditional jumps 0
timed-asm Finish::prepare: 101 lines, mask loops (xor, and, xor) 1, pand 0
[run n=1000000] bench control_null                            ... : n == +0.998M, max t = +2.10985, max tau = +0.00211, (5/tau)^2 = 5602617
[ok] control_null
[run n=1000000] bench control_leaky                           ... : n == +0.615M, max t = +68994.71390, max tau = +87.96712, (5/tau)^2 = 0
[ok] control_leaky: the setup sees an early-exit comparison
[run n=1000000] bench control_unpad_leaky                     ... : n == +0.616M, max t = -71058.89102, max tau = -90.55226, (5/tau)^2 = 0
[ok] control_unpad_leaky: the setup sees an early-exit comparison
[run n=1000000] bench commit_check                            ... : n == +0.721M, max t = +2.21564, max tau = +0.00261, (5/tau)^2 = 3671043
[ok] commit_check
[run n=1000000] bench mac_verify                              ... : n == +0.592M, max t = +2.68121, max tau = +0.00349, (5/tau)^2 = 2057380
[ok] mac_verify
[run n=1000000] bench key_eq                                  ... : n == +0.229M, max t = +2.08839, max tau = +0.00436, (5/tau)^2 = 1312954
[ok] key_eq
[run n=1000000] bench crockford_decode                        ... : n == +0.154M, max t = +2.96311, max tau = +0.00756, (5/tau)^2 = 437339
[ok] crockford_decode
[run n=1000000] bench unpad_ct                                ... : n == +0.999M, max t = +2.18340, max tau = +0.00218, (5/tau)^2 = 5238617
[ok] unpad_ct
[run n=1000000] bench base32_decode                           ... : n == +0.021M, max t = +2.71595, max tau = +0.01853, (5/tau)^2 = 72813
[ok] base32_decode
[run n=1000000] bench kek_pw_commit_path                      ... : n == +0.582M, max t = -1.41119, max tau = -0.00185, (5/tau)^2 = 7302753
[ok] kek_pw_commit_path
[run n=1000000] bench info_unwrap_valid_vs_bad_commit         ... : n == +0.692M, max t = +34789.36741, max tau = +41.83554, (5/tau)^2 = 0
[info] info_unwrap_valid_vs_bad_commit is reported, not gated
[run n=1000000] bench kek_pin_commit_path                     ... : n == +1.000M, max t = +2.01885, max tau = +0.00202, (5/tau)^2 = 6133837
[ok] kek_pin_commit_path
[run n=1000000] bench info_unwrap_pin_valid_vs_bad_commit     ... : n == +0.646M, max t = +37087.80350, max tau = +46.15793, (5/tau)^2 = 0
[info] info_unwrap_pin_valid_vs_bad_commit is reported, not gated
[run n=1000000] bench info_unpad_position_zeros               ... : n == +0.998M, max t = -1.83732, max tau = -0.00184, (5/tau)^2 = 7389143
[info] info_unpad_position_zeros is reported, not gated
[run n=1000000] bench info_unpad_content                      ... : n == +0.999M, max t = -2.27863, max tau = -0.00228, (5/tau)^2 = 4809166
[info] info_unpad_content is reported, not gated
[run n=1000000] bench info_unpad_random_pair                  ... : n == +0.380M, max t = +1.39020, max tau = +0.00226, (5/tau)^2 = 4912638
[info] info_unpad_random_pair is reported, not gated
[run n=1000000] bench info_unpad_same                         ... : n == +0.231M, max t = -2.25654, max tau = -0.00469, (5/tau)^2 = 1134533
[info] info_unpad_same is reported, not gated
[run n=1000000] bench info_base32_a_vs_z                      ... : n == +0.887M, max t = +7.00757, max tau = +0.00744, (5/tau)^2 = 451414
[info] info_base32_a_vs_z is reported, not gated
[run n=1000000] bench info_base32_upper_vs_lower              ... : n == +0.516M, max t = -5.11616, max tau = -0.00712, (5/tau)^2 = 492502
[info] info_base32_upper_vs_lower is reported, not gated
[run n=1000000] bench info_base32_random_pair                 ... : n == +0.989M, max t = +5.82896, max tau = +0.00586, (5/tau)^2 = 727922
[info] info_base32_random_pair is reported, not gated
[run n=1000000] bench server_login_start_known_vs_unknown     ... : n == +0.188M, max t = -1.43553, max tau = -0.00331, (5/tau)^2 = 2275377
[ok] server_login_start_known_vs_unknown
[run n=1000000] bench server_login_start_known_vs_disabled    ... : n == +0.956M, max t = -2.67026, max tau = -0.00273, (5/tau)^2 = 3351196
[ok] server_login_start_known_vs_disabled
[run n=1000000] bench control_server_login_start_null         ... : n == +0.835M, max t = -3.65639, max tau = -0.00400, (5/tau)^2 = 1561443
[ok] control_server_login_start_null
[run n=1000000] bench control_server_prelogin_null            ... : n == +0.995M, max t = -2.19263, max tau = -0.00220, (5/tau)^2 = 5173269
[ok] control_server_prelogin_null
[run n=1000000] bench control_server_finish_null              ... : n == +0.418M, max t = +1.82982, max tau = +0.00283, (5/tau)^2 = 3119667
[ok] control_server_finish_null
[run n=1000000] bench info_server_login_start_lookup_only     ... : n == +0.242M, max t = +1.69480, max tau = +0.00345, (5/tau)^2 = 2105351
[info] info_server_login_start_lookup_only is reported, not gated
[run n=1000000] bench info_server_login_start_real_vs_made_up ... : n == +0.823M, max t = +1.58612, max tau = +0.00175, (5/tau)^2 = 8179863
[info] info_server_login_start_real_vs_made_up is reported, not gated
[run n=1000000] bench info_server_login_start_fixed_vs_pool   ... : n == +0.242M, max t = -1.76510, max tau = -0.00359, (5/tau)^2 = 1942542
[info] info_server_login_start_fixed_vs_pool is reported, not gated
[run n=1000000] bench server_prelogin_known_vs_unknown        ... : n == +0.374M, max t = +2.33600, max tau = +0.00382, (5/tau)^2 = 1714260
[ok] server_prelogin_known_vs_unknown
[run n=1000000] bench info_server_prelogin_resolve_credential ... : n == +0.883M, max t = +1.48275, max tau = +0.00158, (5/tau)^2 = 10041203
[info] info_server_prelogin_resolve_credential is reported, not gated
[run n=1000000] bench server_state_binding                    ... : n == +0.646M, max t = -1.97365, max tau = -0.00246, (5/tau)^2 = 4145216
[ok] server_state_binding
[run n=1000000] bench server_finish_credential_vs_account     ... : n == +0.999M, max t = -1.62244, max tau = -0.00162, (5/tau)^2 = 9487368
[ok] server_finish_credential_vs_account
[run n=1000000] bench info_server_finish_state_vs_missing     ... : n == +0.665M, max t = +41445.44315, max tau = +50.80896, (5/tau)^2 = 0
[info] info_server_finish_state_vs_missing is reported, not gated
load at the end: 1.13 1.09 1.21 1/618 9744
```

## WebAssembly in Node (wasm-opt -Oz)

```text
dudect wasm in Node: {"node":"v22.23.4","v8":"12.4.254.21-node.57","measurements":1000000,"cpu":"1","host":"9278fb79249d","imports":["__wbindgen_placeholder__.__wbindgen_describe","__wbindgen_externref_xform__.__wbindgen_externref_table_grow","__wbindgen_externref_xform__.__wbindgen_externref_table_set_null"]}, 2026-11-25T06:13:17.461Z
module: ct/results/wasm/ferret_ct_opt.wasm, 130854 bytes, targets: commit_check mac_verify key_eq crockford_decode unpad_ct info_unpad_position_zeros info_unpad_content info_unpad_random_pair info_unpad_same base32_decode info_base32_a_vs_z info_base32_upper_vs_lower info_base32_random_pair kek_pw_commit_path info_unwrap_valid_vs_bad_commit kek_pin_commit_path info_unwrap_pin_valid_vs_bad_commit control_unpad_leaky control_null control_leaky
[run n=1000000] bench control_null                     ... : n == 0.243M, max t = +2.39747
[ok] control_null
[run n=1000000] bench control_unpad_leaky              ... : n == 0.535M, max t = -143574.18716
[ok] control_unpad_leaky: the setup sees an early-exit comparison
[run n=1000000] bench control_leaky                    ... : n == 0.541M, max t = +86359.66386
[ok] control_leaky: the setup sees an early-exit comparison
[run n=1000000] bench commit_check                     ... : n == 0.595M, max t = -1.77216
[ok] commit_check
[run n=1000000] bench mac_verify                       ... : n == 0.623M, max t = -1.46766
[ok] mac_verify
[run n=1000000] bench key_eq                           ... : n == 1.000M, max t = +2.20671
[ok] key_eq
[run n=1000000] bench crockford_decode                 ... : n == 0.086M, max t = -1.56134
[ok] crockford_decode
[run n=1000000] bench unpad_ct                         ... : n == 0.989M, max t = +1.59179
[ok] unpad_ct
[run n=1000000] bench info_unpad_position_zeros        ... : n == 0.996M, max t = +2.24729
[info] info_unpad_position_zeros is reported, not gated
[run n=1000000] bench info_unpad_content               ... : n == 0.132M, max t = -1.29155
[info] info_unpad_content is reported, not gated
[run n=1000000] bench info_unpad_random_pair           ... : n == 0.991M, max t = -2.07943
[info] info_unpad_random_pair is reported, not gated
[run n=1000000] bench info_unpad_same                  ... : n == 0.994M, max t = -1.49583
[info] info_unpad_same is reported, not gated
[run n=1000000] bench base32_decode                    ... : n == 0.578M, max t = -3.55945
[ok] base32_decode
[run n=1000000] bench info_base32_a_vs_z               ... : n == 0.749M, max t = +2.46296
[info] info_base32_a_vs_z is reported, not gated
[run n=1000000] bench info_base32_upper_vs_lower       ... : n == 0.999M, max t = +2.05694
[info] info_base32_upper_vs_lower is reported, not gated
[run n=1000000] bench info_base32_random_pair          ... : n == 0.609M, max t = +4.68096
[info] info_base32_random_pair is reported, not gated
[run n=1000000] bench kek_pw_commit_path               ... : n == 0.994M, max t = -2.47029
[ok] kek_pw_commit_path
[run n=1000000] bench info_unwrap_valid_vs_bad_commit  ... : n == 0.533M, max t = +229057.63039
[info] info_unwrap_valid_vs_bad_commit is reported, not gated
[run n=1000000] bench kek_pin_commit_path              ... : n == 0.190M, max t = -1.80648
[ok] kek_pin_commit_path
[run n=1000000] bench info_unwrap_pin_valid_vs_bad_commit ... : n == 0.565M, max t = +203189.08931
[info] info_unwrap_pin_valid_vs_bad_commit is reported, not gated
```

