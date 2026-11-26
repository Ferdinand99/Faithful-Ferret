# Decisive dudect run on the build host

Written by `scripts/lanbox-ct.sh dudect-native` (2026-11-26T16:26:46Z). The limit is
|t| < 4.5 after 1000000 measurements; a bench over 4.5 is measured again with ten
times as many, except at 10^7 or more, where it fails. Every line of the two outputs is
below, runs and reruns included.

- commit: `1afbd2634526bfa6606c6445209c0b038a9f489f`
- exit status of the run: 0
- measurements per bench: 1000000
- machine: Intel Core i7-9700K at 3.6 GHz, 6 cores and 32 GB RAM given to the build VM; the load average was 1.05 at the start of the native run and 1.08 at the end (one core is the pinned bench itself); nothing else of Ferret was running
- the native section is a rerun of `dudect-native` at this commit. The first full run (`all`, started on d1fcf063 with these benches added) was marked NOT DECISIVE because the load of its own build (2.43) was above 2 at the start; its native t-values were all under 4.5 too (passkey_import_jwk +3.00, passkey_import_pkcs8 +1.96). The WebAssembly section below is from that first full run (same bench code; the commit in between only changed `ct/run.sh`, which now waits for the load of the build to fall before it measures)

## Native

```text
dudect native: n=1000000 per bench (rerun with 10000000 when |t| >= 4.5), cpu=0, 2026-11-26T15:29:33Z
host: c893101501af, model name	: Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz
rustc: rustc 1.99.1 (58cf8f9c3 2026-10-13)
profile: opt-level s (ct/dudect/Cargo.toml), lto, codegen-units 1, panic abort, overflow checks
load: 1.05 0.85 0.92 1/619 1608
timed-asm stored_for: 14 lines, conditional jumps 0
timed-asm choose_answer: 26 lines, conditional jumps 0
timed-asm pick_account: 5 lines, conditional jumps 0
timed-asm Finish::prepare: 101 lines, mask loops (xor, and, xor) 1, pand 0
[run n=1000000] bench control_null                            ... : n == +0.999M, max t = -2.18707, max tau = -0.00219, (5/tau)^2 = 5220683
[ok] control_null
[run n=1000000] bench control_leaky                           ... : n == +0.610M, max t = +72832.44755, max tau = +93.23551, (5/tau)^2 = 0
[ok] control_leaky: the setup sees an early-exit comparison
[run n=1000000] bench control_unpad_leaky                     ... : n == +0.631M, max t = -80486.38659, max tau = -101.34606, (5/tau)^2 = 0
[ok] control_unpad_leaky: the setup sees an early-exit comparison
[run n=1000000] bench commit_check                            ... : n == +0.995M, max t = +2.13582, max tau = +0.00214, (5/tau)^2 = 5454012
[ok] commit_check
[run n=1000000] bench mac_verify                              ... : n == +0.749M, max t = +2.35198, max tau = +0.00272, (5/tau)^2 = 3383543
[ok] mac_verify
[run n=1000000] bench key_eq                                  ... : n == +0.282M, max t = -1.93573, max tau = -0.00364, (5/tau)^2 = 1884550
[ok] key_eq
[run n=1000000] bench crockford_decode                        ... : n == +0.985M, max t = +2.16694, max tau = +0.00218, (5/tau)^2 = 5245124
[ok] crockford_decode
[run n=1000000] bench base64url_decode                        ... : n == +0.990M, max t = +2.11156, max tau = +0.00212, (5/tau)^2 = 5551192
[ok] base64url_decode
[run n=1000000] bench passkey_import_jwk                      ... : n == +0.999M, max t = +1.33623, max tau = +0.00134, (5/tau)^2 = 13982145
[ok] passkey_import_jwk
[run n=1000000] bench passkey_import_pkcs8                    ... : n == +0.713M, max t = +0.89695, max tau = +0.00106, (5/tau)^2 = 22150526
[ok] passkey_import_pkcs8
[run n=1000000] bench unpad_ct                                ... : n == +0.999M, max t = +2.80364, max tau = +0.00281, (5/tau)^2 = 3176943
[ok] unpad_ct
[run n=1000000] bench base32_decode                           ... : n == +0.083M, max t = +1.29242, max tau = +0.00449, (5/tau)^2 = 1241665
[ok] base32_decode
[run n=1000000] bench kek_pw_commit_path                      ... : n == +0.559M, max t = -1.34921, max tau = -0.00180, (5/tau)^2 = 7681254
[ok] kek_pw_commit_path
[run n=1000000] bench info_unwrap_valid_vs_bad_commit         ... : n == +0.692M, max t = +38598.78248, max tau = +46.40380, (5/tau)^2 = 0
[info] info_unwrap_valid_vs_bad_commit is reported, not gated
[run n=1000000] bench kek_pin_commit_path                     ... : n == +0.710M, max t = -1.82494, max tau = -0.00217, (5/tau)^2 = 5330276
[ok] kek_pin_commit_path
[run n=1000000] bench info_unwrap_pin_valid_vs_bad_commit     ... : n == +0.669M, max t = +38353.39111, max tau = +46.90260, (5/tau)^2 = 0
[info] info_unwrap_pin_valid_vs_bad_commit is reported, not gated
[run n=1000000] bench info_unpad_position_zeros               ... : n == +0.662M, max t = +2.11009, max tau = +0.00259, (5/tau)^2 = 3717790
[info] info_unpad_position_zeros is reported, not gated
[run n=1000000] bench info_unpad_content                      ... : n == +0.110M, max t = -2.28732, max tau = -0.00689, (5/tau)^2 = 526961
[info] info_unpad_content is reported, not gated
[run n=1000000] bench info_unpad_random_pair                  ... : n == +0.951M, max t = +2.06910, max tau = +0.00212, (5/tau)^2 = 5552400
[info] info_unpad_random_pair is reported, not gated
[run n=1000000] bench info_unpad_same                         ... : n == +0.160M, max t = +1.73083, max tau = +0.00433, (5/tau)^2 = 1332766
[info] info_unpad_same is reported, not gated
[run n=1000000] bench info_base32_a_vs_z                      ... : n == +0.988M, max t = +3.23138, max tau = +0.00325, (5/tau)^2 = 2365797
[info] info_base32_a_vs_z is reported, not gated
[run n=1000000] bench info_base32_upper_vs_lower              ... : n == +0.995M, max t = -12.12166, max tau = -0.01215, (5/tau)^2 = 169351
[info] info_base32_upper_vs_lower is reported, not gated
[run n=1000000] bench info_base32_random_pair                 ... : n == +0.972M, max t = -1.37887, max tau = -0.00140, (5/tau)^2 = 12778695
[info] info_base32_random_pair is reported, not gated
[run n=1000000] bench server_login_start_known_vs_unknown     ... : n == +0.978M, max t = +2.41417, max tau = +0.00244, (5/tau)^2 = 4194691
[ok] server_login_start_known_vs_unknown
[run n=1000000] bench server_login_start_known_vs_disabled    ... : n == +0.533M, max t = +1.29258, max tau = +0.00177, (5/tau)^2 = 7975650
[ok] server_login_start_known_vs_disabled
[run n=1000000] bench control_server_login_start_null         ... : n == +0.918M, max t = -2.28240, max tau = -0.00238, (5/tau)^2 = 4403279
[ok] control_server_login_start_null
[run n=1000000] bench control_server_prelogin_null            ... : n == +0.126M, max t = +2.37731, max tau = +0.00669, (5/tau)^2 = 559249
[ok] control_server_prelogin_null
[run n=1000000] bench control_server_finish_null              ... : n == +0.991M, max t = +1.71948, max tau = +0.00173, (5/tau)^2 = 8379622
[ok] control_server_finish_null
[run n=1000000] bench info_server_login_start_lookup_only     ... : n == +0.564M, max t = -1.82924, max tau = -0.00244, (5/tau)^2 = 4216212
[info] info_server_login_start_lookup_only is reported, not gated
[run n=1000000] bench info_server_login_start_real_vs_made_up ... : n == +0.066M, max t = -2.99519, max tau = -0.01162, (5/tau)^2 = 185221
[info] info_server_login_start_real_vs_made_up is reported, not gated
[run n=1000000] bench info_server_login_start_fixed_vs_pool   ... : n == +0.990M, max t = -2.14886, max tau = -0.00216, (5/tau)^2 = 5358263
[info] info_server_login_start_fixed_vs_pool is reported, not gated
[run n=1000000] bench server_prelogin_known_vs_unknown        ... : n == +0.994M, max t = +1.50703, max tau = +0.00151, (5/tau)^2 = 10937823
[ok] server_prelogin_known_vs_unknown
[run n=1000000] bench info_server_prelogin_resolve_credential ... : n == +0.500M, max t = +3.78539, max tau = +0.00535, (5/tau)^2 = 872255
[info] info_server_prelogin_resolve_credential is reported, not gated
[run n=1000000] bench server_state_binding                    ... : n == +0.850M, max t = -1.86576, max tau = -0.00202, (5/tau)^2 = 6106481
[ok] server_state_binding
[run n=1000000] bench server_finish_credential_vs_account     ... : n == +0.994M, max t = +2.10798, max tau = +0.00211, (5/tau)^2 = 5592791
[ok] server_finish_credential_vs_account
[run n=1000000] bench info_server_finish_state_vs_missing     ... : n == +0.727M, max t = +41086.73838, max tau = +48.19092, (5/tau)^2 = 0
[info] info_server_finish_state_vs_missing is reported, not gated
load at the end: 1.08 1.08 1.03 1/619 2122
```

## WebAssembly in Node (wasm-opt -Oz)

```text
dudect wasm in Node: {"node":"v22.23.4","v8":"12.4.254.21-node.57","measurements":1000000,"cpu":"0","host":"36014c0c2422","imports":["__wbindgen_placeholder__.__wbindgen_describe","__wbindgen_externref_xform__.__wbindgen_externref_table_grow","__wbindgen_externref_xform__.__wbindgen_externref_table_set_null"]}, 2026-11-26T13:00:00.387Z
module: ct/results/wasm/ferret_ct_opt.wasm, 549212 bytes, targets: commit_check mac_verify key_eq crockford_decode base64url_decode passkey_import_jwk passkey_import_pkcs8 unpad_ct info_unpad_position_zeros info_unpad_content info_unpad_random_pair info_unpad_same base32_decode info_base32_a_vs_z info_base32_upper_vs_lower info_base32_random_pair kek_pw_commit_path info_unwrap_valid_vs_bad_commit kek_pin_commit_path info_unwrap_pin_valid_vs_bad_commit control_unpad_leaky control_null control_leaky
[run n=1000000] bench control_null                     ... : n == 0.999M, max t = -1.64649
[ok] control_null
[run n=1000000] bench control_unpad_leaky              ... : n == 0.537M, max t = -141691.95548
[ok] control_unpad_leaky: the setup sees an early-exit comparison
[run n=1000000] bench control_leaky                    ... : n == 0.537M, max t = +84362.04742
[ok] control_leaky: the setup sees an early-exit comparison
[run n=1000000] bench commit_check                     ... : n == 0.995M, max t = +1.50022
[ok] commit_check
[run n=1000000] bench mac_verify                       ... : n == 0.295M, max t = +2.34676
[ok] mac_verify
[run n=1000000] bench key_eq                           ... : n == 0.242M, max t = +1.88265
[ok] key_eq
[run n=1000000] bench crockford_decode                 ... : n == 0.999M, max t = +1.43477
[ok] crockford_decode
[run n=1000000] bench base64url_decode                 ... : n == 0.997M, max t = -1.92910
[ok] base64url_decode
[run n=1000000] bench passkey_import_jwk               ... : n == 0.384M, max t = +3.52583
[ok] passkey_import_jwk
[run n=1000000] bench passkey_import_pkcs8             ... : n == 0.340M, max t = -1.42077
[ok] passkey_import_pkcs8
[run n=1000000] bench unpad_ct                         ... : n == 0.999M, max t = +2.41386
[ok] unpad_ct
[run n=1000000] bench info_unpad_position_zeros        ... : n == 0.565M, max t = -1.44485
[info] info_unpad_position_zeros is reported, not gated
[run n=1000000] bench info_unpad_content               ... : n == 0.995M, max t = +1.42432
[info] info_unpad_content is reported, not gated
[run n=1000000] bench info_unpad_random_pair           ... : n == 0.568M, max t = +2.55829
[info] info_unpad_random_pair is reported, not gated
[run n=1000000] bench info_unpad_same                  ... : n == 0.973M, max t = +1.96841
[info] info_unpad_same is reported, not gated
[run n=1000000] bench base32_decode                    ... : n == 0.999M, max t = -1.51914
[ok] base32_decode
[run n=1000000] bench info_base32_a_vs_z               ... : n == 0.110M, max t = +1.53157
[info] info_base32_a_vs_z is reported, not gated
[run n=1000000] bench info_base32_upper_vs_lower       ... : n == 0.999M, max t = +1.77787
[info] info_base32_upper_vs_lower is reported, not gated
[run n=1000000] bench info_base32_random_pair          ... : n == 1.000M, max t = +1.58602
[info] info_base32_random_pair is reported, not gated
[run n=1000000] bench kek_pw_commit_path               ... : n == 0.824M, max t = -1.33702
[ok] kek_pw_commit_path
[run n=1000000] bench info_unwrap_valid_vs_bad_commit  ... : n == 0.565M, max t = +230974.16423
[info] info_unwrap_valid_vs_bad_commit is reported, not gated
[run n=1000000] bench kek_pin_commit_path              ... : n == 0.978M, max t = -2.61127
[ok] kek_pin_commit_path
[run n=1000000] bench info_unwrap_pin_valid_vs_bad_commit ... : n == 0.565M, max t = +197801.19179
[info] info_unwrap_pin_valid_vs_bad_commit is reported, not gated
```

