# Dudect run on the LANBox: only the benches with "server" in the name

Written by `scripts/lanbox-ct.sh dudect-native` (2026-11-01T06:09:00Z). The limit is
|t| < 4.5 after 10000000 measurements; a bench over 4.5 is measured again with ten
times as many, except at 10^7 or more, where it fails. Every line of the two outputs is
below, runs and reruns included.

- commit: `ef1296634927074797b497e5747c40c7fc783fbe (with uncommitted changes)`: the working copy differed from the commit in `scripts/lanbox.sh` only, which was taken from main so that the container carries the labels of the run (a name and a title); it does not touch the code under test
- exit status of the run: 0
- measurements per bench: 10000000
- every selected bench measured 3 times

## Native

```text
dudect native: n=10000000 per bench (rerun with 100000000 when |t| >= 4.5), cpu=0, 2026-10-31T20:23:16Z
host: 70d0d3878bd5, model name	: Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz
rustc: rustc 1.99.1 (58cf8f9c3 2026-10-13)
profile: opt-level 3, lto, codegen-units 1, panic abort, overflow checks
load: 0.81 0.43 0.63 1/1134 1635
timed-asm stored_for: 16 lines, conditional jumps 0
timed-asm choose_answer: 28 lines, conditional jumps 0
timed-asm pick_account: 6 lines, conditional jumps 0
timed-asm Finish::prepare: 244 lines, mask loops (xor, and, xor) 3, pand 6
[run n=10000000] bench control_null                            ... : n == +9.987M, max t = -2.08890, max tau = -0.00066, (5/tau)^2 = 57219759
[ok] control_null
[run n=10000000] bench control_null                            ... : n == +10.000M, max t = +1.82562, max tau = +0.00058, (5/tau)^2 = 75010250
[ok] control_null
[run n=10000000] bench control_null                            ... : n == +6.880M, max t = +2.07694, max tau = +0.00079, (5/tau)^2 = 39874757
[ok] control_null
[run n=10000000] bench control_leaky                           ... : n == +7.966M, max t = +229846.63899, max tau = +81.43376, (5/tau)^2 = 0
[ok] control_leaky: the setup sees an early-exit comparison
[run n=10000000] bench control_leaky                           ... : n == +7.493M, max t = +204204.10106, max tau = +74.60016, (5/tau)^2 = 0
[ok] control_leaky: the setup sees an early-exit comparison
[run n=10000000] bench control_leaky                           ... : n == +7.595M, max t = +271215.33930, max tau = +98.40952, (5/tau)^2 = 0
[ok] control_leaky: the setup sees an early-exit comparison
[run n=10000000] bench control_unpad_leaky                     ... : n == +8.645M, max t = -82670.45805, max tau = -28.11754, (5/tau)^2 = 0
[ok] control_unpad_leaky: the setup sees an early-exit comparison
[run n=10000000] bench control_unpad_leaky                     ... : n == +9.355M, max t = -88137.77514, max tau = -28.81655, (5/tau)^2 = 0
[ok] control_unpad_leaky: the setup sees an early-exit comparison
[run n=10000000] bench control_unpad_leaky                     ... : n == +5.623M, max t = -204122.77836, max tau = -86.07996, (5/tau)^2 = 0
[ok] control_unpad_leaky: the setup sees an early-exit comparison
[run n=10000000] bench server_login_start_known_vs_unknown     ... : n == +9.641M, max t = -2.63273, max tau = -0.00085, (5/tau)^2 = 34773737
[ok] server_login_start_known_vs_unknown
[run n=10000000] bench server_login_start_known_vs_unknown     ... : n == +1.288M, max t = +2.28211, max tau = +0.00201, (5/tau)^2 = 6180529
[ok] server_login_start_known_vs_unknown
[run n=10000000] bench server_login_start_known_vs_unknown     ... : n == +0.666M, max t = +2.23475, max tau = +0.00274, (5/tau)^2 = 3333896
[ok] server_login_start_known_vs_unknown
[run n=10000000] bench server_login_start_known_vs_disabled    ... : n == +9.873M, max t = +2.37042, max tau = +0.00075, (5/tau)^2 = 43927887
[ok] server_login_start_known_vs_disabled
[run n=10000000] bench server_login_start_known_vs_disabled    ... : n == +8.459M, max t = +1.24953, max tau = +0.00043, (5/tau)^2 = 135453015
[ok] server_login_start_known_vs_disabled
[run n=10000000] bench server_login_start_known_vs_disabled    ... : n == +9.945M, max t = -1.47138, max tau = -0.00047, (5/tau)^2 = 114838108
[ok] server_login_start_known_vs_disabled
[run n=10000000] bench control_server_login_start_null         ... : n == +9.904M, max t = -2.06926, max tau = -0.00066, (5/tau)^2 = 57824515
[ok] control_server_login_start_null
[run n=10000000] bench control_server_login_start_null         ... : n == +9.375M, max t = +1.47472, max tau = +0.00048, (5/tau)^2 = 107768572
[ok] control_server_login_start_null
[run n=10000000] bench control_server_login_start_null         ... : n == +8.833M, max t = -1.58097, max tau = -0.00053, (5/tau)^2 = 88352900
[ok] control_server_login_start_null
[run n=10000000] bench control_server_prelogin_null            ... : n == +5.924M, max t = -3.13627, max tau = -0.00129, (5/tau)^2 = 15055840
[ok] control_server_prelogin_null
[run n=10000000] bench control_server_prelogin_null            ... : n == +4.966M, max t = +1.88662, max tau = +0.00085, (5/tau)^2 = 34880071
[ok] control_server_prelogin_null
[run n=10000000] bench control_server_prelogin_null            ... : n == +2.877M, max t = +1.77746, max tau = +0.00105, (5/tau)^2 = 22761653
[ok] control_server_prelogin_null
[run n=10000000] bench control_server_finish_null              ... : n == +1.066M, max t = -3.89264, max tau = -0.00377, (5/tau)^2 = 1758962
[ok] control_server_finish_null
[run n=10000000] bench control_server_finish_null              ... : n == +9.941M, max t = +2.01465, max tau = +0.00064, (5/tau)^2 = 61229100
[ok] control_server_finish_null
[run n=10000000] bench control_server_finish_null              ... : n == +5.644M, max t = -2.45763, max tau = -0.00103, (5/tau)^2 = 23362844
[ok] control_server_finish_null
[run n=10000000] bench info_server_login_start_lookup_only     ... : n == +9.937M, max t = +2.43847, max tau = +0.00077, (5/tau)^2 = 41777306
[info] info_server_login_start_lookup_only is reported, not gated
[run n=10000000] bench info_server_login_start_lookup_only     ... : n == +10.000M, max t = -2.41569, max tau = -0.00076, (5/tau)^2 = 42840761
[info] info_server_login_start_lookup_only is reported, not gated
[run n=10000000] bench info_server_login_start_lookup_only     ... : n == +4.640M, max t = +1.68019, max tau = +0.00078, (5/tau)^2 = 41093188
[info] info_server_login_start_lookup_only is reported, not gated
[run n=10000000] bench info_server_login_start_real_vs_made_up ... : n == +9.983M, max t = +2.59880, max tau = +0.00082, (5/tau)^2 = 36953402
[info] info_server_login_start_real_vs_made_up is reported, not gated
[run n=10000000] bench info_server_login_start_real_vs_made_up ... : n == +9.746M, max t = +2.54454, max tau = +0.00082, (5/tau)^2 = 37631950
[info] info_server_login_start_real_vs_made_up is reported, not gated
[run n=10000000] bench info_server_login_start_real_vs_made_up ... : n == +9.897M, max t = -1.86704, max tau = -0.00059, (5/tau)^2 = 70979748
[info] info_server_login_start_real_vs_made_up is reported, not gated
[run n=10000000] bench info_server_login_start_fixed_vs_pool   ... : n == +9.687M, max t = -1.15221, max tau = -0.00037, (5/tau)^2 = 182425917
[info] info_server_login_start_fixed_vs_pool is reported, not gated
[run n=10000000] bench info_server_login_start_fixed_vs_pool   ... : n == +9.948M, max t = +1.75962, max tau = +0.00056, (5/tau)^2 = 80325892
[info] info_server_login_start_fixed_vs_pool is reported, not gated
[run n=10000000] bench info_server_login_start_fixed_vs_pool   ... : n == +10.000M, max t = +1.35128, max tau = +0.00043, (5/tau)^2 = 136915457
[info] info_server_login_start_fixed_vs_pool is reported, not gated
[run n=10000000] bench server_prelogin_known_vs_unknown        ... : n == +1.864M, max t = +1.48017, max tau = +0.00108, (5/tau)^2 = 21265979
[ok] server_prelogin_known_vs_unknown
[run n=10000000] bench server_prelogin_known_vs_unknown        ... : n == +9.889M, max t = +1.42531, max tau = +0.00045, (5/tau)^2 = 121700539
[ok] server_prelogin_known_vs_unknown
[run n=10000000] bench server_prelogin_known_vs_unknown        ... : n == +5.308M, max t = +1.24531, max tau = +0.00054, (5/tau)^2 = 85562704
[ok] server_prelogin_known_vs_unknown
[run n=10000000] bench info_server_prelogin_resolve_credential ... : n == +9.882M, max t = +7.08832, max tau = +0.00225, (5/tau)^2 = 4916759
[info] info_server_prelogin_resolve_credential is reported, not gated
[run n=10000000] bench info_server_prelogin_resolve_credential ... : n == +5.642M, max t = +7.18065, max tau = +0.00302, (5/tau)^2 = 2735673
[info] info_server_prelogin_resolve_credential is reported, not gated
[run n=10000000] bench info_server_prelogin_resolve_credential ... : n == +5.647M, max t = +11.20040, max tau = +0.00471, (5/tau)^2 = 1125288
[info] info_server_prelogin_resolve_credential is reported, not gated
[run n=10000000] bench server_state_binding                    ... : n == +9.988M, max t = +1.88472, max tau = +0.00060, (5/tau)^2 = 70295059
[ok] server_state_binding
[run n=10000000] bench server_state_binding                    ... : n == +9.985M, max t = -1.95968, max tau = -0.00062, (5/tau)^2 = 65001794
[ok] server_state_binding
[run n=10000000] bench server_state_binding                    ... : n == +9.982M, max t = -1.48119, max tau = -0.00047, (5/tau)^2 = 113743638
[ok] server_state_binding
[run n=10000000] bench server_finish_credential_vs_account     ... : n == +9.982M, max t = -2.00076, max tau = -0.00063, (5/tau)^2 = 62338392
[ok] server_finish_credential_vs_account
[run n=10000000] bench server_finish_credential_vs_account     ... : n == +9.964M, max t = -0.94689, max tau = -0.00030, (5/tau)^2 = 277812606
[ok] server_finish_credential_vs_account
[run n=10000000] bench server_finish_credential_vs_account     ... : n == +5.286M, max t = +2.31260, max tau = +0.00101, (5/tau)^2 = 24710380
[ok] server_finish_credential_vs_account
[run n=10000000] bench info_server_finish_state_vs_missing     ... : n == +7.657M, max t = +112841.79107, max tau = +40.77976, (5/tau)^2 = 0
[info] info_server_finish_state_vs_missing is reported, not gated
[run n=10000000] bench info_server_finish_state_vs_missing     ... : n == +7.815M, max t = +106245.58276, max tau = +38.00616, (5/tau)^2 = 0
[info] info_server_finish_state_vs_missing is reported, not gated
[run n=10000000] bench info_server_finish_state_vs_missing     ... : n == +6.895M, max t = +115949.88360, max tau = +44.15801, (5/tau)^2 = 0
[info] info_server_finish_state_vs_missing is reported, not gated
load at the end: 1.07 1.15 1.17 1/1110 2273
```

