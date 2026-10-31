# Dudect run on the LANBox: only the benches with "server" in the name

Written by hand from the container log of `scripts/lanbox-ct.sh dudect-native`
(`CT_ONLY=server`, started 2026-10-31T07:57:25Z): the local client was stopped
overnight, so the script did not write this file. Two things are therefore
missing, and they are the only differences from a file the script writes:
the host load at the end was not captured (there is no `load at the end:` line),
and the last information bench, `info_server_finish_state_vs_missing`, is not in
the log copy (it was the last bench of the list and may not have finished or
been copied). The exit status of the run is not known; every gated bench in the
log is `[ok]`. The limit is |t| < 4.5 at 10^7 measurements from the start (a
bench over it fails without a rerun). Every line of the output that exists is
below.

- commit: `29fbc6b` (the head of the pull request when the run started)
- exit status of the run: not captured
- measurements per bench: 10000000
- load: 0.92 (1 minute) at the start; at the end not captured

## Native

```text
dudect native: n=10000000 per bench (rerun with 100000000 when |t| >= 4.5), cpu=6, 2026-10-31T07:57:25Z
host: f621134097b6, model name	: Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz
rustc: rustc 1.99.1 (58cf8f9c3 2026-10-13)
load: 0.92 0.31 0.28 1/1179 1635
timed-asm stored_for: 14 lines, conditional jumps 0
timed-asm choose_answer: 26 lines, conditional jumps 0
timed-asm pick_account: 5 lines, conditional jumps 0
[run n=10000000] bench control_null                            ... : n == +9.986M, max t = +2.59757, max tau = +0.00082, (5/tau)^2 = 37000227
[ok] control_null
[run n=10000000] bench control_leaky                           ... : n == +5.880M, max t = +217548.91327, max tau = +89.71401, (5/tau)^2 = 0
[ok] control_leaky: the setup sees an early-exit comparison
[run n=10000000] bench control_unpad_leaky                     ... : n == +6.350M, max t = -256952.96158, max tau = -101.97234, (5/tau)^2 = 0
[ok] control_unpad_leaky: the setup sees an early-exit comparison
[run n=10000000] bench server_login_start_known_vs_unknown     ... : n == +9.330M, max t = -3.89910, max tau = -0.00128, (5/tau)^2 = 15342556
[ok] server_login_start_known_vs_unknown
[run n=10000000] bench server_login_start_known_vs_disabled    ... : n == +3.843M, max t = -2.54468, max tau = -0.00130, (5/tau)^2 = 14837930
[ok] server_login_start_known_vs_disabled
[run n=10000000] bench control_server_login_start_null         ... : n == +0.663M, max t = -1.72027, max tau = -0.00211, (5/tau)^2 = 5598350
[ok] control_server_login_start_null
[run n=10000000] bench control_server_prelogin_null            ... : n == +8.228M, max t = -2.64930, max tau = -0.00092, (5/tau)^2 = 29306917
[ok] control_server_prelogin_null
[run n=10000000] bench control_server_finish_null              ... : n == +7.294M, max t = -1.91583, max tau = -0.00071, (5/tau)^2 = 49681347
[ok] control_server_finish_null
[run n=10000000] bench info_server_login_start_lookup_only     ... : n == +9.966M, max t = -2.52291, max tau = -0.00080, (5/tau)^2 = 39143222
[info] info_server_login_start_lookup_only is reported, not gated
[run n=10000000] bench info_server_login_start_real_vs_made_up ... : n == +5.643M, max t = -1.38481, max tau = -0.00058, (5/tau)^2 = 73563855
[info] info_server_login_start_real_vs_made_up is reported, not gated
[run n=10000000] bench info_server_login_start_fixed_vs_pool   ... : n == +9.882M, max t = +1.76484, max tau = +0.00056, (5/tau)^2 = 79315477
[info] info_server_login_start_fixed_vs_pool is reported, not gated
[run n=10000000] bench server_prelogin_known_vs_unknown        ... : n == +9.952M, max t = -2.56225, max tau = -0.00081, (5/tau)^2 = 37896787
[ok] server_prelogin_known_vs_unknown
[run n=10000000] bench info_server_prelogin_resolve_credential ... : n == +9.916M, max t = +5.27957, max tau = +0.00168, (5/tau)^2 = 8893852
[info] info_server_prelogin_resolve_credential is reported, not gated
[run n=10000000] bench server_state_binding                    ... : n == +3.840M, max t = -1.82708, max tau = -0.00093, (5/tau)^2 = 28755721
[ok] server_state_binding
[run n=10000000] bench server_finish_credential_vs_account     ... : n == +9.744M, max t = +1.38592, max tau = +0.00044, (5/tau)^2 = 126825906
[ok] server_finish_credential_vs_account
```
