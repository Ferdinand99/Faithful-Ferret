# Dudect run on the LANBox: only the benches with "server" in the name

Written by `scripts/lanbox-ct.sh dudect-native` (2026-10-31T04:04:26Z). The limit is
|t| < 4.5 after 10^6 measurements, a bench over 4.5 measured again with 10^7. Every
line of the two outputs is below, runs and reruns included.

- commit: `e4e63343d91962b81076d1401f4edb6e832d6517 (with uncommitted changes)`
- exit status of the run: 1
- measurements per bench: 10000000

## Native

```text
dudect native: n=10000000 per bench (rerun with 100000000 when |t| >= 4.5), cpu=6, 2026-10-31T01:00:06Z
host: 65e7cd067e41, model name	: Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz
rustc: rustc 1.99.1 (58cf8f9c3 2026-10-13)
load: 1.35 1.13 1.05 2/1140 1633
[run n=10000000] bench control_null                            ... : n == +8.116M, max t = +1.54911, max tau = +0.00054, (5/tau)^2 = 84547449
[ok] control_null
[run n=10000000] bench control_leaky                           ... : n == +5.895M, max t = +235900.44477, max tau = +97.15807, (5/tau)^2 = 0
[ok] control_leaky: the setup sees an early-exit comparison
[run n=10000000] bench control_unpad_leaky                     ... : n == +6.385M, max t = -150385.82673, max tau = -59.51644, (5/tau)^2 = 0
[ok] control_unpad_leaky: the setup sees an early-exit comparison
[run n=10000000] bench server_login_start_known_vs_unknown     ... : n == +0.666M, max t = -12.30844, max tau = -0.01509, (5/tau)^2 = 109843
[FAIL] server_login_start_known_vs_unknown: |t| >= 4.5 at n=10000000 (no rerun above 10^7)
[run n=10000000] bench server_login_start_known_vs_disabled    ... : n == +4.997M, max t = +6.26054, max tau = +0.00280, (5/tau)^2 = 3187341
[FAIL] server_login_start_known_vs_disabled: |t| >= 4.5 at n=10000000 (no rerun above 10^7)
[run n=10000000] bench control_server_login_start_null         ... : n == +9.916M, max t = -1.54729, max tau = -0.00049, (5/tau)^2 = 103549297
[ok] control_server_login_start_null
[run n=10000000] bench info_server_login_start_lookup_only     ... : n == +4.995M, max t = +2.61517, max tau = +0.00117, (5/tau)^2 = 18260475
[info] info_server_login_start_lookup_only is reported, not gated
[run n=10000000] bench info_server_login_start_real_vs_made_up ... : n == +9.952M, max t = -2.04788, max tau = -0.00065, (5/tau)^2 = 59325110
[info] info_server_login_start_real_vs_made_up is reported, not gated
[run n=10000000] bench server_prelogin_known_vs_unknown        ... : n == +0.654M, max t = +18.30828, max tau = +0.02264, (5/tau)^2 = 48789
[FAIL] server_prelogin_known_vs_unknown: |t| >= 4.5 at n=10000000 (no rerun above 10^7)
[run n=10000000] bench info_server_prelogin_resolve_credential ... : n == +0.664M, max t = +17.03748, max tau = +0.02091, (5/tau)^2 = 57175
[info] info_server_prelogin_resolve_credential is reported, not gated
[run n=10000000] bench server_state_binding                    ... : n == +5.617M, max t = +2.61876, max tau = +0.00110, (5/tau)^2 = 20476597
[ok] server_state_binding
[run n=10000000] bench server_finish_credential_vs_account     ... : n == +4.987M, max t = +2.66593, max tau = +0.00119, (5/tau)^2 = 17541325
[ok] server_finish_credential_vs_account
[run n=10000000] bench info_server_finish_state_vs_missing     ... : n == +6.896M, max t = +129475.31468, max tau = +49.30300, (5/tau)^2 = 0
[info] info_server_finish_state_vs_missing is reported, not gated
load at the end: 1.21 1.19 1.22 1/1119 1807
```

