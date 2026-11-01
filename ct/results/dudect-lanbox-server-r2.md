# Dudect run on the LANBox: only the benches with "server" in the name

Written by `scripts/lanbox-ct.sh dudect-native` (2026-10-31T07:24:03Z). The limit is
|t| < 4.5 after 10^6 measurements, a bench over 4.5 measured again with 10^7. Every
line of the two outputs is below, runs and reruns included.

- commit: `6f8743b114d0626d50a43aaf3a8aeddd846808b0 (with uncommitted changes)`
- exit status of the run: 1
- measurements per bench: 10000000

## Native

```text
dudect native: n=10000000 per bench (rerun with 100000000 when |t| >= 4.5), cpu=2, 2026-10-31T04:23:11Z
host: 3c80eb11b01b, model name	: Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz
rustc: rustc 1.99.1 (58cf8f9c3 2026-10-13)
load: 1.08 0.39 0.52 1/1183 1635
[run n=10000000] bench control_null                            ... : n == +9.980M, max t = -1.48461, max tau = -0.00047, (5/tau)^2 = 113204561
[ok] control_null
[run n=10000000] bench control_leaky                           ... : n == +7.821M, max t = +171345.26368, max tau = +61.27012, (5/tau)^2 = 0
[ok] control_leaky: the setup sees an early-exit comparison
[run n=10000000] bench control_unpad_leaky                     ... : n == +6.627M, max t = -153228.24788, max tau = -59.52418, (5/tau)^2 = 0
[ok] control_unpad_leaky: the setup sees an early-exit comparison
[run n=10000000] bench server_login_start_known_vs_unknown     ... : n == +0.663M, max t = +17.40739, max tau = +0.02138, (5/tau)^2 = 54690
[FAIL] server_login_start_known_vs_unknown: |t| >= 4.5 at n=10000000 (no rerun above 10^7)
[run n=10000000] bench server_login_start_known_vs_disabled    ... : n == +0.668M, max t = +4.26504, max tau = +0.00522, (5/tau)^2 = 918240
[ok] server_login_start_known_vs_disabled
[run n=10000000] bench control_server_login_start_null         ... : n == +9.417M, max t = -1.90625, max tau = -0.00062, (5/tau)^2 = 64786801
[ok] control_server_login_start_null
[run n=10000000] bench info_server_login_start_lookup_only     ... : n == +0.668M, max t = +2.53078, max tau = +0.00310, (5/tau)^2 = 2606404
[info] info_server_login_start_lookup_only is reported, not gated
[run n=10000000] bench info_server_login_start_real_vs_made_up ... : n == +10.000M, max t = +3.01661, max tau = +0.00095, (5/tau)^2 = 27472762
[info] info_server_login_start_real_vs_made_up is reported, not gated
[run n=10000000] bench server_prelogin_known_vs_unknown        ... : n == +4.638M, max t = -4.19782, max tau = -0.00195, (5/tau)^2 = 6579505
[ok] server_prelogin_known_vs_unknown
[run n=10000000] bench info_server_prelogin_resolve_credential ... : n == +4.991M, max t = +8.53076, max tau = +0.00382, (5/tau)^2 = 1714661
[info] info_server_prelogin_resolve_credential is reported, not gated
[run n=10000000] bench server_state_binding                    ... : n == +3.810M, max t = +1.70459, max tau = +0.00087, (5/tau)^2 = 32778510
[ok] server_state_binding
[run n=10000000] bench server_finish_credential_vs_account     ... : n == +3.794M, max t = +25.92183, max tau = +0.01331, (5/tau)^2 = 141173
[FAIL] server_finish_credential_vs_account: |t| >= 4.5 at n=10000000 (no rerun above 10^7)
[run n=10000000] bench info_server_finish_state_vs_missing     ... : n == +7.298M, max t = +140085.88623, max tau = +51.85344, (5/tau)^2 = 0
[info] info_server_finish_state_vs_missing is reported, not gated
load at the end: 1.17 1.17 1.19 1/1119 1809
```

