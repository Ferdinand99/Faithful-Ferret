# Dudect run on the LANBox: only the benches with "server" in the name

Written by `scripts/lanbox-ct.sh dudect-native` (2026-10-30T22:35:45Z). The limit is
|t| < 4.5 after 10^6 measurements, a bench over 4.5 measured again with 10^7. Every
line of the two outputs is below, runs and reruns included.

- commit: `9aaa5667ef03bae7335beeb8476df8493f28da2e`
- exit status of the run: 0
- measurements per bench: 1000000
- every selected bench measured 2 times

## Native

```text
dudect native: n=1000000 per bench (rerun with 10000000 when |t| >= 4.5), cpu=1, 2026-10-30T22:15:51Z
host: 5787c7e57907, model name	: Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz
rustc: rustc 1.99.1 (58cf8f9c3 2026-10-13)
load: 21.26 16.49 11.63 19/1427 1634
[run n=1000000] bench server_login_start_known_vs_unknown     ... : n == +0.979M, max t = -3.87604, max tau = -0.00392, (5/tau)^2 = 1629728
[ok] server_login_start_known_vs_unknown
[run n=1000000] bench server_login_start_known_vs_unknown     ... : n == +0.999M, max t = -2.91711, max tau = -0.00292, (5/tau)^2 = 2935021
[ok] server_login_start_known_vs_unknown
[run n=1000000] bench server_login_start_known_vs_disabled    ... : n == +0.621M, max t = +2.29373, max tau = +0.00291, (5/tau)^2 = 2951056
[ok] server_login_start_known_vs_disabled
[run n=1000000] bench server_login_start_known_vs_disabled    ... : n == +0.996M, max t = -3.09721, max tau = -0.00310, (5/tau)^2 = 2594444
[ok] server_login_start_known_vs_disabled
[run n=1000000] bench server_prelogin_known_vs_unknown        ... : n == +1.000M, max t = +2.31009, max tau = +0.00231, (5/tau)^2 = 4684698
[ok] server_prelogin_known_vs_unknown
[run n=1000000] bench server_prelogin_known_vs_unknown        ... : n == +1.000M, max t = +1.89730, max tau = +0.00190, (5/tau)^2 = 6944903
[ok] server_prelogin_known_vs_unknown
[run n=1000000] bench info_server_prelogin_resolve_credential ... : n == +0.129M, max t = +5.60774, max tau = +0.01560, (5/tau)^2 = 102725
[info] info_server_prelogin_resolve_credential is reported, not gated
[run n=1000000] bench info_server_prelogin_resolve_credential ... : n == +0.978M, max t = +4.57219, max tau = +0.00462, (5/tau)^2 = 1169461
[info] info_server_prelogin_resolve_credential is reported, not gated
[run n=1000000] bench server_state_binding                    ... : n == +1.000M, max t = -1.71976, max tau = -0.00172, (5/tau)^2 = 8452868
[ok] server_state_binding
[run n=1000000] bench server_state_binding                    ... : n == +0.999M, max t = -1.69078, max tau = -0.00169, (5/tau)^2 = 8736543
[ok] server_state_binding
[run n=1000000] bench server_finish_credential_vs_account     ... : n == +0.995M, max t = +4.16949, max tau = +0.00418, (5/tau)^2 = 1430639
[ok] server_finish_credential_vs_account
[run n=1000000] bench server_finish_credential_vs_account     ... : n == +0.846M, max t = +4.64847, max tau = +0.00505, (5/tau)^2 = 978439
[rerun n=10000000] bench server_finish_credential_vs_account     ... : n == +9.807M, max t = +2.13900, max tau = +0.00068, (5/tau)^2 = 53587851
[ok, rerun] server_finish_credential_vs_account: |t| >= 4.5 at n=1000000, below at n=10000000
[run n=1000000] bench info_server_finish_state_vs_missing     ... : n == +0.691M, max t = +19667.57859, max tau = +23.65151, (5/tau)^2 = 0
[info] info_server_finish_state_vs_missing is reported, not gated
[run n=1000000] bench info_server_finish_state_vs_missing     ... : n == +0.691M, max t = +20325.51182, max tau = +24.45251, (5/tau)^2 = 0
[info] info_server_finish_state_vs_missing is reported, not gated
```

