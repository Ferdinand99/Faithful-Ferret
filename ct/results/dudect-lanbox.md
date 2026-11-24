# Decisive dudect run on the build host

Written by `scripts/lanbox-ct.sh wasm-scan` (2026-11-24T15:28:47Z). The limit is
|t| < 4.5 after 1000000 measurements; a bench over 4.5 is measured again with ten
times as many, except at 10^7 or more, where it fails. Every line of the two outputs is
below, runs and reruns included.

- commit: `9d6bd3dbb07dd200b082c1faaa87eba2eec29f34`
- exit status of the run: 1
- measurements per bench: 1000000
- **NOT DECISIVE**: the machine was not quiet (1-minute load average above 2 at the start or the end; see the load lines below)

## Native

```text
dudect native: n=1000000 per bench (rerun with 10000000 when |t| >= 4.5), cpu=1, 2026-11-24T14:30:19Z
host: f70247efad9d, model name	: Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz
rustc: rustc 1.99.1 (58cf8f9c3 2026-10-13)
profile: opt-level s (ct/dudect/Cargo.toml), lto, codegen-units 1, panic abort, overflow checks
load: 17.95 16.17 13.79 17/902 1286
NOT DECISIVE: the 1-minute load average at the start was above 2; the machine was not quiet
timed-asm stored_for: 14 lines, conditional jumps 0
timed-asm choose_answer: 26 lines, conditional jumps 0
timed-asm pick_account: 5 lines, conditional jumps 0
timed-asm Finish::prepare: 101 lines, mask loops (xor, and, xor) 1, pand 0
[run n=1000000] bench control_null                            ... : n == +0.969M, max t = +1.56485, max tau = +0.00159, (5/tau)^2 = 9889073
[ok] control_null
[run n=1000000] bench control_leaky                           ... : n == +0.560M, max t = +94763.54347, max tau = +126.65822, (5/tau)^2 = 0
[ok] control_leaky: the setup sees an early-exit comparison
[run n=1000000] bench control_unpad_leaky                     ... : n == +0.827M, max t = -46500.95558, max tau = -51.14268, (5/tau)^2 = 0
[ok] control_unpad_leaky: the setup sees an early-exit comparison
[run n=1000000] bench kek_pin_commit_path                     ... : n == +0.990M, max t = +1.91144, max tau = +0.00192, (5/tau)^2 = 6771907
[ok] kek_pin_commit_path
[run n=1000000] bench info_unwrap_pin_valid_vs_bad_commit     ... : n == +0.692M, max t = +25430.69170, max tau = +30.56770, (5/tau)^2 = 0
[info] info_unwrap_pin_valid_vs_bad_commit is reported, not gated
[run n=1000000] bench control_server_login_start_null         ... : n == +0.997M, max t = -2.50138, max tau = -0.00251, (5/tau)^2 = 3982924
[ok] control_server_login_start_null
[run n=1000000] bench control_server_prelogin_null            ... : n == +0.988M, max t = +1.93748, max tau = +0.00195, (5/tau)^2 = 6580966
[ok] control_server_prelogin_null
[run n=1000000] bench control_server_finish_null              ... : n == +0.997M, max t = -1.63694, max tau = -0.00164, (5/tau)^2 = 9298115
[ok] control_server_finish_null
load at the end: 13.88 14.75 13.97 14/790 1436
NOT DECISIVE: the 1-minute load average at the end was above 2
```

