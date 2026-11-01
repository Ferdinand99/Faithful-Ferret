# Diagnosis 2 of the finish bench at opt-level 3 (LANBox)

Written from the container log of a throwaway build (not committed) of the
version of the bench that moves the missing-state case into a target of its own,
plus the target `info_server_finish_old_shape`: the `Finish::prepare` of 49efe22,
with the class test of the missing-state case, on equal bytes. Two builds
(layouts) at `opt-level = 3`: `a` as built, `b` with
`-C llvm-args=-align-all-functions=6`. Five rounds of three benches in `a`,
three in `b`, 10^7 measurements each, `taskset -c 1`. The 1-minute load average
was 0.43 at the start and 1.11 at the end. `control_leaky` at 10^6 shows the
setup sees an early exit in both layouts.

* `control_server_finish_null` (N): the null control, equal bytes, the new `prepare`.
* `server_finish_credential_vs_account` (G): the gate, the new `prepare`.
* `info_server_finish_old_shape` (B): equal bytes, the old `prepare` with the class test.

The lines starting `a ` and `b ` count the instructions of the two `prepare`
functions in each layout. In the disassembly of the old one (49efe22,
`Finish::prepare`, 282 lines) the class (`%cl`) is tested after the mask loop,
before the missing-state test of the target kind: `test %cl,%cl; je`, then
`cmpb $0x1,<kind>; jne`; the class decides a jump.

```text
load: 0.43 0.43 0.56 1/1155 12
a Finish::prepare: 245 lines
a FinishOld::prepare: 282 lines
b Finish::prepare: 245 lines
b FinishOld::prepare: 330 lines
bench control_leaky                           ... : n == +0.533M, max t = +70742.28189, max tau = +96.90160, (5/tau)^2 = 0
a round 1
bench control_server_finish_null              ... : n == +9.964M, max t = +2.04099, max tau = +0.00065, (5/tau)^2 = 59795886
bench server_finish_credential_vs_account     ... : n == +7.211M, max t = -2.16944, max tau = -0.00081, (5/tau)^2 = 38304512
bench info_server_finish_old_shape            ... : n == +4.943M, max t = +64.77953, max tau = +0.02914, (5/tau)^2 = 29448
a round 2
bench control_server_finish_null              ... : n == +9.987M, max t = -2.19641, max tau = -0.00070, (5/tau)^2 = 51755172
bench server_finish_credential_vs_account     ... : n == +9.968M, max t = +1.68206, max tau = +0.00053, (5/tau)^2 = 88079326
bench info_server_finish_old_shape            ... : n == +4.640M, max t = -26.18130, max tau = -0.01215, (5/tau)^2 = 169215
a round 3
bench control_server_finish_null              ... : n == +1.054M, max t = +1.80551, max tau = +0.00176, (5/tau)^2 = 8083637
bench server_finish_credential_vs_account     ... : n == +9.988M, max t = +2.55505, max tau = +0.00081, (5/tau)^2 = 38248787
bench info_server_finish_old_shape            ... : n == +5.260M, max t = -17.57586, max tau = -0.00766, (5/tau)^2 = 425674
a round 4
bench control_server_finish_null              ... : n == +4.970M, max t = -2.46897, max tau = -0.00111, (5/tau)^2 = 20383359
bench server_finish_credential_vs_account     ... : n == +9.990M, max t = +1.25004, max tau = +0.00040, (5/tau)^2 = 159822742
bench info_server_finish_old_shape            ... : n == +4.963M, max t = +53.42902, max tau = +0.02398, (5/tau)^2 = 43461
a round 5
bench control_server_finish_null              ... : n == +9.961M, max t = -2.17186, max tau = -0.00069, (5/tau)^2 = 52792892
bench server_finish_credential_vs_account     ... : n == +9.982M, max t = -1.61836, max tau = -0.00051, (5/tau)^2 = 95279425
bench info_server_finish_old_shape            ... : n == +4.993M, max t = -77.30603, max tau = -0.03460, (5/tau)^2 = 20887
bench control_leaky                           ... : n == +0.866M, max t = +70309.67653, max tau = +75.55294, (5/tau)^2 = 0
b round 1
bench control_server_finish_null              ... : n == +5.000M, max t = -2.01307, max tau = -0.00090, (5/tau)^2 = 30844949
bench server_finish_credential_vs_account     ... : n == +9.922M, max t = -1.75972, max tau = -0.00056, (5/tau)^2 = 80099552
bench info_server_finish_old_shape            ... : n == +4.977M, max t = +2.47268, max tau = +0.00111, (5/tau)^2 = 20350097
b round 2
bench control_server_finish_null              ... : n == +5.935M, max t = +3.22084, max tau = +0.00132, (5/tau)^2 = 14302592
bench server_finish_credential_vs_account     ... : n == +8.417M, max t = -2.61013, max tau = -0.00090, (5/tau)^2 = 30888181
bench info_server_finish_old_shape            ... : n == +1.757M, max t = -9.92881, max tau = -0.00749, (5/tau)^2 = 445682
b round 3
bench control_server_finish_null              ... : n == +9.623M, max t = +1.88168, max tau = +0.00061, (5/tau)^2 = 67944240
bench server_finish_credential_vs_account     ... : n == +9.990M, max t = +2.59753, max tau = +0.00082, (5/tau)^2 = 37016312
bench info_server_finish_old_shape            ... : n == +4.636M, max t = -61.47998, max tau = -0.02855, (5/tau)^2 = 30663
load at the end: 1.11 1.10 0.96 1/1099 3364
```
