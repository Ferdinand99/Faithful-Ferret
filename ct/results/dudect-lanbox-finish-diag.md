# Diagnosis of the finish bench at opt-level 3 (LANBox)

Written from the container log of a throwaway build of `b7f2c54` plus four information benches (not committed), run once, 10^7
measurements per bench, five rounds with the benches interleaved, `taskset -c 1`,
`opt-level = 3`. The 1-minute load average was 1.01 at the start and 1.36 at the
end. `control_leaky` at 10^6 shows the setup sees an early exit. The first
three lines count instructions in the disassembly (`objdump -d -C`) of
`Finish::prepare`, of the same function of the bench that hides the class behind
`black_box`, and of the crate's `ct_eq`.

* `server_finish_credential_vs_account`: the bench as it was.
* `control_server_finish_null`: its null control.
* `info_server_finish_same_masked`: the mask of the bench and equal bytes in the two buffers.
* `info_server_finish_hidden_mask`: the data of the bench, the class behind `black_box`.
* `info_server_finish_swapped`: the bench with the two positions swapped.
* `info_server_finish_open_only`: as the hidden-mask bench, stopping after the open.

```text
finish-prepare: 333 lines, jumps 47, pand 0, and 8, memcpy 0, cmov 1
finish-hidden-prepare: 245 lines, jumps 34, pand 3, and 5, memcpy 0, cmov 1
ct-eq: 1207 lines, jumps 2, pand 0, and 105, memcpy 0, cmov 0
load: 1.01 0.44 0.60 1/1142 1648
bench control_leaky                           ... : n == +0.661M, max t = +72631.08696, max tau = +89.32639, (5/tau)^2 = 0
round 1
bench server_finish_credential_vs_account     ... : n == +5.614M, max t = +22.77891, max tau = +0.00961, (5/tau)^2 = 270466
bench control_server_finish_null              ... : n == +9.985M, max t = -1.84842, max tau = -0.00058, (5/tau)^2 = 73062667
bench info_server_finish_same_masked          ... : n == +4.981M, max t = +18.95303, max tau = +0.00849, (5/tau)^2 = 346633
bench info_server_finish_hidden_mask          ... : n == +1.267M, max t = -2.17270, max tau = -0.00193, (5/tau)^2 = 6711203
bench info_server_finish_swapped              ... : n == +4.242M, max t = +25.25261, max tau = +0.01226, (5/tau)^2 = 166298
bench info_server_finish_open_only            ... : n == +9.987M, max t = -2.29908, max tau = -0.00073, (5/tau)^2 = 47236008
round 2
bench server_finish_credential_vs_account     ... : n == +4.965M, max t = +21.40389, max tau = +0.00961, (5/tau)^2 = 270934
bench control_server_finish_null              ... : n == +0.621M, max t = +2.13478, max tau = +0.00271, (5/tau)^2 = 3405598
bench info_server_finish_same_masked          ... : n == +5.325M, max t = +19.30302, max tau = +0.00836, (5/tau)^2 = 357303
bench info_server_finish_hidden_mask          ... : n == +9.990M, max t = -1.50422, max tau = -0.00048, (5/tau)^2 = 110372228
bench info_server_finish_swapped              ... : n == +3.780M, max t = +4.41735, max tau = +0.00227, (5/tau)^2 = 4843212
bench info_server_finish_open_only            ... : n == +9.970M, max t = +2.46163, max tau = +0.00078, (5/tau)^2 = 41134426
round 3
bench server_finish_credential_vs_account     ... : n == +5.327M, max t = +28.51420, max tau = +0.01235, (5/tau)^2 = 163780
bench control_server_finish_null              ... : n == +6.690M, max t = +2.49862, max tau = +0.00097, (5/tau)^2 = 26789995
bench info_server_finish_same_masked          ... : n == +5.301M, max t = +22.48408, max tau = +0.00977, (5/tau)^2 = 262159
bench info_server_finish_hidden_mask          ... : n == +10.000M, max t = -2.69789, max tau = -0.00085, (5/tau)^2 = 34347219
bench info_server_finish_swapped              ... : n == +5.334M, max t = +23.86484, max tau = +0.01033, (5/tau)^2 = 234151
bench info_server_finish_open_only            ... : n == +1.265M, max t = +1.96427, max tau = +0.00175, (5/tau)^2 = 8198694
round 4
bench server_finish_credential_vs_account     ... : n == +5.248M, max t = +24.54019, max tau = +0.01071, (5/tau)^2 = 217862
bench control_server_finish_null              ... : n == +2.660M, max t = -2.22074, max tau = -0.00136, (5/tau)^2 = 13485515
bench info_server_finish_same_masked          ... : n == +4.987M, max t = +20.47066, max tau = +0.00917, (5/tau)^2 = 297513
bench info_server_finish_hidden_mask          ... : n == +6.907M, max t = +2.59335, max tau = +0.00099, (5/tau)^2 = 25674661
bench info_server_finish_swapped              ... : n == +4.962M, max t = +20.16981, max tau = +0.00905, (5/tau)^2 = 304905
bench info_server_finish_open_only            ... : n == +6.897M, max t = -2.92066, max tau = -0.00111, (5/tau)^2 = 20214581
round 5
bench server_finish_credential_vs_account     ... : n == +5.301M, max t = +34.83963, max tau = +0.01513, (5/tau)^2 = 109190
bench control_server_finish_null              ... : n == +10.000M, max t = +2.49281, max tau = +0.00079, (5/tau)^2 = 40231117
bench info_server_finish_same_masked          ... : n == +0.578M, max t = -26.49908, max tau = -0.03484, (5/tau)^2 = 20594
bench info_server_finish_hidden_mask          ... : n == +9.064M, max t = +2.07176, max tau = +0.00069, (5/tau)^2 = 52794234
bench info_server_finish_swapped              ... : n == +5.933M, max t = +31.26545, max tau = +0.01284, (5/tau)^2 = 151742
bench info_server_finish_open_only            ... : n == +8.491M, max t = -1.48911, max tau = -0.00051, (5/tau)^2 = 95729488
load at the end: 1.36 1.25 1.02 1/1101 1785
```
