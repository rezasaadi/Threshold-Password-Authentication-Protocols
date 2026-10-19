# Protocol revision scope

The implementation retains the five phases Setup, Registration, Authentication,
Secret Update, and Password Update. The network adapter adds the following
checks and recovery restrictions:

| Implemented behavior | Remaining protocol question |
|---|---|
| Reads use `r = n_sp - q_sp + t_sp` | A complete security argument for all recovery schedules |
| New-password polynomial consistency requires `r >= 2*t_sp - 1` | Verifiable TOPRF contributions or another robust reconstruction method |
| Store/Discard choices persist before transmission | Completion certificates for general recovery of missed writes |
| Repeated fixed-password updates abort before writes | Revocation of previously used passwords |
| Replica activation requires completion evidence | General identification catch-up and account activation after missed writes |

Signatures establish authorization of a tuple, not its completion. The same-password
restriction does not establish freshness for every password history. These limits
are detailed in `PROTOCOL_GAPS.md`.

The supported comparison grid uses `t=floor((n+2)/3)` and is separate from the
original 60% threshold grid. RoUpSPA Password Update on the latter grid aborts
before writes when the consistency requirement is not satisfied. Historical
performance figures remain separate from new measurements. Current validation
is recorded in `docs/validation/README.md`; experiment instructions appear in
`RUN_ALL_MEASUREMENTS.md` and `RUN_NEW_RESULTS.md`.
