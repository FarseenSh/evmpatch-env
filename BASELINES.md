# Baselines

Measured runs of the legacy tool environment (`load_environment`, `local` backend) with an
API model. Numbers are per rollout; `inconclusive` is the grader's third outcome (no valid
evidence, never a reward), reported separately from `not_solved`.

## DeepSeek V4 Pro, 4 tasks x 4 rollouts, 30-turn budget

```bash
vf-eval evmpatch-env -m accounts/fireworks/models/deepseek-v4-pro-0813 \
    -b https://api.fireworks.ai/inference/v1 -k FIREWORKS_API_KEY \
    -n 4 -r 4 -c 4 -t 12000 -a '{"split":"train","backend":"local","max_turns":30}' -s
```

| task | rollouts | solved | not solved | inconclusive | of which undeclared block reason |
|---|---|---|---|---|---|
| `bitallx_2025_05` | 4 | 2 | 0 | 2 | 2 |
| `goldreserve_2025_02` | 4 | 1 | 2 | 1 | 0 |
| `mcai_2025_01` | 4 | 3 | 0 | 1 | 0 |
| `ngp_2025_09` | 4 | 4 | 0 | 0 | 0 |
| all | 16 | 10 | 2 | 4 | 2 |

pass@1 (mean over rollouts) 0.625; every task solved at least once. Mean 5.3 tool turns,
about 113k input and 10.5k output tokens per rollout (the GoldReserve source is large), about
4 minutes per episode including grading. Two inconclusive rollouts block the exploit with a
revert reason the task does not declare; under the literal-reason policy that is a curation
signal for the task's `recognised_block_reasons`, not a reward. A per-turn cap of 4,096
output tokens truncated the model's reasoning mid-episode in a preliminary run; the numbers
above use a 12,000-token cap.

The grade components (`outcome_solved`, `outcome_not_solved`, `outcome_inconclusive`,
`unrecognised_block_reason`, `poc_blocked`, `hidden_all_pass`, `compiled`, `canary_fired`)
are reported as weight-0 metrics alongside the scalar reward, so a run shows why episodes
scored 0.
