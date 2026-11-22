# T-487 progress

## Plan
1. Hermes: a message that would be refused during a drain is handed back to its platform (Buzz leaves it
   unconsumed on disk, so the restored cursor replays it after the restart). Commands are never held.
2. uni-ops memory: gateway drop-in (oomd omit/avoid), heavy.slice made the kill target (oomd kill + cap),
   workers' oom_score_adj raised; forced-pressure test on throwaway units; DEPLOY.md.

## Done
- Orientation: refusal sites run_inbound.py:698/1028, run_busy.py _send_busy_drain_notice, discard run_turn.py:3668.

- Part 1 committed: hold_for_restart seam (base adapter no-op, Buzz implements), called at the three refusal
  sites and the pending-follow-up discard; MessageEvent.absorb/parts tracks merged messages.
  tests/gateway/test_buzz_restart_hold.py: red on base (both tests), green with fix; merge tracking proven by mutation.
  tests/gateway + tests/plugins/platforms/buzz: 171 failures, all in 54 files that fail the same on base
  (missing optional deps in the worktree venv: telegram, discord, ...). No new failures.

- Part 2 committed in uni-ops (26b6dee, a96e091 and the second-review fix): drop-ins, memory/apply, memory/check,
  memory/pressure-test (all 8 control/guarded checks pass on throwaway t487* units).
- Two code reviews; fixes: all-or-nothing hold, staged slot + overflow held by one run_busy helper on every drain
  (also when a queued command cleared the pending item), rewrite keeps merged parts; apply/check never walk an
  empty cgroup path, gateway main process only, check covers every gateway.
- DEPLOY.md, WALKTHROUGH.md, docs (updating.md, messaging/index.md).

- Reviews 3 and 4 fixed: held ids saved with when they were held, pin the cursor in every life until re-read,
  expire 6 h after the hold; held reply-only messages skip the mention gate in the next life; unadopted DMs keep
  their cursor. pressure-test: per-slice ceilings (load-independent), omit-only scenario, staged-change guard before
  every reload. apply --undo reverts only what apply set.

## Next
- Done: sixth review clean; final verify ran (see report). Report. Nothing applied live (Uni runs memory/apply; Aaron restarts the gateway).
