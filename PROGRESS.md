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

## Next
- Part 2: uni-ops memory drop-ins, throwaway-unit pressure test, DEPLOY.md.
