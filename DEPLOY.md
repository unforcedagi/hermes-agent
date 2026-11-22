# T-487 deploy: messages wait during a restart; the gateway is never the memory killer's pick

Two parts, independent. Do the memory guard first: it needs no restart.

## 1. Memory guard (uni-ops 26b6dee) — Uni runs it, live, no restart

    ~/Code/uni-ops/memory/apply

Installs the drop-ins from `~/Code/uni-ops/memory/dropins/` into `~/.config/systemd/user/`, runs
`systemctl --user daemon-reload`, sets the running gateway's processes to oom_score_adj 100 and the running mts
workers' to 900 (`choom`, unprivileged), then runs the check. Nothing restarts.

- Check: `~/Code/uni-ops/memory/check` — exit 0 and every line `ok`: gateway `user.oomd_omit` = 1, OOMPolicy
  continue, oom_score_adj 100; heavy.slice watched by oomd at 30.00%/10s; each mts worker's main process at 900;
  call capture `user.oomd_avoid` = 1; core's T-335 guard still in place.
- Undo: `~/Code/uni-ops/memory/apply --undo` (removes the T-487 drop-ins, heavy.slice back to MemoryHigh=64G only,
  scores back to 200; the T-335 core guard stays).
- Takes effect: oomd marks, heavy.slice's kill rule and OOMPolicy at daemon-reload; OOMScoreAdjust at the next start
  of each unit (apply's choom covers the processes already running).
- Proof it works, on throwaway units: `~/Code/uni-ops/memory/pressure-test` (about 2 min, never touches live units).
- Trade-off to know: a burst of workers that holds heavy.slice at its 64G ceiling until 30% stalled now loses its
  biggest worker (mts records it failed); before, it only slowed.

## 2. Hermes: hold instead of refuse (branch fix/restart-hold, commit on top of plugin-inject-origin)

Uni merges the branch into the fork and pushes it (fork pushes are Uni's). Then the gateway needs one restart to load
the code; Uni asks Aaron for it.

- The restart that loads the fix is drained by the old code, so messages sent during that one drain are still
  refused. Pick a quiet moment, or tell the rooms.
- Check after the restart: send a message in a test room while a restart drains (for example `/restart` while a
  long turn runs elsewhere). The reply is "⏳ Gateway is restarting — I'll answer this when it's back.", the
  gateway log has `Buzz: holding message … until the gateway is back`, and after the restart the message gets a real
  answer. `~/.hermes/buzz/channel-cursors.json` keeps the held id out of `seen` until then.
- Undo: revert the commit on the fork and restart the gateway once more.
- Tests: `scripts/run_tests.sh tests/gateway/test_buzz_restart_hold.py` (fails on the old code, passes on the new).
