# DEPLOY: T-488 Hermes local-model fixes

Branch `fix/mcp-breaker-param-errors-max-tokens`, cut from the live branch `plugin-inject-origin` at `350b5070c5`.
Nothing live changes until Uni merges and the gateway restarts.

## What changes

1. **MCP breaker.** A JSON-RPC `-32602 Invalid params` reply (the Parachute vault's answer to an update without
   `if_updated_at`) is now the tool's answer: it neither adds nor clears a breaker strike, and the model sees the
   server's message and hint. Before, three in a row marked the server "unreachable" for 60 s.
2. **Output cap.** `model.max_tokens` in config.yaml now reaches the wire for the configured default model on its own
   route. With no setting nothing changes: the server's default applies. The live config does not set it, so live
   requests to Claude are unchanged.

## Merge (on uni, in the live checkout)

```bash
cd ~/REPOS/hermes-agent
git status --short                       # must be empty
git log -1 --format=%h                   # expect 350b5070c5; if the live branch moved, use the rebase line below
git merge --ff-only fix/mcp-breaker-param-errors-max-tokens
# if the live branch moved on:  git rebase plugin-inject-origin fix/mcp-breaker-param-errors-max-tokens && git merge --ff-only fix/mcp-breaker-param-errors-max-tokens
git push fork plugin-inject-origin       # keep the fork in step (fork only; no upstream PR)
```

The branch is local to this repo (the worktree shares it) and also pushed to `fork`.

## Restart

At the next planned gateway restart (Uni's call, not as part of this merge):

```bash
systemctl --user restart hermes-gateway-2c0b9ad2.service
```

## Check after the restart

```bash
systemctl --user is-active hermes-gateway-2c0b9ad2.service          # active
journalctl --user -u hermes-gateway-2c0b9ad2.service --since "5 min ago" | grep -iE "traceback|error" | head
```

- Send Uni one ordinary message in a room; it answers as before (the Claude route is untouched).
- The first time a model sends a bad vault argument, `~/.hermes/logs/agent.log` shows
  `rejected the arguments (-32602)` and no `unreachable after 3 consecutive failures` for that server.
- Only if a local model becomes the main model: set `model.max_tokens` (e.g. 16384) next to `model.context_length`.

## Roll back

```bash
cd ~/REPOS/hermes-agent && git reset --keep 350b5070c5 && systemctl --user restart hermes-gateway-2c0b9ad2.service
```

## After it is live

- The bench's `sim/hermes_nobreaker.py` (in `~/Code/wt/inkling-sim`, hybrid-experiment session) was a stopgap for
  fix 1 and can go; `SIM_BREAKER=off` is then unnecessary.
