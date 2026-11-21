# DEPLOY: T-487 vault fill keeps its browser; codes from Uni's own inboxes

Branch `fix/vault-fill-supervisor`, cut from the live branch `plugin-inject-origin` at `040ef1f07f`.
Nothing live changes until Uni merges and the gateway restarts.

## What changes

1. **The browser stays open while a vault prompt waits.** Root cause of the `supervisor_required` failures
   (11-11, 11-20, 11-21 ×2): `browser_vault_enter_code` blocks on the user's code (the Buzz 🔐 card) for minutes.
   Meanwhile the inactivity janitor (`tools/browser_tool_lifecycle.py::_cleanup_inactive_browser_sessions`) and the
   agent-browser daemon's own idle exit (`AGENT_BROWSER_IDLE_TIMEOUT_MS`, `browser_tool_session.py:161`) closed the
   browser at 120 s. The supervisor gave up after five reconnects, and `_eval_js_secret`
   (`tools/browser_vault_tool.py:139`) found no supervisor. Every failure in the logs waited 159–591 s.
   Now `hold_browser_session()` keeps the janitor off the session and pings its daemon, and the vault fill,
   save-login and enter-code handlers hold the page for the whole call. Not the 11-18 machine move: the 11-11
   failure predates it.
2. **Codes sent to Uni's own inboxes** (owner's rule, 11-21). `browser_vault_enter_code` takes `source: "own_inbox"`
   (plus `inbox`, `sender`, `site`, `wait_s`). Hermes runs the configured reader, takes the newest unused code from
   the last 10 minutes and types it over the supervisor socket. The model sees only "entered" / "no code found";
   the code is not in argv, tool output, logs or the session DB. Limits: only `vault.own_inbox.addresses`; the
   reader opens only the inboxes named on its own command line; the call names the `sender` (a From domain or
   address, so another site's newer code is never read); a used code means "wait for the next mail" (the reader
   waits on Stalwart's push stream, up to `wait_s`); the page origin must be bound to the saved login,
   listed in `vault.own_inbox.origins`, or named in the call (`site`). Every attempt writes one
   `AUDIT vault own-inbox code <outcome>: origin=… basis=item|config|named inbox=… sender=…` line to `agent.log`.
   With no `vault.own_inbox` config the schema is unchanged.

## Merge (on uni, in the live checkout)

```bash
cd ~/REPOS/hermes-agent
git status --short                       # must be empty
git log -1 --format=%h                   # expect 040ef1f07f; if it moved: git rebase plugin-inject-origin fix/vault-fill-supervisor
git merge --ff-only fix/vault-fill-supervisor
git push fork plugin-inject-origin       # fork only; no upstream PR
```

## Config (Uni edits `~/.hermes/config.yaml`)

Add under `vault:` (the two addresses are Uni's own inboxes from the 11-21 addendum; the run report has the block
with them and the two credential paths filled in):

```yaml
  own_inbox:
    reader: [sudo, -n, /usr/bin/python3, -I, <live checkout>/scripts/own_inbox_code.py,
             --jmap, "<agi inbox>=<root-only Stalwart password file>",
             --agentmail, "<uni inbox>=<AgentMail curl config>"]
    addresses: [<agi inbox>, <uni inbox>]
    origins: []
```

The reader runs as root because the Stalwart secret is root-only and the mail ports refuse non-root connections
on this box. The gateway unit has `NoNewPrivileges=no`, so `sudo -n` works from it today. When passwordless sudo
is retired (SOUL, 11-19), install the reader root-owned (e.g. `/usr/local/libexec/own-inbox-code`, mode 755,
root:root) with a sudoers line for that exact path, and point `reader` at it. Never list the owner's mailboxes.

## Restart

At the next planned gateway restart (Uni's call or the owner's). Nothing to migrate.

## Check after the restart

1. `grep -c "Vault fill requires the supervised" ~/.hermes/logs/agent.log` stops growing on code entries.
2. In a room: a site that mails a code to Uni's inbox → `browser_vault_enter_code(source="own_inbox", sender=…)`
   → `AUDIT vault own-inbox code entered` in `agent.log`, and the code is nowhere in the transcript.

## Proposed wording (Uni applies; this branch does not touch ~/.hermes)

SOUL.md, the "Never type a password…" line, replace its second sentence with:

> A code sent to one of Uni's own inboxes: call `browser_vault_enter_code` with `source="own_inbox"` (and
> `sender=` the domain the site mails from); Hermes reads and enters it and you never see it. Never read such a code yourself
> into chat, a log or `browser_exec`. Codes for the owner's accounts come from their prompt (no `source`).

Skill `agent-web-logins`, "Magic-link / emailed-link sign-ins": add after the AgentMail line:

> One-time codes (not links) in your own inboxes: `browser_vault_enter_code(source="own_inbox", sender=<the
> domain the site mails from>)`, never a curl loop. It waits up to `wait_s` (default 60 s) for the mail.

## Subtract

Codes in Uni's own inboxes no longer go through `agimail.py grab` + a private file + a manual fill, or the AgentMail
curl loop in `agent-web-logins`: once this is live, Uni drops the code half of those (agimail keeps `list` and
links). The second way to read mail stays only because Hermes needs the code in-process and never on disk.

## Roll back

`git revert` the T-487 commits on `plugin-inject-origin`, remove `vault.own_inbox`, restart at the next window.
