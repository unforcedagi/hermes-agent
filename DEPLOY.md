# DEPLOY: T-487 vault fill keeps its browser; codes from Uni's own inboxes

**Update (branch `fix/own-inbox-noroot`, off `plugin-inject-origin` at 6ddfaefeda, which already holds the sections below): no sudo on the reader's path.** Hermes
no longer runs a reader command. It sends one request line to the inbox reader *service* over a unix socket
(`vault.own_inbox.socket`) and reads one reply. The service (already installed on the machine by the admin's setup
step, with its own read-only mail login) holds the mailbox credentials; Hermes and its user never do. Sections below
are updated for it; the machine steps, exact paths and the threat note are in the private setup repo's own-inbox note
(the run report names it).

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
   (plus `inbox`, `sender`, `site`, `wait_s`). Hermes asks the inbox reader service on its socket for the newest unused
   code from the last 10 minutes and types it over the supervisor socket. The model sees only "entered" / "no code found";
   the code is not in argv, tool output, logs or the session DB. Limits: only `vault.own_inbox.addresses`; the
   reader opens only the inboxes named in its own root-owned unit, answers only Hermes's uid (SO_PEERCRED), takes
   only its five request fields, and queries only the account named by the inbox; the call names the `sender` (a From domain or
   address, so another site's newer code is never read); a used code means "wait for the next mail" (the reader
   checks every 5 s, up to `wait_s`: Stalwart sends no push for a shared Inbox, which is what its login reads); the page origin must be bound to the saved login,
   listed in `vault.own_inbox.origins`, or named in the call (`site`). Every attempt writes one
   `AUDIT vault own-inbox code <outcome>: origin=… basis=item|config|named inbox=… sender=…` line to `agent.log`.
   With no `vault.own_inbox.socket` the schema is unchanged: a config that still has the old `reader:` key and no
   `socket:` turns the feature off (no sudo is ever run).

## Merge (on uni, in the live checkout)

```bash
cd ~/REPOS/hermes-agent
git status --short                       # must be empty
git log -1 --format=%h                   # expect 6ddfaefeda; if it moved: git rebase plugin-inject-origin fix/own-inbox-noroot
git merge --ff-only fix/own-inbox-noroot
git push fork plugin-inject-origin       # fork only; no upstream PR
```

Then the admin's setup check, which compares the installed reader with the merged file:
`sudo <setup repo>/s2-70-own-inbox-reader.sh check` (all pass; before the merge it reports "reader differs").

## Config (Uni edits `~/.hermes/config.yaml`)

Replace the `reader:` line (the sudo command) with the socket. The diff, with the machine's values in the run report:

```diff
   own_inbox:
-    reader: [sudo, -n, /usr/bin/python3, -I, <live checkout>/scripts/own_inbox_code.py,
-             --jmap, "<agi inbox>=<root-only Stalwart password file>",
-             --agentmail, "<uni inbox>=<AgentMail curl config>"]
+    socket: /run/own-inbox-code.sock
     addresses: [<agi inbox>, <uni inbox>]
     origins: []
```

No sudo, no credential path and no reader argument is left in Hermes's config. Which inboxes the service reads, with
which login and against which server, is fixed in its root-owned unit.

## Restart

At the next planned gateway restart (Uni's call or the owner's). Nothing to migrate.

## Check after the restart

1. `grep -c "Vault fill requires the supervised" ~/.hermes/logs/agent.log` stops growing on code entries.
1b. `sudo journalctl -u 'own-inbox-code@*' -o cat | grep audit` shows one line per request (peer uid, inbox,
   sender, outcome; never the code).
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
The sudo reader command (`vault.own_inbox.reader`) goes the day this merges: the code no longer reads that key.

## Roll back

`git revert` the T-487 commits on `plugin-inject-origin`, remove `vault.own_inbox`, restart at the next window.
The reader service alone: `sudo <setup repo>/s2-70-own-inbox-reader.sh undo` (stops it, revokes its mail login's
share and deletes that login); Hermes then answers "the inbox reader could not be reached".
