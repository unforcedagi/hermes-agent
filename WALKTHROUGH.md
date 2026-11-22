# Walkthrough: a message sent during a restart is answered after it

What is judged: the reply a person sees in a Buzz room while the gateway restarts, and that their message is
answered afterwards instead of lost. Nothing else on screen changes.

Run: `scripts/run_tests.sh tests/gateway/test_buzz_restart_hold.py -v` (a fake relay and a real Buzz adapter, two
gateway lives). No screenshots: the change is one chat reply, and the live gateway can't be restarted for a demo
before Aaron's restart (DEPLOY.md, check step, shows it live).

1. **Before.** Show the old reply: "⏳ Gateway is restarting and is not accepting new work right now."
   Narration: "On 11-21 two messages in #systems got this, and were never answered."
2. **During the restart now.** Show: "⏳ Gateway is restarting — I'll answer this when it's back."
   Narration: "Now the gateway hands the message back to Buzz; the relay keeps it."
3. **After the restart.** The test's second gateway life answers the held message, and nothing else.
   Narration: "The new process picks it up from where it left off and answers it."
4. **Commands are not held.** A slash command during the drain is still refused.
   Narration: "A held /restart would run again after the restart, so commands aren't held."
