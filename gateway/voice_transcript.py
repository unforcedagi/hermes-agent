"""Compare client voice captions with the gateway's authoritative STT output."""

import re
from collections import Counter
from collections.abc import Sequence


_ATTACHMENT_LINE = re.compile(r"\s*(?:!?\[[^\]]*\]\([^\n]*\)|https?://\S+)\s*")


def strip_duplicate_voice_caption(user_text: str, transcripts: Sequence[str]) -> str:
    """Remove a near-duplicate caption, retaining its standalone attachment lines.

    Compare word occurrences rather than spelling/punctuation, allowing phone and
    gateway STT to disagree slightly. Short captions are too ambiguous to remove.
    """
    lines = user_text.splitlines(keepends=True)
    caption = "".join(line for line in lines if not _ATTACHMENT_LINE.fullmatch(line))
    words = re.findall(r"\w+", caption.lower())
    if len(words) < 3:
        return user_text
    client_tokens = Counter(words)
    # A caption can cover several clips merged into one pending voice event.
    candidates = [*transcripts, " ".join(transcripts)]
    for transcript in candidates:
        gateway_tokens = Counter(re.findall(r"\w+", transcript.lower()))
        shorter = min(len(words), gateway_tokens.total())
        if shorter and (client_tokens & gateway_tokens).total() / shorter >= 0.6:
            return "".join(line for line in lines if _ATTACHMENT_LINE.fullmatch(line)).rstrip("\r\n")
    return user_text
