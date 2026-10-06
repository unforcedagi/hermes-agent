"""Voice enrichment preserves captions and links without repeating phone STT."""

from unittest.mock import patch

import pytest

from gateway.config import GatewayConfig
from gateway.run import GatewayRunner


LINK = "[voice-20261006-114615.webm](https://buzz.unforced.org/media/abc.webm)"
TRANSCRIPT = "Please bring the blue notebook to our meeting tomorrow."


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "caption,success,drop_caption",
    [
        ("Please bring the blue note book to our meeting tomorrow!", True, True),
        ("", True, False),
        ("Here is background for the budget review.", True, False),
        ("Please bring the blue note book to our meeting tomorrow!", False, False),
    ],
)
async def test_voice_enrichment_keeps_one_transcript_and_original_attachments(
    caption, success, drop_caption, tmp_path
):
    runner = GatewayRunner.__new__(GatewayRunner)
    runner.config = GatewayConfig(stt_enabled=True)
    user_text = f"{caption}\n{LINK}" if caption else LINK
    result = {"success": success, "transcript": TRANSCRIPT, "error": "unavailable"}
    with (
        patch("tools.transcription_tools.transcribe_audio", return_value=result),
        patch("tools.transcription_tools.transcribe_audio_local_fallback", return_value=result),
    ):
        enriched, transcripts = await runner._enrich_message_with_transcription(
            user_text, [str(tmp_path / "voice.webm")]
        )
    assert enriched.count(LINK) == 1
    if success:
        assert transcripts == [TRANSCRIPT]
        expected_caption = LINK if drop_caption else user_text
        assert enriched == f'"{TRANSCRIPT}"\n\n{expected_caption}'
    else:
        assert transcripts == []
        assert "could not be transcribed automatically" in enriched
        assert enriched.endswith(user_text)


@pytest.mark.parametrize(
    "caption,transcripts,drop",
    [
        ("HELLO, brave world!", ["hello brave world"], True),
        ("hello world", ["hello world"], False),
        ("one two three four five", ["one two three six seven"], True),
        ("one two three four five", ["one two six seven eight"], False),
        ("first clip says hello second clip says goodbye", ["first clip says hello", "second clip says goodbye"], True),
        ("hello brave world", [], False),
    ],
)
def test_caption_overlap_preserves_attachment_lines(caption, transcripts, drop):
    from gateway.voice_transcript import strip_duplicate_voice_caption

    links = f"{LINK}\n[attachment](https://buzz.unforced.org/media/other.webm)"
    text = f"{caption}\n{links}"
    assert strip_duplicate_voice_caption(text, transcripts) == (links if drop else text)
