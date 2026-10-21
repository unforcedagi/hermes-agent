import asyncio
import hashlib
import json
import struct
import subprocess
import zlib
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from plugins.platforms.buzz import media_canon as canon
from tests.gateway._plugin_adapter_loader import load_plugin_adapter
from gateway.config import PlatformConfig

mod = load_plugin_adapter('buzz')


def run(*args):
    return subprocess.run(args, check=True, capture_output=True).stdout


@pytest.fixture
def video(tmp_path):
    path = tmp_path / 'WALKTHROUGH.mp4'
    run('ffmpeg', '-y', '-v', 'error', '-f', 'lavfi', '-i', 'color=c=blue:s=160x120:d=0.6',
        '-f', 'lavfi', '-i', 'sine=frequency=440:duration=0.6', '-c:v', 'libx264', '-c:a', 'aac',
        '-metadata', 'title=private test metadata', str(path))
    return path


def probe(path):
    return json.loads(run('ffprobe', '-v', 'error', '-show_streams', '-show_format', '-of', 'json', str(path)))


def atoms(data):
    result = []
    pos = 0
    while pos + 8 <= len(data):
        size, kind = struct.unpack('>I4s', data[pos:pos + 8])
        assert size >= 8
        result.append(kind)
        if kind in {b'moov', b'trak', b'mdia', b'minf', b'stbl', b'udta'}:
            result.extend(atoms(data[pos + 8:pos + size]))
        pos += size
    return result


def test_mp4_metadata_faststart(video, tmp_path):
    before = video.read_bytes()
    assert b'udta' in atoms(before)
    out = canon.canonicalize(video, tmp_path)
    kinds = atoms(out.read_bytes())
    assert b'udta' not in kinds and b'meta' not in kinds
    assert kinds.index(b'moov') < kinds.index(b'mdat')
    info = probe(out)
    assert 'title' not in info['format'].get('tags', {})
    assert video.read_bytes() == before and out != video


def test_narration_survives(video, tmp_path):
    out = canon.canonicalize(video, tmp_path)
    assert any(s['codec_type'] == 'audio' for s in probe(out)['streams'])


def chunk(kind, data):
    return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))


def png(path):
    path.write_bytes(b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
                     + chunk(b'tEXt', b'private\0metadata') + chunk(b'IDAT', zlib.compress(b'\0\xff\0\0')) + chunk(b'IEND', b''))
    return path


def test_png_pixels(tmp_path):
    src = png(tmp_path / 'input.png')
    out = canon.canonicalize(src, tmp_path)
    assert b'tEXt' not in out.read_bytes()
    def pixels(p):
        return run('ffmpeg', '-v', 'error', '-i', str(p), '-f', 'rawvideo', '-pix_fmt', 'rgb24', '-')
    assert hashlib.sha256(pixels(src)).digest() == hashlib.sha256(pixels(out)).digest()
    assert b'tEXt' in src.read_bytes()


def test_audio_wrap(tmp_path):
    src = tmp_path / "voice's: sample.wav"
    run('ffmpeg', '-y', '-v', 'error', '-f', 'lavfi', '-i', 'sine=duration=0.3', str(src))
    out = canon.canonicalize(src, tmp_path)
    assert out.suffix == '.mp4'
    assert {s['codec_type'] for s in probe(out)['streams']} == {'video', 'audio'}
    assert b'udta' not in atoms(out.read_bytes())


def adapter():
    return mod.BuzzAdapter(PlatformConfig(enabled=True, extra={'relay_url': 'https://example.invalid'}))


def test_retry_and_cleanup(video):
    a = adapter()
    a._run_cli = AsyncMock(return_value=(4, '', 'not found'))
    paths = []
    async def send(args, text):
        p = Path(args[args.index('--file') + 1])
        assert p.is_file()
        paths.append(p)
        return (4, '', 'relay error 422: media contains metadata') if len(paths) == 1 else (0, '{"accepted":true,"event_id":"ok"}', '')
    a._run_message_send = send
    result = asyncio.run(a.send_video('test', str(video)))
    assert result.success and len(paths) == 2 and paths[0] != paths[1]
    assert all(not p.exists() for p in paths)
    assert video.is_file()


def test_existing_hash_unchanged(video):
    a = adapter()
    async def get(args):
        Path(args[args.index('-o') + 1]).write_bytes(video.read_bytes())
        return 0, '', ''
    a._run_cli = get
    a._run_message_send = AsyncMock(return_value=(0, '{"accepted":true,"event_id":"ok"}', ''))
    assert asyncio.run(a.send_video('test', str(video))).success
    assert a._run_message_send.call_args.args[0][5] == str(video)


def test_missing_ffmpeg_uploads_original(video, tmp_path, monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError('ffmpeg')
    monkeypatch.setattr(canon.subprocess, 'run', missing)
    assert canon.canonicalize(video, tmp_path) == video


def test_webm_transcodes_with_audio(tmp_path):
    src = tmp_path / 'recording.webm'
    run('ffmpeg', '-y', '-v', 'error', '-f', 'lavfi', '-i', 'color=s=160x120:d=0.3',
        '-f', 'lavfi', '-i', 'sine=duration=0.3', '-c:v', 'libvpx-vp9', '-c:a', 'libopus', str(src))
    out = canon.canonicalize(src, tmp_path)
    assert {s['codec_name'] for s in probe(out)['streams']} == {'h264', 'aac'}
    assert b'udta' not in atoms(out.read_bytes())


def test_jpeg_lossless_strip(tmp_path):
    src = tmp_path / 'image.jpg'
    run('magick', '-size', '4x4', 'xc:blue', str(src))
    data = src.read_bytes()
    segment = b'Exif\0\0private metadata'
    src.write_bytes(data[:2] + b'\xff\xe1' + struct.pack('>H', len(segment) + 2) + segment + data[2:])
    out = canon.canonicalize(src, tmp_path)
    assert b'private metadata' not in out.read_bytes()
    # Everything from the start-of-scan onward must remain byte-identical.
    assert out.read_bytes().split(b'\xff\xda', 1)[1] == src.read_bytes().split(b'\xff\xda', 1)[1]


def test_heavy_png_converts_to_jpeg(tmp_path):
    src = png(tmp_path / 'input.png')
    out = canon.canonicalize(src, tmp_path, heavy=True)
    assert out.suffix == '.jpg' and out.read_bytes().startswith(b'\xff\xd8')
    assert src.read_bytes().startswith(b'\x89PNG')


def test_no_retry_for_unrelated_error(video):
    a = adapter()
    a._run_cli = AsyncMock(return_value=(4, '', 'not found'))
    a._run_message_send = AsyncMock(return_value=(4, '', 'relay error 503: unavailable'))
    assert not asyncio.run(a.send_video('test', str(video))).success
    assert a._run_message_send.await_count == 1


def test_failed_conversion_logs_reason_and_preserves_original(video, tmp_path, monkeypatch, caplog):
    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(1, args[0], stderr=b'/private/host/path')
    monkeypatch.setattr(canon.subprocess, 'run', fail)
    before = video.read_bytes()
    assert canon.canonicalize(video, tmp_path) == video
    assert video.read_bytes() == before
    assert 'CalledProcessError' in caplog.text and 'uploading original' in caplog.text
    assert '/private/host' not in caplog.text
