"""Relay-safe media copies. Callers own the temporary directory and original file."""
import logging
import struct
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)
VIDEO = {'.mp4', '.mov', '.m4v', '.webm'}
AUDIO = {'.mp3', '.ogg', '.opus', '.wav', '.m4a'}
SUPPORTED = VIDEO | AUDIO | {'.png', '.jpg', '.jpeg'}
SAFE = ['-map_metadata', '-1', '-map_chapters', '-1', '-fflags', '+bitexact',
        '-flags:v', '+bitexact', '-flags:a', '+bitexact',
        '-metadata:s:v', 'handler_name=', '-metadata:s:a', 'handler_name=']
ENCODE = ['-c:v', 'libx264', '-x264-params', 'no-info=1', '-pix_fmt', 'yuv420p', '-c:a', 'aac']


def strip_png(src, dst):
    """Preserve the original critical/pixel chunks, including palette transparency."""
    data = Path(src).read_bytes()
    if data[:8] != b'\x89PNG\r\n\x1a\n':
        raise ValueError('invalid PNG signature')
    out = bytearray(data[:8])
    pos = 8
    while pos < len(data):
        n = struct.unpack('>I', data[pos:pos + 4])[0]
        end = pos + 12 + n
        if end > len(data):
            raise ValueError('truncated PNG chunk')
        if data[pos + 4:pos + 8] in {b'IHDR', b'PLTE', b'tRNS', b'IDAT', b'IEND'}:
            out.extend(data[pos:end])
        pos = end
    Path(dst).write_bytes(out)


def strip_jpeg(src, dst):
    """Drop APPn and COM segments without changing compressed image data."""
    data = Path(src).read_bytes()
    if data[:2] != b'\xff\xd8':
        raise ValueError('invalid JPEG signature')
    out = bytearray(data[:2])
    pos = 2
    while pos < len(data):
        start = pos
        if data[pos] != 255:
            raise ValueError('invalid JPEG marker')
        while data[pos] == 255:
            pos += 1
        marker = data[pos]
        pos += 1
        if marker in (0xda, 0xd9):
            out.extend(data[start:])
            break
        size = int.from_bytes(data[pos:pos + 2], 'big')
        if size < 2 or pos + size > len(data):
            raise ValueError('truncated JPEG segment')
        if marker not in range(0xe0, 0xf0) and marker != 0xfe:
            out.extend(data[start:pos + size])
        pos += size
    Path(dst).write_bytes(out)


def clear_mp4_metadata(path):
    """Replace metadata containers with equal-size free atoms, keeping chunk offsets.

    ffmpeg emits even empty udta/meta containers on some versions with bitexact.
    Never move mdat or rewrite its encoded streams.
    """
    with Path(path).open('r+b') as stream:
        def scan(start, end):
            pos = start
            while pos + 8 <= end:
                stream.seek(pos)
                size, kind = struct.unpack('>I4s', stream.read(8))
                header = 8
                if size == 1:
                    size = struct.unpack('>Q', stream.read(8))[0]
                    header = 16
                if size == 0:
                    size = end - pos
                if size < header or pos + size > end:
                    raise ValueError('invalid MP4 atom')
                if kind in {b'udta', b'meta'}:
                    stream.seek(pos + 4)
                    stream.write(b'free')
                    stream.seek(pos + header)
                    remaining = size - header
                    while remaining:
                        block = min(remaining, 65536)
                        stream.write(b'\0' * block)
                        remaining -= block
                elif kind in {b'moov', b'trak', b'mdia', b'minf', b'stbl'}:
                    scan(pos + header, pos + size)
                pos += size
        stream.seek(0, 2)
        scan(0, stream.tell())


def canonicalize(src: Path, directory: Path, *, heavy=False) -> Path:
    """Return a new copy, or the original on unavailable tools/failed conversion.

    No subprocess diagnostics escape here: they can contain private host paths.
    """
    src = Path(src)
    ext = src.suffix.lower()
    if ext not in SUPPORTED:
        return src
    suffix = '.mp4' if ext in VIDEO | AUDIO else '.jpg' if heavy and ext == '.png' else ext
    dst = Path(directory) / ('retry' if heavy else 'canonical')
    dst = dst.with_suffix(suffix)
    try:
        if ext == '.png' and not heavy:
            strip_png(src, dst)
            return dst
        if ext in {'.jpg', '.jpeg'}:
            try:
                strip_jpeg(src, dst)
            except (ValueError, IndexError):
                subprocess.run(['magick', str(src), '-strip', '-quality', '92', str(dst)],
                               check=True, capture_output=True, timeout=600)
            return dst
        if ext == '.png':
            cmd = ['magick', str(src), '-strip', '-quality', '88', str(dst)]
        else:
            cmd = ['ffmpeg', '-y', '-v', 'error', '-nostdin']
            if ext in AUDIO:
                # textfile avoids drawtext filter injection through arbitrary filenames.
                label = Path(directory) / 'label.txt'
                label.write_text(src.name)
                cmd += ['-f', 'lavfi', '-i', 'color=c=0x111111:s=640x360', '-i', str(src),
                        '-vf', f'drawtext=textfile={label}:expansion=none:fontcolor=white:fontsize=48:x=(w-text_w)/2:y=(h-text_h)/2',
                        '-shortest', *SAFE, *ENCODE, '-tune', 'stillimage', '-b:a', '96k']
            else:
                cmd += ['-i', str(src), '-map', '0:v', '-map', '0:a?', *SAFE]
                cmd += ENCODE if heavy or ext == '.webm' else ['-c', 'copy']
            cmd += ['-movflags', '+faststart', str(dst)]
        subprocess.run(cmd, check=True, capture_output=True, timeout=600)
        if suffix == ".mp4":
            clear_mp4_metadata(dst)
        return dst
    except (OSError, ValueError, struct.error, subprocess.SubprocessError) as exc:
        logger.warning('Buzz: canonicalization failed (%s); uploading original', type(exc).__name__)
        return src
