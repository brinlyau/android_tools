#!/usr/bin/env python3
"""
Android Sparse Image Tool

Parse, inspect, validate, and convert Android sparse images (.img).
Supports split sparse images (system.img, system.img.0001, etc.),
super.img sparse containers, and brotli-compressed images (.img.br).

Sparse format: https://android.googlesource.com/platform/system/core/+/refs/heads/main/libsparse/sparse_format.h
"""

import argparse
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    import brotli
    HAS_BROTLI = True
except ImportError:
    try:
        import brotlicffi as brotli
        HAS_BROTLI = True
    except ImportError:
        HAS_BROTLI = False

SPARSE_MAGIC = 0xED26FF3A

# Chunk types
CHUNK_RAW       = 0xCAC1
CHUNK_FILL      = 0xCAC2
CHUNK_DONT_CARE = 0xCAC3
CHUNK_CRC32     = 0xCAC4

CHUNK_NAMES = {
    CHUNK_RAW: "RAW",
    CHUNK_FILL: "FILL",
    CHUNK_DONT_CARE: "DONT_CARE",
    CHUNK_CRC32: "CRC32",
}

# Header: magic(4) major(2) minor(2) header_sz(2) chunk_hdr_sz(2)
#          block_sz(4) total_blocks(4) total_chunks(4) checksum(4)
SPARSE_HEADER_FMT = "<IHHHHIIIII"
SPARSE_HEADER_SIZE = struct.calcsize(SPARSE_HEADER_FMT)

# Chunk header: type(2) reserved(2) chunk_sz(4) total_sz(4)
CHUNK_HEADER_FMT = "<HHII"
CHUNK_HEADER_SIZE = struct.calcsize(CHUNK_HEADER_FMT)


class SparseImage:
    def __init__(self, path):
        self.path = path
        self.chunks = []
        self.header = None
        self._parse()

    def _parse(self):
        with open(self.path, "rb") as f:
            hdr = f.read(SPARSE_HEADER_SIZE)
            if len(hdr) < SPARSE_HEADER_SIZE:
                raise ValueError("File too small for sparse header")

            fields = struct.unpack(SPARSE_HEADER_FMT, hdr)
            magic = fields[0]
            if magic != SPARSE_MAGIC:
                raise ValueError(
                    f"Not a sparse image (magic: 0x{magic:08X}, "
                    f"expected: 0x{SPARSE_MAGIC:08X})"
                )

            self.header = {
                "magic": magic,
                "major_version": fields[1],
                "minor_version": fields[2],
                "header_size": fields[3],
                "chunk_header_size": fields[4],
                "block_size": fields[5],
                "total_blocks": fields[6],
                "total_chunks": fields[7],
                "checksum": fields[8],
                "image_checksum": fields[9] if len(fields) > 9 else 0,
            }

            # Seek past any extra header bytes
            if self.header["header_size"] > SPARSE_HEADER_SIZE:
                f.seek(self.header["header_size"])

            block_size = self.header["block_size"]
            output_offset = 0

            for i in range(self.header["total_chunks"]):
                chunk_hdr = f.read(CHUNK_HEADER_SIZE)
                if len(chunk_hdr) < CHUNK_HEADER_SIZE:
                    break

                ctype, _, chunk_blocks, total_bytes = struct.unpack(
                    CHUNK_HEADER_FMT, chunk_hdr
                )

                # Extra chunk header bytes
                extra = self.header["chunk_header_size"] - CHUNK_HEADER_SIZE
                if extra > 0:
                    f.read(extra)

                data_size = total_bytes - self.header["chunk_header_size"]
                data_offset = f.tell()

                chunk = {
                    "index": i,
                    "type": ctype,
                    "type_name": CHUNK_NAMES.get(ctype, f"UNKNOWN(0x{ctype:04X})"),
                    "chunk_blocks": chunk_blocks,
                    "total_bytes": total_bytes,
                    "data_size": data_size,
                    "data_offset": data_offset,
                    "output_offset": output_offset,
                    "output_size": chunk_blocks * block_size,
                }

                if ctype == CHUNK_FILL:
                    if data_size >= 4:
                        fill_val = struct.unpack("<I", f.read(4))[0]
                        chunk["fill_value"] = fill_val
                        if data_size > 4:
                            f.seek(data_size - 4, 1)
                    else:
                        f.seek(data_size, 1)
                elif ctype == CHUNK_CRC32:
                    if data_size >= 4:
                        crc = struct.unpack("<I", f.read(4))[0]
                        chunk["crc32"] = crc
                        if data_size > 4:
                            f.seek(data_size - 4, 1)
                    else:
                        f.seek(data_size, 1)
                else:
                    f.seek(data_size, 1)

                self.chunks.append(chunk)
                output_offset += chunk_blocks * block_size

    @property
    def raw_size(self):
        return self.header["total_blocks"] * self.header["block_size"]

    @property
    def sparse_size(self):
        return os.path.getsize(self.path)

    @property
    def compression_ratio(self):
        raw = self.raw_size
        if raw == 0:
            return 0
        return (1 - self.sparse_size / raw) * 100

    def info(self):
        h = self.header
        print(f"File:           {self.path}")
        print(f"Sparse size:    {self.sparse_size:,} bytes ({self.sparse_size / 1024 / 1024:.1f} MB)")
        print(f"Raw size:       {self.raw_size:,} bytes ({self.raw_size / 1024 / 1024:.1f} MB)")
        print(f"Compression:    {self.compression_ratio:.1f}%")
        print(f"Version:        {h['major_version']}.{h['minor_version']}")
        print(f"Block size:     {h['block_size']}")
        print(f"Total blocks:   {h['total_blocks']}")
        print(f"Total chunks:   {h['total_chunks']}")
        if h.get("checksum"):
            print(f"Checksum:       0x{h['checksum']:08X}")

        # Chunk type summary
        type_counts = {}
        type_blocks = {}
        for c in self.chunks:
            name = c["type_name"]
            type_counts[name] = type_counts.get(name, 0) + 1
            type_blocks[name] = type_blocks.get(name, 0) + c["chunk_blocks"]

        print(f"\nChunk breakdown:")
        for name in ("RAW", "FILL", "DONT_CARE", "CRC32"):
            if name in type_counts:
                blocks = type_blocks[name]
                size = blocks * h["block_size"]
                print(f"  {name:<12} {type_counts[name]:>5} chunks, "
                      f"{blocks:>8} blocks ({size / 1024 / 1024:.1f} MB)")

    def dump_chunks(self, limit=None):
        """Print detailed chunk listing."""
        bs = self.header["block_size"]
        print(f"\n{'#':<5} {'Type':<12} {'Blocks':<10} {'Output Offset':<18} {'Data Size':<14} {'Extra'}")
        print("-" * 80)
        for c in self.chunks[:limit]:
            extra = ""
            if c["type"] == CHUNK_FILL:
                fv = c.get("fill_value", 0)
                if fv == 0:
                    extra = "zeros"
                else:
                    extra = f"0x{fv:08X}"
            elif c["type"] == CHUNK_CRC32:
                extra = f"0x{c.get('crc32', 0):08X}"

            print(f"{c['index']:<5} {c['type_name']:<12} {c['chunk_blocks']:<10} "
                  f"0x{c['output_offset']:012X}  {c['data_size']:<14,} {extra}")

        if limit and len(self.chunks) > limit:
            print(f"  ... ({len(self.chunks) - limit} more chunks)")

    def unsparse(self, output_path, show_progress=True):
        """Convert sparse image to raw image."""
        bs = self.header["block_size"]
        total = self.raw_size

        with open(self.path, "rb") as fin, open(output_path, "wb") as fout:
            written = 0
            for c in self.chunks:
                out_size = c["chunk_blocks"] * bs

                if c["type"] == CHUNK_RAW:
                    fin.seek(c["data_offset"])
                    remaining = c["data_size"]
                    while remaining > 0:
                        chunk = min(remaining, 1024 * 1024)
                        data = fin.read(chunk)
                        if not data:
                            break
                        fout.write(data)
                        remaining -= len(data)
                    # Pad if data_size < out_size
                    pad = out_size - c["data_size"]
                    if pad > 0:
                        fout.write(b'\x00' * pad)

                elif c["type"] == CHUNK_FILL:
                    fill = c.get("fill_value", 0)
                    if fill == 0:
                        fout.seek(out_size, 1)
                    else:
                        fill_bytes = struct.pack("<I", fill)
                        for _ in range(out_size // 4):
                            fout.write(fill_bytes)

                elif c["type"] == CHUNK_DONT_CARE:
                    fout.seek(out_size, 1)

                # CRC32 chunks produce no output

                written += out_size
                if show_progress and total > 0:
                    pct = written / total * 100
                    print(f"\r  [{pct:5.1f}%] {written / 1024 / 1024:.1f} / {total / 1024 / 1024:.1f} MB", end="", flush=True)

            # Truncate to exact size (in case of trailing DONT_CARE seek)
            fout.truncate(total)

        if show_progress:
            print()
        print(f"[+] Written: {output_path} ({total / 1024 / 1024:.1f} MB)")

    def extract_range(self, output_path, start_block, count, show_progress=True):
        """Extract a range of blocks from the sparse image to a raw file."""
        bs = self.header["block_size"]
        start_offset = start_block * bs
        end_offset = start_offset + count * bs

        with open(self.path, "rb") as fin, open(output_path, "wb") as fout:
            for c in self.chunks:
                chunk_start = c["output_offset"]
                chunk_end = chunk_start + c["output_size"]

                # Skip chunks entirely outside our range
                if chunk_end <= start_offset or chunk_start >= end_offset:
                    continue

                # Calculate overlap
                overlap_start = max(chunk_start, start_offset)
                overlap_end = min(chunk_end, end_offset)
                overlap_size = overlap_end - overlap_start

                # Offset within this chunk
                inner_offset = overlap_start - chunk_start

                if c["type"] == CHUNK_RAW:
                    fin.seek(c["data_offset"] + inner_offset)
                    remaining = overlap_size
                    while remaining > 0:
                        chunk = min(remaining, 1024 * 1024)
                        data = fin.read(chunk)
                        if not data:
                            break
                        fout.write(data)
                        remaining -= len(data)

                elif c["type"] == CHUNK_FILL:
                    fill = c.get("fill_value", 0)
                    if fill == 0:
                        fout.write(b'\x00' * overlap_size)
                    else:
                        fill_bytes = struct.pack("<I", fill)
                        for _ in range(overlap_size // 4):
                            fout.write(fill_bytes)

                elif c["type"] == CHUNK_DONT_CARE:
                    fout.write(b'\x00' * overlap_size)

        size = count * bs
        print(f"[+] Extracted blocks {start_block}-{start_block + count}: "
              f"{output_path} ({size / 1024 / 1024:.1f} MB)")

    def validate(self):
        """Validate the sparse image structure."""
        bs = self.header["block_size"]
        errors = []
        warnings = []

        # Check total blocks match
        actual_blocks = sum(c["chunk_blocks"] for c in self.chunks)
        if actual_blocks != self.header["total_blocks"]:
            errors.append(
                f"Block count mismatch: header says {self.header['total_blocks']}, "
                f"chunks sum to {actual_blocks}"
            )

        # Check chunk count
        if len(self.chunks) != self.header["total_chunks"]:
            warnings.append(
                f"Chunk count mismatch: header says {self.header['total_chunks']}, "
                f"parsed {len(self.chunks)}"
            )

        # Check RAW chunk data sizes
        for c in self.chunks:
            if c["type"] == CHUNK_RAW:
                expected = c["chunk_blocks"] * bs
                if c["data_size"] != expected:
                    errors.append(
                        f"Chunk {c['index']}: RAW data size {c['data_size']} "
                        f"!= expected {expected}"
                    )
            elif c["type"] == CHUNK_FILL:
                if c["data_size"] != 4:
                    warnings.append(
                        f"Chunk {c['index']}: FILL data size {c['data_size']} != 4"
                    )

        # Check file size covers all chunk data
        file_size = os.path.getsize(self.path)
        for c in self.chunks:
            if c["type"] == CHUNK_RAW:
                end = c["data_offset"] + c["data_size"]
                if end > file_size:
                    errors.append(
                        f"Chunk {c['index']}: data extends past EOF "
                        f"(offset {end} > file size {file_size})"
                    )

        if errors:
            print(f"[!] {len(errors)} error(s):")
            for e in errors:
                print(f"  - {e}")
        if warnings:
            print(f"[?] {len(warnings)} warning(s):")
            for w in warnings:
                print(f"  - {w}")
        if not errors and not warnings:
            print("[+] Sparse image is valid")

        return len(errors) == 0

    def md5(self):
        """Compute MD5 of the raw (unsparsed) output without writing to disk."""
        bs = self.header["block_size"]
        h = hashlib.md5()

        with open(self.path, "rb") as fin:
            pos = 0
            for c in self.chunks:
                out_size = c["chunk_blocks"] * bs

                if c["type"] == CHUNK_RAW:
                    fin.seek(c["data_offset"])
                    remaining = c["data_size"]
                    while remaining > 0:
                        chunk = min(remaining, 1024 * 1024)
                        data = fin.read(chunk)
                        if not data:
                            break
                        h.update(data)
                        remaining -= len(data)
                    pad = out_size - c["data_size"]
                    if pad > 0:
                        h.update(b'\x00' * pad)

                elif c["type"] == CHUNK_FILL:
                    fill = c.get("fill_value", 0)
                    if fill == 0:
                        # Hash zeros in chunks to avoid huge alloc
                        remaining = out_size
                        zero_block = b'\x00' * min(1024 * 1024, remaining)
                        while remaining > 0:
                            chunk = min(remaining, len(zero_block))
                            h.update(zero_block[:chunk])
                            remaining -= chunk
                    else:
                        fill_bytes = struct.pack("<I", fill) * (out_size // 4)
                        h.update(fill_bytes)

                elif c["type"] == CHUNK_DONT_CARE:
                    remaining = out_size
                    zero_block = b'\x00' * min(1024 * 1024, remaining)
                    while remaining > 0:
                        chunk = min(remaining, len(zero_block))
                        h.update(zero_block[:chunk])
                        remaining -= chunk

                pos += out_size

        return h.hexdigest()


def find_split_images(path):
    """Find split sparse image parts (e.g. system.img.0000, .0001, ...)."""
    p = Path(path)
    base = p.stem
    parent = p.parent

    # Check for .0000, .0001, ... pattern
    parts = sorted(parent.glob(f"{base}.*"))
    numbered = [
        x for x in parts
        if x.suffix and x.suffix[1:].isdigit()
    ]

    if numbered:
        return [str(x) for x in numbered]
    return [path]


def is_sparse(path):
    """Quick check if a file is a sparse image."""
    try:
        with open(path, "rb") as f:
            magic = struct.unpack("<I", f.read(4))[0]
            return magic == SPARSE_MAGIC
    except (OSError, struct.error):
        return False


def is_brotli(path):
    """Check if a file is brotli-compressed (by extension or magic)."""
    if path.endswith(".br"):
        return True
    # Brotli has no reliable magic bytes, so rely on extension
    return False


def decompress_brotli(br_path, output_path=None, show_progress=True):
    """Decompress a brotli-compressed file.

    Args:
        br_path: Path to .br file
        output_path: Output path. If None, strips .br extension.

    Returns:
        Path to decompressed file.
    """
    if not HAS_BROTLI:
        print("[-] Brotli support not available. Install it:")
        print("    pip install brotli")
        sys.exit(1)

    if not output_path:
        if br_path.endswith(".br"):
            output_path = br_path[:-3]
        else:
            output_path = br_path + ".dec"

    if os.path.exists(output_path):
        print(f"[*] Already decompressed: {output_path}")
        return output_path

    br_size = os.path.getsize(br_path)
    print(f"[*] Decompressing brotli: {br_path} ({br_size / 1024 / 1024:.1f} MB)")

    decompressor = brotli.Decompressor()
    written = 0

    with open(br_path, "rb") as fin, open(output_path, "wb") as fout:
        while True:
            chunk = fin.read(1024 * 1024)
            if not chunk:
                break
            data = decompressor.process(chunk)
            if data:
                fout.write(data)
                written += len(data)
            if show_progress:
                read_pos = fin.tell()
                pct = read_pos / br_size * 100 if br_size else 0
                print(
                    f"\r  [{pct:5.1f}%] read {read_pos / 1024 / 1024:.1f} MB "
                    f"-> {written / 1024 / 1024:.1f} MB",
                    end="", flush=True,
                )

    if show_progress:
        print()

    print(f"[+] Decompressed: {output_path} ({written / 1024 / 1024:.1f} MB)")
    return output_path


def resolve_input(path):
    """Resolve input path — decompress brotli if needed, return usable path."""
    if is_brotli(path):
        return decompress_brotli(path)
    return path


def detect_filesystem(path):
    """Detect filesystem type from a raw image file."""
    try:
        with open(path, "rb") as f:
            # ext2/3/4: magic 0xEF53 at offset 0x438
            f.seek(0x438)
            ext_magic = f.read(2)
            if ext_magic == b'\x53\xef':
                # Read compat features to distinguish ext2/3/4
                f.seek(0x45C)
                compat = struct.unpack("<I", f.read(4))[0]
                incompat = struct.unpack("<I", f.read(4))[0]
                if incompat & 0x40:  # EXTENTS
                    return "ext4"
                elif incompat & 0x4:  # JOURNAL
                    return "ext3"
                return "ext2"

            # erofs: magic 0xE0F5E1E2 at offset 0x400
            f.seek(0x400)
            erofs_magic = struct.unpack("<I", f.read(4))[0]
            if erofs_magic == 0xE0F5E1E2:
                return "erofs"

            # f2fs: magic 0xF2F52010 at offset 0x400
            f.seek(0x400)
            f2fs_magic = struct.unpack("<I", f.read(4))[0]
            if f2fs_magic == 0xF2F52010:
                return "f2fs"

            # squashfs: magic "hsqs" at offset 0
            f.seek(0)
            sq_magic = f.read(4)
            if sq_magic == b'hsqs':
                return "squashfs"

    except (OSError, struct.error):
        pass

    # Fallback: use file command
    try:
        out = subprocess.run(
            ["file", "-b", path], capture_output=True, text=True, timeout=5
        ).stdout.lower()
        for fs in ("ext4", "ext3", "ext2", "erofs", "f2fs", "squashfs"):
            if fs in out:
                return fs
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return None


def mount_image(sparse_path, mountpoint, raw_path=None, keep_raw=False):
    """Unsparse (if needed) and mount an Android image.

    Args:
        sparse_path: Path to the sparse image
        mountpoint: Where to mount
        raw_path: Explicit raw output path. If None, uses a temp file.
        keep_raw: Keep the raw file after mounting (otherwise cleaned up on unmount)
    """
    # Check if the input is already raw (not sparse)
    if not is_sparse(sparse_path):
        raw = sparse_path
        tmp_raw = False
    else:
        img = SparseImage(sparse_path)
        if raw_path:
            raw = raw_path
            tmp_raw = False
        else:
            base = Path(sparse_path).stem
            raw = str(Path(sparse_path).parent / f".{base}.raw.tmp")
            tmp_raw = not keep_raw

        if not os.path.exists(raw):
            print(f"[*] Unsparsing to {raw}...")
            img.unsparse(raw)
        else:
            print(f"[*] Using existing raw image: {raw}")

    # Detect filesystem
    fs = detect_filesystem(raw)
    if not fs:
        print(f"[-] Could not detect filesystem type")
        print(f"    Try: file {raw}")
        if tmp_raw:
            os.remove(raw)
        return False

    print(f"[+] Detected filesystem: {fs}")

    # Create mountpoint
    os.makedirs(mountpoint, exist_ok=True)

    # Build mount command
    mount_cmd = ["sudo", "mount", "-o", "ro,loop"]
    if fs == "erofs":
        mount_cmd += ["-t", "erofs"]
    elif fs == "squashfs":
        mount_cmd += ["-t", "squashfs"]
    elif fs == "f2fs":
        mount_cmd += ["-t", "f2fs"]
    # ext2/3/4 auto-detected by mount

    mount_cmd += [raw, mountpoint]

    print(f"[*] Mounting: {' '.join(mount_cmd)}")
    result = subprocess.run(mount_cmd, capture_output=True, text=True)

    if result.returncode != 0:
        stderr = result.stderr.strip()
        print(f"[-] Mount failed: {stderr}")

        # Suggest fixes
        if "erofs" in stderr or "unknown filesystem" in stderr:
            print(f"    Your kernel may not support {fs}.")
            if fs == "erofs":
                print(f"    Try: sudo modprobe erofs")
        elif "permission" in stderr.lower():
            print(f"    Try running with sudo")

        if tmp_raw:
            os.remove(raw)
        return False

    print(f"[+] Mounted at {mountpoint}")
    print(f"    Filesystem: {fs}")
    print(f"    Raw image:  {raw}")

    # Show basic contents
    try:
        entries = sorted(os.listdir(mountpoint))[:20]
        if entries:
            print(f"    Contents:   {', '.join(entries)}")
            if len(os.listdir(mountpoint)) > 20:
                print(f"                ... and {len(os.listdir(mountpoint)) - 20} more")
    except PermissionError:
        pass

    print(f"\n    To unmount:  sudo umount {mountpoint}")
    if tmp_raw:
        print(f"    Then clean:  rm {raw}")

    return True


def main():
    parser = argparse.ArgumentParser(
        description="Android sparse image tool — inspect, validate, convert"
    )
    parser.add_argument("image", help="Sparse image file path")

    sub = parser.add_subparsers(dest="command", help="Command")

    # info
    info_p = sub.add_parser("info", help="Show sparse image header and chunk summary")

    # chunks
    chunks_p = sub.add_parser("chunks", help="List all chunks in detail")
    chunks_p.add_argument("-n", "--limit", type=int, help="Limit output to N chunks")

    # validate
    val_p = sub.add_parser("validate", help="Validate sparse image integrity")

    # unsparse
    unsparse_p = sub.add_parser("unsparse", help="Convert to raw image")
    unsparse_p.add_argument("-o", "--output", help="Output path (default: <name>.raw)")

    # extract
    extract_p = sub.add_parser("extract", help="Extract a block range to raw file")
    extract_p.add_argument("start", type=int, help="Start block number")
    extract_p.add_argument("count", type=int, help="Number of blocks")
    extract_p.add_argument("-o", "--output", help="Output path")

    # md5
    md5_p = sub.add_parser("md5", help="Compute MD5 of raw output without writing to disk")

    # mount
    mount_p = sub.add_parser("mount", help="Unsparse and mount the image (auto-detects fs)")
    mount_p.add_argument("mountpoint", nargs="?", help="Mount directory (default: /mnt/<name>)")
    mount_p.add_argument("--raw", help="Path for intermediate raw image")
    mount_p.add_argument("--keep-raw", action="store_true", help="Keep raw file after mounting")

    args = parser.parse_args()

    if not args.command:
        # Default to info
        args.command = "info"

    path = args.image
    if not os.path.exists(path):
        print(f"[-] File not found: {path}")
        sys.exit(1)

    # Decompress brotli if needed (.img.br -> .img)
    path = resolve_input(path)

    if not is_sparse(path):
        # mount command can handle raw images directly
        if args.command == "mount":
            mp = args.mountpoint or f"/mnt/{Path(path).stem}"
            mount_image(path, mp, raw_path=args.raw, keep_raw=args.keep_raw)
            sys.exit(0)
        print(f"[-] Not a sparse image: {path}")
        parts = find_split_images(path)
        if len(parts) > 1:
            print(f"[*] Found {len(parts)} split parts — try the first one: {parts[0]}")
        sys.exit(1)

    img = SparseImage(path)

    if args.command == "info":
        img.info()
        # Check for split images
        parts = find_split_images(path)
        if len(parts) > 1:
            print(f"\nSplit image parts ({len(parts)}):")
            for p in parts:
                s = "sparse" if is_sparse(p) else "not sparse"
                sz = os.path.getsize(p)
                print(f"  {p} ({sz / 1024 / 1024:.1f} MB, {s})")

    elif args.command == "chunks":
        img.dump_chunks(limit=args.limit)

    elif args.command == "validate":
        ok = img.validate()
        sys.exit(0 if ok else 1)

    elif args.command == "unsparse":
        output = args.output
        if not output:
            base = Path(path).stem
            output = str(Path(path).parent / f"{base}.raw")
        img.unsparse(output)

    elif args.command == "extract":
        output = args.output or f"blocks_{args.start}_{args.count}.raw"
        img.extract_range(output, args.start, args.count)

    elif args.command == "md5":
        print(f"[*] Computing MD5 of raw output...")
        digest = img.md5()
        print(f"[+] MD5: {digest}")

    elif args.command == "mount":
        mp = args.mountpoint
        if not mp:
            mp = f"/mnt/{Path(path).stem}"
        mount_image(path, mp, raw_path=args.raw, keep_raw=args.keep_raw)


if __name__ == "__main__":
    main()
