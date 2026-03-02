#!/usr/bin/env python3
"""
Android OTA payload.bin extractor.

Extracts partition images from Android OTA payload.bin files.
Supports full and incremental OTAs (full extraction only —
incremental ops require the source partition).

Format: Chrome OS Auto Update (CrAU) payload version 2.
No external dependencies — includes a minimal protobuf wire parser.

Usage:
    payload_dumper.py payload.bin                    # extract all partitions
    payload_dumper.py payload.bin -p boot vendor     # extract specific partitions
    payload_dumper.py payload.bin -l                 # list partitions only
    payload_dumper.py payload.bin -i                 # show full payload info
"""

import argparse
import bz2
import hashlib
import io
import lzma
import os
import struct
import sys
import zlib
from pathlib import Path


# ── Minimal protobuf wire-format parser ─────────────────────────────────────
# Only handles what payload.bin needs: varint, length-delimited, fixed32/64.
# No .proto compilation needed.

WIRE_VARINT = 0
WIRE_64BIT = 1
WIRE_LEN = 2
WIRE_32BIT = 5


def decode_varint(data, pos):
    result = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return result, pos
        shift += 7
    raise ValueError("Truncated varint")


def decode_signed_varint(data, pos):
    val, pos = decode_varint(data, pos)
    # zigzag decode
    return (val >> 1) ^ -(val & 1), pos


def parse_proto(data):
    """Parse raw protobuf bytes into {field_number: [values]} dict.

    Each value is (wire_type, raw_value) where raw_value is:
      - int for VARINT, FIXED32, FIXED64
      - bytes for length-delimited
    """
    fields = {}
    pos = 0
    while pos < len(data):
        tag, pos = decode_varint(data, pos)
        field_num = tag >> 3
        wire_type = tag & 0x7

        if wire_type == WIRE_VARINT:
            val, pos = decode_varint(data, pos)
        elif wire_type == WIRE_64BIT:
            val = struct.unpack("<Q", data[pos:pos+8])[0]
            pos += 8
        elif wire_type == WIRE_LEN:
            length, pos = decode_varint(data, pos)
            val = data[pos:pos+length]
            pos += length
        elif wire_type == WIRE_32BIT:
            val = struct.unpack("<I", data[pos:pos+4])[0]
            pos += 4
        else:
            raise ValueError(f"Unknown wire type {wire_type} at offset {pos}")

        fields.setdefault(field_num, []).append((wire_type, val))

    return fields


def proto_get(fields, num, default=None):
    """Get first value for a field number."""
    vals = fields.get(num)
    if not vals:
        return default
    _, val = vals[0]
    return val


def proto_get_all(fields, num):
    """Get all values for a repeated field number."""
    return [val for _, val in fields.get(num, [])]


# ── Payload.bin format structures ────────────────────────────────────────────
#
# DeltaArchiveManifest (protobuf):
#   1: repeated InstallOperation install_operations  (unused in v2)
#   2: repeated InstallOperation kernel_install_ops   (unused in v2)
#   3: uint32 block_size
#   4: signatures_offset (uint64)
#   5: signatures_size (uint64)
#   7: old_image_info
#   8: new_image_info
#  13: repeated PartitionUpdate partitions
#  14: max_timestamp
#  15: dynamic_partition_metadata
#
# PartitionUpdate:
#   1: string partition_name
#   2: repeated InstallOperation operations
#   5: new_partition_info  (PartitionInfo)
#   8: new_partition_signature
#
# InstallOperation:
#   1: type (enum)
#   2: data_offset (uint64, but encoded as varint in practice)
#   3: data_length (uint64)
#   4: repeated Extent src_extents
#   5: src_length (uint64)
#   6: repeated Extent dst_extents
#   7: dst_length (uint64)
#   8: data_sha256_hash (bytes)
#  10: src_sha256_hash (bytes)
#
# Extent:
#   1: start_block (uint64)
#   2: num_blocks (uint64)
#
# PartitionInfo:
#   1: size (uint64)
#   2: hash (bytes)
#
# InstallOperation.Type enum:
#   0: REPLACE
#   1: REPLACE_BZ
#   2: MOVE (deprecated)
#   3: BSDIFF (deprecated)
#   4: SOURCE_COPY
#   5: SOURCE_BSDIFF
#   6: ZERO
#   7: DISCARD
#   8: REPLACE_XZ
#   9: PUFFDIFF
#  10: BROTLI_BSDIFF
#  11: ZSTD

OP_REPLACE = 0
OP_REPLACE_BZ = 1
OP_MOVE = 2
OP_BSDIFF = 3
OP_SOURCE_COPY = 4
OP_SOURCE_BSDIFF = 5
OP_ZERO = 6
OP_DISCARD = 7
OP_REPLACE_XZ = 8
OP_PUFFDIFF = 9
OP_BROTLI_BSDIFF = 10
OP_ZSTD = 11

OP_NAMES = {
    0: "REPLACE", 1: "REPLACE_BZ", 2: "MOVE", 3: "BSDIFF",
    4: "SOURCE_COPY", 5: "SOURCE_BSDIFF", 6: "ZERO", 7: "DISCARD",
    8: "REPLACE_XZ", 9: "PUFFDIFF", 10: "BROTLI_BSDIFF", 11: "ZSTD",
}

# Full OTA ops — these don't need source partition
FULL_OPS = {OP_REPLACE, OP_REPLACE_BZ, OP_REPLACE_XZ, OP_ZERO, OP_DISCARD, OP_ZSTD}

try:
    import brotli as _brotli
    HAS_BROTLI = True
except ImportError:
    try:
        import brotlicffi as _brotli
        HAS_BROTLI = True
    except ImportError:
        HAS_BROTLI = False

try:
    import zstandard as _zstd
    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False


def parse_extent(data):
    fields = parse_proto(data)
    return {
        "start_block": proto_get(fields, 1, 0),
        "num_blocks": proto_get(fields, 2, 0),
    }


def parse_partition_info(data):
    fields = parse_proto(data)
    return {
        "size": proto_get(fields, 1, 0),
        "hash": proto_get(fields, 2, b""),
    }


def parse_install_op(data):
    fields = parse_proto(data)
    return {
        "type": proto_get(fields, 1, 0),
        "data_offset": proto_get(fields, 2, 0),
        "data_length": proto_get(fields, 3, 0),
        "src_extents": [parse_extent(e) for e in proto_get_all(fields, 4) if isinstance(e, bytes)],
        "src_length": proto_get(fields, 5, 0),
        "dst_extents": [parse_extent(e) for e in proto_get_all(fields, 6) if isinstance(e, bytes)],
        "dst_length": proto_get(fields, 7, 0),
        "data_sha256": proto_get(fields, 8, b""),
        "src_sha256": proto_get(fields, 10, b""),
    }


def parse_partition_update(data):
    fields = parse_proto(data)
    name_bytes = proto_get(fields, 1, b"")
    name = name_bytes.decode("utf-8") if isinstance(name_bytes, bytes) else str(name_bytes)

    # Operations can be in field 2 (older payloads) or field 8 (newer payloads)
    ops_raw = proto_get_all(fields, 8) or proto_get_all(fields, 2)
    operations = [parse_install_op(op) for op in ops_raw if isinstance(op, bytes)]

    # Partition info can be in field 7 (newer) or field 5 (older)
    part_info_raw = proto_get(fields, 7) or proto_get(fields, 5)
    part_info = parse_partition_info(part_info_raw) if isinstance(part_info_raw, bytes) else None

    return {
        "name": name,
        "operations": operations,
        "new_partition_info": part_info,
    }


class Payload:
    MAGIC = b"CrAU"
    HEADER_SIZE = 24  # magic(4) + version(8) + manifest_size(8) + metadata_sig_size(4)

    def __init__(self, path):
        self.path = path
        self.f = open(path, "rb")
        self._parse_header()
        self._parse_manifest()

    def _parse_header(self):
        magic = self.f.read(4)
        if magic != self.MAGIC:
            raise ValueError(f"Not a payload.bin (magic: {magic!r}, expected: {self.MAGIC!r})")

        self.version = struct.unpack(">Q", self.f.read(8))[0]
        self.manifest_size = struct.unpack(">Q", self.f.read(8))[0]

        if self.version >= 2:
            self.metadata_sig_size = struct.unpack(">I", self.f.read(4))[0]
        else:
            self.metadata_sig_size = 0

        self.manifest_offset = self.f.tell()
        self.data_offset = self.manifest_offset + self.manifest_size + self.metadata_sig_size

    def _parse_manifest(self):
        self.f.seek(self.manifest_offset)
        manifest_raw = self.f.read(self.manifest_size)
        fields = parse_proto(manifest_raw)

        self.block_size = proto_get(fields, 3, 4096)
        self.signatures_offset = proto_get(fields, 4, 0)
        self.signatures_size = proto_get(fields, 5, 0)
        self.max_timestamp = proto_get(fields, 14, 0)

        # Parse partition updates
        self.partitions = []
        for pu_raw in proto_get_all(fields, 13):
            if isinstance(pu_raw, bytes):
                self.partitions.append(parse_partition_update(pu_raw))

    def info(self):
        file_size = os.path.getsize(self.path)
        print(f"File:             {self.path}")
        print(f"File size:        {file_size:,} bytes ({file_size / 1024 / 1024:.1f} MB)")
        print(f"Payload version:  {self.version}")
        print(f"Manifest size:    {self.manifest_size:,} bytes")
        print(f"Metadata sig:     {self.metadata_sig_size:,} bytes")
        print(f"Block size:       {self.block_size}")
        print(f"Data offset:      0x{self.data_offset:X}")
        if self.max_timestamp:
            print(f"Max timestamp:    {self.max_timestamp}")
        print(f"Partitions:       {len(self.partitions)}")

        total_raw = 0
        total_data = 0
        for p in self.partitions:
            if p["new_partition_info"]:
                total_raw += p["new_partition_info"]["size"]
            for op in p["operations"]:
                total_data += op["data_length"]

        print(f"Total raw size:   {total_raw:,} bytes ({total_raw / 1024 / 1024 / 1024:.2f} GB)")
        print(f"Total data size:  {total_data:,} bytes ({total_data / 1024 / 1024 / 1024:.2f} GB)")

    def list_partitions(self):
        print(f"\n{'#':<4} {'Partition':<24} {'Size':<14} {'Ops':<6} {'Type':<14} {'Hash'}")
        print("-" * 90)
        for i, p in enumerate(self.partitions):
            info = p["new_partition_info"]
            size = info["size"] if info else 0
            hash_hex = info["hash"].hex()[:16] + "..." if info and info["hash"] else "N/A"

            op_types = set(op["type"] for op in p["operations"])
            is_full = op_types.issubset(FULL_OPS)
            type_str = "full" if is_full else "incremental"

            if size >= 1024 * 1024 * 1024:
                size_str = f"{size / 1024 / 1024 / 1024:.2f} GB"
            elif size >= 1024 * 1024:
                size_str = f"{size / 1024 / 1024:.1f} MB"
            elif size >= 1024:
                size_str = f"{size / 1024:.1f} KB"
            else:
                size_str = f"{size} B"

            print(f"[{i:<2}] {p['name']:<24} {size_str:<14} {len(p['operations']):<6} {type_str:<14} {hash_hex}")

    def _decompress(self, op_type, data):
        if op_type == OP_REPLACE:
            return data
        elif op_type == OP_REPLACE_BZ:
            return bz2.decompress(data)
        elif op_type == OP_REPLACE_XZ:
            return lzma.decompress(data)
        elif op_type == OP_ZSTD:
            if not HAS_ZSTD:
                print("[-] ZSTD operation requires zstandard: pip install zstandard")
                sys.exit(1)
            dctx = _zstd.ZstdDecompressor()
            return dctx.decompress(data)
        else:
            return data

    def extract_partition(self, part, output_dir, verify=True):
        """Extract a single partition to a raw image file."""
        name = part["name"]
        info = part["new_partition_info"]
        target_size = info["size"] if info else 0

        out_path = os.path.join(output_dir, f"{name}.img")
        os.makedirs(output_dir, exist_ok=True)

        # Check if already extracted and verified
        if os.path.exists(out_path) and info and info.get("hash"):
            existing_size = os.path.getsize(out_path)
            if existing_size == target_size:
                h = hashlib.sha256()
                with open(out_path, "rb") as ef:
                    for chunk in iter(lambda: ef.read(1024 * 1024), b""):
                        h.update(chunk)
                if h.digest() == info["hash"]:
                    print(f"  [+] {name}: already extracted and verified")
                    return out_path

        ops = part["operations"]
        op_types = set(op["type"] for op in ops)

        # Check for incremental ops
        incremental_ops = op_types - FULL_OPS
        if incremental_ops:
            inc_names = ", ".join(OP_NAMES.get(t, str(t)) for t in incremental_ops)
            print(f"  [!] {name}: incremental OTA ({inc_names}) — skipping")
            print(f"       Incremental ops require the source partition to apply diffs")
            return None

        # Check for brotli ops
        if OP_BROTLI_BSDIFF in op_types and not HAS_BROTLI:
            print(f"  [-] {name}: requires brotli (pip install brotli)")
            return None

        total_ops = len(ops)
        data_written = 0

        with open(out_path, "wb") as out:
            for idx, op in enumerate(ops):
                op_type = op["type"]
                data_length = op["data_length"]

                if op_type in (OP_ZERO, OP_DISCARD):
                    # Write zeros for each dst extent
                    for ext in op["dst_extents"]:
                        zero_size = ext["num_blocks"] * self.block_size
                        out.seek(ext["start_block"] * self.block_size)
                        remaining = zero_size
                        zero_chunk = b'\x00' * min(1024 * 1024, remaining)
                        while remaining > 0:
                            w = min(remaining, len(zero_chunk))
                            out.write(zero_chunk[:w])
                            remaining -= w
                        data_written += zero_size

                elif op_type in (OP_REPLACE, OP_REPLACE_BZ, OP_REPLACE_XZ, OP_ZSTD):
                    # Read compressed/raw data from payload
                    self.f.seek(self.data_offset + op["data_offset"])
                    raw_data = self.f.read(data_length)

                    if len(raw_data) != data_length:
                        print(f"\n  [-] {name}: short read at op {idx} "
                              f"(got {len(raw_data)}, expected {data_length})")
                        return None

                    # Verify data hash if available
                    if verify and op["data_sha256"]:
                        h = hashlib.sha256(raw_data).digest()
                        if h != op["data_sha256"]:
                            print(f"\n  [-] {name}: data hash mismatch at op {idx}")
                            return None

                    # Decompress
                    decompressed = self._decompress(op_type, raw_data)

                    # Write to dst extents
                    offset = 0
                    for ext in op["dst_extents"]:
                        write_pos = ext["start_block"] * self.block_size
                        write_size = ext["num_blocks"] * self.block_size
                        out.seek(write_pos)
                        out.write(decompressed[offset:offset + write_size])
                        offset += write_size

                    data_written += len(decompressed)

                else:
                    print(f"\n  [-] {name}: unsupported op {OP_NAMES.get(op_type, op_type)} at op {idx}")
                    return None

                # Progress
                pct = (idx + 1) / total_ops * 100
                print(f"\r  [{pct:5.1f}%] {name}: op {idx+1}/{total_ops}", end="", flush=True)

            # Truncate to exact size
            if target_size > 0:
                out.truncate(target_size)

        print()

        # Verify final hash
        if verify and info and info.get("hash"):
            print(f"  [*] Verifying {name}...", end="", flush=True)
            h = hashlib.sha256()
            with open(out_path, "rb") as vf:
                for chunk in iter(lambda: vf.read(1024 * 1024), b""):
                    h.update(chunk)
            if h.digest() == info["hash"]:
                print(f" OK")
            else:
                print(f" MISMATCH")
                print(f"      Expected: {info['hash'].hex()}")
                print(f"      Got:      {h.hexdigest()}")

        size = os.path.getsize(out_path)
        print(f"  [+] {name}: {out_path} ({size / 1024 / 1024:.1f} MB)")
        return out_path

    def extract(self, output_dir, partition_names=None, verify=True, workers=1):
        """Extract partitions from the payload.

        Args:
            output_dir: Directory to write partition images
            partition_names: List of partition names to extract (None = all)
            verify: Verify SHA256 hashes
            workers: Unused (reserved for future parallel extraction)
        """
        to_extract = self.partitions
        if partition_names:
            names = set(partition_names)
            to_extract = [p for p in self.partitions if p["name"] in names]
            missing = names - set(p["name"] for p in to_extract)
            if missing:
                print(f"[-] Partitions not found: {', '.join(missing)}")
                available = [p["name"] for p in self.partitions]
                print(f"    Available: {', '.join(available)}")
                if not to_extract:
                    return

        print(f"\n[*] Extracting {len(to_extract)} partition(s) to {output_dir}/\n")

        extracted = 0
        skipped = 0
        for part in to_extract:
            result = self.extract_partition(part, output_dir, verify=verify)
            if result:
                extracted += 1
            else:
                skipped += 1

        print(f"\n[+] Done: {extracted} extracted, {skipped} skipped")

    def close(self):
        self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


def main():
    parser = argparse.ArgumentParser(
        description="Extract partition images from Android OTA payload.bin"
    )
    parser.add_argument("payload", help="Path to payload.bin")
    parser.add_argument(
        "-p", "--partitions", nargs="+",
        help="Specific partitions to extract (e.g. boot vendor system)"
    )
    parser.add_argument(
        "-o", "--output", default="payload_out",
        help="Output directory (default: payload_out)"
    )
    parser.add_argument(
        "-l", "--list", action="store_true",
        help="List partitions only, don't extract"
    )
    parser.add_argument(
        "-i", "--info", action="store_true",
        help="Show payload info and partition list"
    )
    parser.add_argument(
        "--no-verify", action="store_true",
        help="Skip SHA256 verification (faster)"
    )

    args = parser.parse_args()

    if not os.path.exists(args.payload):
        print(f"[-] File not found: {args.payload}")
        sys.exit(1)

    # Handle .zip — look for payload.bin inside
    if args.payload.endswith(".zip"):
        import zipfile
        if not zipfile.is_zipfile(args.payload):
            print(f"[-] Not a valid zip file: {args.payload}")
            sys.exit(1)
        with zipfile.ZipFile(args.payload) as z:
            if "payload.bin" not in z.namelist():
                print(f"[-] No payload.bin in zip. Contents:")
                for name in z.namelist()[:20]:
                    print(f"    {name}")
                sys.exit(1)
            # Extract payload.bin to temp location
            extract_dir = os.path.dirname(args.payload) or "."
            payload_path = os.path.join(extract_dir, "payload.bin")
            if not os.path.exists(payload_path):
                print(f"[*] Extracting payload.bin from zip...")
                z.extract("payload.bin", extract_dir)
                print(f"[+] Extracted to {payload_path}")
            args.payload = payload_path

    with Payload(args.payload) as payload:
        if args.info:
            payload.info()
            payload.list_partitions()
            sys.exit(0)

        if args.list:
            payload.list_partitions()
            sys.exit(0)

        payload.extract(
            args.output,
            partition_names=args.partitions,
            verify=not args.no_verify,
        )


if __name__ == "__main__":
    main()
