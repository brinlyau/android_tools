#!/usr/bin/env python3
"""
UNISOC .pac firmware unpacker with sparse image and super.img support.

Usage:
    python3 unpack_pac.py firmware.pac [output_dir]
    python3 unpack_pac.py --sparse super.img [output.raw]
    python3 unpack_pac.py --super  super.img [output_dir]
    python3 unpack_pac.py --super-raw super.raw [output_dir]

Modes:
    (default)    Unpack a .pac file, auto-converting sparse images and
                 extracting super.img partitions.
    --sparse     Convert a single sparse image to raw.
    --super      Convert sparse super.img to raw, then extract LP partitions.
    --super-raw  Extract LP partitions from an already-raw super image.
    --no-super   Unpack .pac but skip super.img partition extraction.
    --no-sparse  Unpack .pac but skip sparse-to-raw conversion.
"""

import argparse
import io
import os
import struct
import sys
from pathlib import Path

# ── PAC format constants ─────────────────────────────────────────────────────

PAC_MAGIC = 0xFFFAFFFA

# BIN_PACKET_HEADER: 2120 bytes
# All WCHAR fields are UTF-16LE.
_PAC_HEADER_FMT = "<"  + \
    "44s"   + \
    "I"     + \
    "I"     + \
    "512s"  + \
    "512s"  + \
    "i"     + \
    "I"     + \
    "I"     + \
    "I"     + \
    "I"     + \
    "I"     + \
    "I"     + \
    "200s"  + \
    "I"     + \
    "I"     + \
    "I"     + \
    "H"     + \
    "H"     + \
    "I"     + \
    "I"     + \
    "788s"  + \
    "I"     + \
    "H"     + \
    "H"
_PAC_HEADER_SIZE = struct.calcsize(_PAC_HEADER_FMT)  # 2120

# FILE_INFO: 2580 bytes
_FILE_INFO_FMT = "<"  + \
    "I"     + \
    "512s"  + \
    "512s"  + \
    "504s"  + \
    "I"     + \
    "I"     + \
    "I"     + \
    "i"     + \
    "I"     + \
    "I"     + \
    "I"     + \
    "I"     + \
    "5I"    + \
    "996s"
_FILE_INFO_SIZE = struct.calcsize(_FILE_INFO_FMT)  # 2580

# ── Sparse image constants ───────────────────────────────────────────────────

SPARSE_HEADER_MAGIC = 0xED26FF3A
CHUNK_TYPE_RAW      = 0xCAC1
CHUNK_TYPE_FILL     = 0xCAC2
CHUNK_TYPE_DONT_CARE= 0xCAC3
CHUNK_TYPE_CRC32    = 0xCAC4

# sparse_header: 28 bytes
_SPARSE_HEADER_FMT  = "<IHHHHIIII"
_SPARSE_HEADER_SIZE = struct.calcsize(_SPARSE_HEADER_FMT)  # 28

# chunk_header: 12 bytes
_CHUNK_HEADER_FMT  = "<HHII"
_CHUNK_HEADER_SIZE = struct.calcsize(_CHUNK_HEADER_FMT)  # 12

# ── Android LP metadata constants ────────────────────────────────────────────

LP_METADATA_GEOMETRY_MAGIC  = 0x616C4467   # 'gDla'
LP_METADATA_HEADER_MAGIC    = 0x414C5030   # '0PLA'
LP_PARTITION_ATTR_READONLY  = (1 << 0)

# Geometry sits at 4096 from the start of the super partition (primary copy).
LP_METADATA_GEOMETRY_OFFSET = 4096
LP_METADATA_GEOMETRY_SIZE   = 4096  # padded to this

# ── Helpers ──────────────────────────────────────────────────────────────────

def _wchar(raw: bytes) -> str:
    """Decode a fixed-size UTF-16LE WCHAR buffer, stripping NUL padding."""
    try:
        return raw.decode("utf-16-le").split("\x00", 1)[0]
    except UnicodeDecodeError:
        return raw.hex()


def _human(size: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TiB"


def _copy_stream(src, dst, length: int, buf_size: int = 4 * 1024 * 1024):
    """Copy exactly *length* bytes from src to dst."""
    remaining = length
    while remaining > 0:
        chunk = src.read(min(buf_size, remaining))
        if not chunk:
            raise IOError(f"Unexpected EOF – {remaining} bytes remaining")
        dst.write(chunk)
        remaining -= len(chunk)


# ── PAC unpacking ────────────────────────────────────────────────────────────

class PacHeader:
    __slots__ = (
        "version", "total_size", "product_name", "product_version",
        "file_count", "file_offset", "mode", "flash_type",
        "nand_strategy", "is_nv_backup", "nand_page_type",
        "product_alias", "encrypted", "crc_flag", "magic",
    )

    def __init__(self, buf: bytes):
        (
            raw_ver, hi_sz, lo_sz, raw_prd, raw_prd_ver,
            file_count, file_offset, mode, flash_type,
            nand_strategy, is_nv_backup, nand_page_type,
            raw_alias,
            _oma_flag, _oma_dm, _preload,
            encrypted, crc_flag, _ft_org, _ft_enc,
            _reserved, magic, _crc1, _crc2,
        ) = struct.unpack_from(_PAC_HEADER_FMT, buf)

        self.version         = _wchar(raw_ver)
        self.total_size      = (hi_sz << 32) | lo_sz
        self.product_name    = _wchar(raw_prd)
        self.product_version = _wchar(raw_prd_ver)
        self.file_count      = file_count
        self.file_offset     = file_offset
        self.mode            = mode
        self.flash_type      = flash_type
        self.nand_strategy   = nand_strategy
        self.is_nv_backup    = is_nv_backup
        self.nand_page_type  = nand_page_type
        self.product_alias   = _wchar(raw_alias)
        self.encrypted       = encrypted
        self.crc_flag        = crc_flag
        self.magic           = magic


class PacFileEntry:
    __slots__ = (
        "struct_size", "file_id", "file_name", "file_version",
        "file_size", "data_offset", "file_flag", "check_flag",
        "can_omit", "addr_num", "addrs",
    )

    def __init__(self, buf: bytes, offset: int = 0):
        (
            struct_size,
            raw_id, raw_name, raw_ver,
            hi_file_sz, hi_data_off, lo_file_sz,
            file_flag, check_flag, lo_data_off,
            can_omit, addr_num,
            a0, a1, a2, a3, a4,
            _reserved,
        ) = struct.unpack_from(_FILE_INFO_FMT, buf, offset)

        self.struct_size  = struct_size
        self.file_id      = _wchar(raw_id)
        self.file_name    = _wchar(raw_name)
        self.file_version = _wchar(raw_ver)
        self.file_size    = (hi_file_sz << 32) | lo_file_sz
        self.data_offset  = (hi_data_off << 32) | lo_data_off
        self.file_flag    = file_flag
        self.check_flag   = check_flag
        self.can_omit     = can_omit
        self.addr_num     = addr_num
        self.addrs        = [a0, a1, a2, a3, a4][:max(addr_num, 1)]


def parse_pac(pac_path: str):
    """Parse a .pac file and return (PacHeader, [PacFileEntry])."""
    with open(pac_path, "rb") as f:
        hdr_buf = f.read(_PAC_HEADER_SIZE)
        if len(hdr_buf) < _PAC_HEADER_SIZE:
            raise ValueError("File too small to be a valid .pac")

        hdr = PacHeader(hdr_buf)
        if hdr.magic != PAC_MAGIC:
            raise ValueError(
                f"Bad PAC magic: 0x{hdr.magic:08X} (expected 0x{PAC_MAGIC:08X})"
            )

        f.seek(hdr.file_offset)
        entries = []
        for i in range(hdr.file_count):
            entry_buf = f.read(_FILE_INFO_SIZE)
            if len(entry_buf) < _FILE_INFO_SIZE:
                raise ValueError(f"Truncated FILE_INFO at index {i}")
            entries.append(PacFileEntry(entry_buf))

    return hdr, entries


def unpack_pac(pac_path: str, out_dir: str, *, convert_sparse=True, extract_super=True):
    """Unpack all files from a .pac, optionally handling sparse & super."""
    pac_path = os.path.abspath(pac_path)
    out_dir  = os.path.abspath(out_dir)
    os.makedirs(out_dir, exist_ok=True)

    hdr, entries = parse_pac(pac_path)
    print(f"PAC version   : {hdr.version}")
    print(f"Product       : {hdr.product_name}")
    print(f"Product ver   : {hdr.product_version}")
    if hdr.product_alias:
        print(f"Product alias : {hdr.product_alias}")
    mode_names = {0: "Research", 1: "Factory", 2: "Upgrade"}
    print(f"Mode          : {mode_names.get(hdr.mode, hdr.mode)}")
    flash_names = {0: "NOR", 1: "NAND"}
    print(f"Flash type    : {flash_names.get(hdr.flash_type, hdr.flash_type)}")
    print(f"Encrypted     : {'yes' if hdr.encrypted else 'no'}")
    print(f"Total size    : {_human(hdr.total_size)}")
    print(f"Files         : {hdr.file_count}")
    print()

    if hdr.encrypted:
        print("WARNING: PAC is marked as encrypted. Files will be extracted as-is")
        print("         (raw encrypted blobs). Decryption requires the AuthenticationLib")
        print("         key material and is not supported by this tool.")
        print()

    extracted = []
    with open(pac_path, "rb") as pac_f:
        for entry in entries:
            if entry.file_size == 0 and entry.file_flag == 0:
                # Operation-only entry (e.g. ERASE, RESET) – no file data
                print(f"  [skip]  {entry.file_id:<20s}  (operation, no data)")
                continue

            # Determine output filename
            fname = entry.file_name
            if not fname:
                fname = entry.file_id
            # Strip any path components from the name
            fname = os.path.basename(fname)
            if not fname:
                fname = f"file_{entry.file_id or 'unknown'}"

            out_path = os.path.join(out_dir, fname)

            if entry.file_size == 0:
                # Touch an empty file for completeness
                Path(out_path).touch()
                print(f"  [empty] {entry.file_id:<20s}  {fname}")
                extracted.append((entry, out_path))
                continue

            # Extract file data
            pac_f.seek(entry.data_offset)
            addr_str = ""
            if entry.addr_num > 0:
                addr_str = "  addr=" + ",".join(
                    f"0x{a:08X}" for a in entry.addrs
                )
            print(
                f"  [{_human(entry.file_size):>10s}]  "
                f"{entry.file_id:<20s}  -> {fname}{addr_str}"
            )

            with open(out_path, "wb") as out_f:
                _copy_stream(pac_f, out_f, entry.file_size)

            extracted.append((entry, out_path))

    print(f"\nExtracted {len(extracted)} files to {out_dir}/")

    # Post-processing: sparse conversion & super extraction
    super_raw_path = None
    for entry, out_path in extracted:
        if not os.path.isfile(out_path) or os.path.getsize(out_path) == 0:
            continue

        if convert_sparse and is_sparse_image(out_path):
            raw_path = out_path + ".raw"
            print(f"\nConverting sparse image: {os.path.basename(out_path)}")
            sparse_to_raw(out_path, raw_path)
            # Replace the sparse file with the raw one
            os.replace(raw_path, out_path)
            print(f"  -> converted to raw ({_human(os.path.getsize(out_path))})")

            fid = entry.file_id.lower()
            if "super" in fid:
                super_raw_path = out_path

    if extract_super and super_raw_path:
        super_dir = os.path.join(out_dir, "super_unpacked")
        print(f"\nExtracting super.img partitions to {super_dir}/")
        extract_super_partitions(super_raw_path, super_dir)

    return extracted


# ── Sparse image handling ────────────────────────────────────────────────────

def is_sparse_image(path: str) -> bool:
    """Check if a file starts with the Android sparse image magic."""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            return len(magic) == 4 and struct.unpack("<I", magic)[0] == SPARSE_HEADER_MAGIC
    except OSError:
        return False


class SparseHeader:
    __slots__ = (
        "magic", "major_version", "minor_version",
        "file_hdr_sz", "chunk_hdr_sz", "blk_sz",
        "total_blks", "total_chunks", "image_checksum",
    )

    def __init__(self, buf: bytes):
        (
            self.magic, self.major_version, self.minor_version,
            self.file_hdr_sz, self.chunk_hdr_sz, self.blk_sz,
            self.total_blks, self.total_chunks, self.image_checksum,
        ) = struct.unpack_from(_SPARSE_HEADER_FMT, buf)


def sparse_to_raw(sparse_path: str, raw_path: str):
    """Convert an Android sparse image to a raw image."""
    with open(sparse_path, "rb") as sf:
        hdr_buf = sf.read(_SPARSE_HEADER_SIZE)
        shdr = SparseHeader(hdr_buf)

        if shdr.magic != SPARSE_HEADER_MAGIC:
            raise ValueError(f"Not a sparse image (magic 0x{shdr.magic:08X})")
        if shdr.major_version != 1:
            raise ValueError(f"Unsupported sparse major version {shdr.major_version}")

        raw_size = shdr.blk_sz * shdr.total_blks
        print(f"  Sparse: {shdr.total_chunks} chunks, blk_sz={shdr.blk_sz}, "
              f"raw size={_human(raw_size)}")

        # Skip any extra header bytes
        if shdr.file_hdr_sz > _SPARSE_HEADER_SIZE:
            sf.read(shdr.file_hdr_sz - _SPARSE_HEADER_SIZE)

        with open(raw_path, "wb") as rf:
            blocks_written = 0
            for _ in range(shdr.total_chunks):
                chdr_buf = sf.read(shdr.chunk_hdr_sz)
                if len(chdr_buf) < _CHUNK_HEADER_SIZE:
                    raise ValueError("Truncated chunk header")

                ctype, _reserved, chunk_sz, total_sz = struct.unpack_from(
                    _CHUNK_HEADER_FMT, chdr_buf
                )
                data_sz = total_sz - shdr.chunk_hdr_sz

                if ctype == CHUNK_TYPE_RAW:
                    _copy_stream(sf, rf, data_sz)
                    blocks_written += chunk_sz

                elif ctype == CHUNK_TYPE_FILL:
                    fill_val = sf.read(4)
                    if len(fill_val) < 4:
                        raise ValueError("Truncated FILL chunk")
                    fill_block = fill_val * (shdr.blk_sz // 4)
                    for _ in range(chunk_sz):
                        rf.write(fill_block)
                    blocks_written += chunk_sz

                elif ctype == CHUNK_TYPE_DONT_CARE:
                    # Write zeros (seek forward in output)
                    skip_bytes = chunk_sz * shdr.blk_sz
                    rf.seek(skip_bytes, os.SEEK_CUR)
                    blocks_written += chunk_sz

                elif ctype == CHUNK_TYPE_CRC32:
                    if data_sz > 0:
                        sf.read(data_sz)  # discard CRC value
                else:
                    raise ValueError(f"Unknown chunk type 0x{ctype:04X}")

            # Truncate/extend to exact raw size
            rf.truncate(raw_size)


def sparse_to_raw_stream(src_f, size: int) -> io.BytesIO:
    """Convert a sparse image from an open file handle into a BytesIO raw image.

    Used when we want to process sparse data without writing a temp file.
    Falls back to reading as raw if not sparse.
    """
    start = src_f.tell()
    magic_bytes = src_f.read(4)
    src_f.seek(start)

    if len(magic_bytes) < 4 or struct.unpack("<I", magic_bytes)[0] != SPARSE_HEADER_MAGIC:
        # Not sparse – read as-is
        buf = io.BytesIO()
        _copy_stream(src_f, buf, size)
        buf.seek(0)
        return buf

    hdr_buf = src_f.read(_SPARSE_HEADER_SIZE)
    shdr = SparseHeader(hdr_buf)
    raw_size = shdr.blk_sz * shdr.total_blks

    if shdr.file_hdr_sz > _SPARSE_HEADER_SIZE:
        src_f.read(shdr.file_hdr_sz - _SPARSE_HEADER_SIZE)

    out = io.BytesIO(b'\x00' * raw_size)
    out.seek(0)

    for _ in range(shdr.total_chunks):
        chdr_buf = src_f.read(shdr.chunk_hdr_sz)
        ctype, _, chunk_sz, total_sz = struct.unpack_from(_CHUNK_HEADER_FMT, chdr_buf)
        data_sz = total_sz - shdr.chunk_hdr_sz

        if ctype == CHUNK_TYPE_RAW:
            _copy_stream(src_f, out, data_sz)
        elif ctype == CHUNK_TYPE_FILL:
            fill_val = src_f.read(4)
            fill_block = fill_val * (shdr.blk_sz // 4)
            for _ in range(chunk_sz):
                out.write(fill_block)
        elif ctype == CHUNK_TYPE_DONT_CARE:
            out.seek(chunk_sz * shdr.blk_sz, os.SEEK_CUR)
        elif ctype == CHUNK_TYPE_CRC32:
            if data_sz > 0:
                src_f.read(data_sz)
        else:
            raise ValueError(f"Unknown chunk type 0x{ctype:04X}")

    out.seek(0)
    return out


# ── Super.img / LP metadata extraction ───────────────────────────────────────
#
# Android dynamic partitions use "LP metadata" (liblp).
# Layout of the raw super partition:
#   0x0000 – 0x0FFF : primary geometry (padded to 4096)
#   0x1000 – 0x1FFF : backup geometry  (padded to 4096)
#   then metadata slots at offsets specified in geometry
#
# Geometry structure (relevant fields):
#   magic(4) checksum(32) max_metadata_size(4) slot_count(4) logical_block_size(4)
#
# Metadata header:
#   magic(4) major(2) minor(2) header_size(4) header_checksum(32)
#   tables_size(4) tables_checksum(32)
#   partitions(offset4,count4,entry_size4)
#   extents(offset4,count4,entry_size4)
#   groups(offset4,count4,entry_size4)
#   block_devices(offset4,count4,entry_size4)
#
# Partition entry (at least 52 bytes):
#   name(36) attributes(4) first_extent_index(4) num_extents(4) group_index(4)
#
# Extent entry (at least 24 bytes):
#   num_sectors(8) target_type(4) target_data(8) target_source(4)

LP_TARGET_TYPE_LINEAR = 0
LP_TARGET_TYPE_ZERO   = 1
LP_SECTOR_SIZE        = 512


class LpGeometry:
    def __init__(self, buf: bytes, offset: int = 0):
        self.magic = struct.unpack_from("<I", buf, offset)[0]
        if self.magic != LP_METADATA_GEOMETRY_MAGIC:
            raise ValueError(
                f"Bad LP geometry magic: 0x{self.magic:08X} "
                f"(expected 0x{LP_METADATA_GEOMETRY_MAGIC:08X})"
            )
        # Skip: magic(4) + sha256(32) = 36
        (
            self.metadata_max_size,
            self.metadata_slot_count,
            self.logical_block_size,
        ) = struct.unpack_from("<III", buf, offset + 36)


class LpMetadataHeader:
    """Parse the LP metadata header to locate the tables."""
    def __init__(self, buf: bytes, offset: int = 0):
        self.magic = struct.unpack_from("<I", buf, offset)[0]
        if self.magic != LP_METADATA_HEADER_MAGIC:
            raise ValueError(
                f"Bad LP metadata magic: 0x{self.magic:08X} "
                f"(expected 0x{LP_METADATA_HEADER_MAGIC:08X})"
            )
        # magic(4) major(2) minor(2) header_size(4) header_checksum(32)
        # = 44 bytes to tables_size
        base = offset + 4
        self.major, self.minor = struct.unpack_from("<HH", buf, base)
        base += 4
        self.header_size = struct.unpack_from("<I", buf, base)[0]
        base += 4
        # header_checksum: 32 bytes
        base += 32
        self.tables_size = struct.unpack_from("<I", buf, base)[0]
        base += 4
        # tables_checksum: 32 bytes
        base += 32

        # Table descriptors: (offset, count, entry_size) × 4
        def _read_desc():
            nonlocal base
            o, n, s = struct.unpack_from("<III", buf, base)
            base += 12
            return o, n, s

        self.partitions_offset, self.partitions_count, self.partitions_entry_size = _read_desc()
        self.extents_offset, self.extents_count, self.extents_entry_size = _read_desc()
        self.groups_offset, self.groups_count, self.groups_entry_size = _read_desc()
        self.block_devices_offset, self.block_devices_count, self.block_devices_entry_size = _read_desc()


class LpPartition:
    def __init__(self, buf: bytes, offset: int = 0):
        # name: 36 bytes (null-terminated ASCII)
        raw_name = buf[offset:offset + 36]
        self.name = raw_name.split(b"\x00", 1)[0].decode("ascii", errors="replace")
        base = offset + 36
        (
            self.attributes,
            self.first_extent_index,
            self.num_extents,
            self.group_index,
        ) = struct.unpack_from("<IIII", buf, base)


class LpExtent:
    def __init__(self, buf: bytes, offset: int = 0):
        (
            self.num_sectors,
            self.target_type,
            self.target_data,
            self.target_source,
        ) = struct.unpack_from("<QIQII", buf, offset)[:4]
        # Re-parse more carefully: num_sectors(8), target_type(4), target_data(8), target_source(4)
        self.num_sectors = struct.unpack_from("<Q", buf, offset)[0]
        self.target_type = struct.unpack_from("<I", buf, offset + 8)[0]
        self.target_data = struct.unpack_from("<Q", buf, offset + 12)[0]
        self.target_source = struct.unpack_from("<I", buf, offset + 20)[0]


def extract_super_partitions(super_raw_path: str, out_dir: str):
    """Extract individual partitions from a raw super.img using LP metadata."""
    os.makedirs(out_dir, exist_ok=True)

    with open(super_raw_path, "rb") as f:
        # Read primary geometry at offset 4096
        f.seek(LP_METADATA_GEOMETRY_OFFSET)
        geo_buf = f.read(LP_METADATA_GEOMETRY_SIZE)

        try:
            geo = LpGeometry(geo_buf)
        except ValueError:
            # Some images put geometry at offset 0
            f.seek(0)
            geo_buf = f.read(LP_METADATA_GEOMETRY_SIZE)
            try:
                geo = LpGeometry(geo_buf)
            except ValueError:
                print("  ERROR: Could not find LP metadata geometry in super image.")
                print("         This may not be an Android dynamic partition image.")
                return

        print(f"  LP geometry: slot_count={geo.metadata_slot_count}, "
              f"max_metadata_size={geo.metadata_max_size}, "
              f"logical_block_size={geo.logical_block_size}")

        # Metadata starts right after primary + backup geometry
        # Primary geometry at 4096, backup at 4096+4096=8192
        # First metadata slot at 8192+4096 = 12288  (3 × 4096)
        metadata_offset = LP_METADATA_GEOMETRY_OFFSET + 2 * LP_METADATA_GEOMETRY_SIZE
        f.seek(metadata_offset)
        meta_buf = f.read(geo.metadata_max_size)

        try:
            mhdr = LpMetadataHeader(meta_buf)
        except ValueError as e:
            print(f"  ERROR: {e}")
            return

        print(f"  LP metadata v{mhdr.major}.{mhdr.minor}: "
              f"{mhdr.partitions_count} partitions, "
              f"{mhdr.extents_count} extents")

        # The tables start after the header
        tables_base = mhdr.header_size

        # Parse partitions
        partitions = []
        for i in range(mhdr.partitions_count):
            off = tables_base + mhdr.partitions_offset + i * mhdr.partitions_entry_size
            partitions.append(LpPartition(meta_buf, off))

        # Parse extents
        extents = []
        for i in range(mhdr.extents_count):
            off = tables_base + mhdr.extents_offset + i * mhdr.extents_entry_size
            extents.append(LpExtent(meta_buf, off))

        # Extract each partition
        for part in partitions:
            if part.num_extents == 0:
                print(f"    {part.name:<24s}  (no extents, empty)")
                continue

            total_size = 0
            for ei in range(part.first_extent_index, part.first_extent_index + part.num_extents):
                ext = extents[ei]
                total_size += ext.num_sectors * LP_SECTOR_SIZE

            if total_size == 0:
                print(f"    {part.name:<24s}  (zero size)")
                continue

            out_path = os.path.join(out_dir, f"{part.name}.img")
            print(f"    {part.name:<24s}  {_human(total_size):>10s}  -> {part.name}.img")

            with open(out_path, "wb") as of:
                for ei in range(part.first_extent_index, part.first_extent_index + part.num_extents):
                    ext = extents[ei]
                    extent_bytes = ext.num_sectors * LP_SECTOR_SIZE

                    if ext.target_type == LP_TARGET_TYPE_LINEAR:
                        # target_data is the sector offset within the super image
                        src_offset = ext.target_data * LP_SECTOR_SIZE
                        f.seek(src_offset)
                        _copy_stream(f, of, extent_bytes)
                    elif ext.target_type == LP_TARGET_TYPE_ZERO:
                        of.write(b'\x00' * extent_bytes)
                    else:
                        print(f"      WARNING: unknown extent type {ext.target_type}, "
                              f"writing zeros")
                        of.write(b'\x00' * extent_bytes)

    print(f"\n  Extracted {sum(1 for p in partitions if p.num_extents > 0)} "
          f"partitions to {out_dir}/")


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="UNISOC .pac firmware unpacker with sparse & super.img support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("input", help="Input .pac / sparse / super image file")
    parser.add_argument("output", nargs="?", help="Output directory or file (default: auto)")

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--sparse", action="store_true",
                      help="Convert a sparse image to raw")
    mode.add_argument("--super", action="store_true",
                      help="Convert sparse super.img to raw and extract partitions")
    mode.add_argument("--super-raw", action="store_true",
                      help="Extract partitions from an already-raw super image")

    parser.add_argument("--no-sparse", action="store_true",
                        help="Skip sparse-to-raw conversion during .pac unpack")
    parser.add_argument("--no-super", action="store_true",
                        help="Skip super.img partition extraction during .pac unpack")

    args = parser.parse_args()

    input_path = args.input
    if not os.path.isfile(input_path):
        print(f"Error: {input_path} not found", file=sys.stderr)
        sys.exit(1)

    if args.sparse:
        # Sparse-to-raw mode
        out = args.output or (input_path + ".raw")
        print(f"Converting sparse image: {input_path}")
        sparse_to_raw(input_path, out)
        print(f"Raw image written to: {out} ({_human(os.path.getsize(out))})")

    elif args.super:
        # Super mode: sparse→raw then extract partitions
        out_dir = args.output or (os.path.splitext(input_path)[0] + "_partitions")
        os.makedirs(out_dir, exist_ok=True)

        if is_sparse_image(input_path):
            raw_path = os.path.join(out_dir, "super.raw")
            print(f"Converting sparse super.img to raw...")
            sparse_to_raw(input_path, raw_path)
            print(f"Raw super image: {_human(os.path.getsize(raw_path))}")
        else:
            raw_path = input_path
            print("Input is already a raw image.")

        print(f"\nExtracting LP partitions...")
        extract_super_partitions(raw_path, out_dir)

        # Clean up intermediate raw if we created it
        if raw_path != input_path and os.path.isfile(raw_path):
            sz = os.path.getsize(raw_path)
            os.remove(raw_path)
            print(f"\nCleaned up intermediate super.raw ({_human(sz)})")

    elif args.super_raw:
        # Extract from already-raw super
        out_dir = args.output or (os.path.splitext(input_path)[0] + "_partitions")
        print(f"Extracting LP partitions from raw super image...")
        extract_super_partitions(input_path, out_dir)

    else:
        # Default: unpack .pac
        out_dir = args.output or (os.path.splitext(input_path)[0] + "_unpacked")
        print(f"Unpacking: {input_path}")
        print(f"Output   : {out_dir}/\n")
        unpack_pac(
            input_path, out_dir,
            convert_sparse=not args.no_sparse,
            extract_super=not args.no_super,
        )

    print("\nDone.")


if __name__ == "__main__":
    main()
