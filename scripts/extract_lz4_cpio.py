#!/usr/bin/env python3
"""Decompress Android LZ4-legacy (0x184c2102) vendor_ramdisk streams and extract CPIO entries."""
import os
import re
import struct
import sys


def decompress_lz4_block(src: bytes) -> bytes:
    out = bytearray()
    i = 0
    n = len(src)
    while i < n:
        token = src[i]
        i += 1
        lit_len = token >> 4
        if lit_len == 15:
            while i < n:
                b = src[i]
                i += 1
                lit_len += b
                if b != 255:
                    break
        out.extend(src[i : i + lit_len])
        i += lit_len
        if i >= n:
            break
        offset = src[i] | (src[i + 1] << 8)
        i += 2
        if offset == 0:
            raise ValueError("Invalid LZ4 offset 0")
        match_len = (token & 0x0F) + 4
        if (token & 0x0F) == 15:
            while i < n:
                b = src[i]
                i += 1
                match_len += b
                if b != 255:
                    break
        start = len(out) - offset
        for j in range(match_len):
            out.append(out[start + j])
    return bytes(out)


def decompress_lz4_legacy(data: bytes) -> bytes:
    """Decompress one or more concatenated LZ4 legacy frames (magic 02 21 4c 18)."""
    out = bytearray()
    pos = 0
    n = len(data)
    while pos + 4 <= n:
        if data[pos : pos + 4] != b"\x02\x21\x4c\x18":
            # Skip padding zeros between vendor_boot v4 ramdisk fragments
            if data[pos] == 0:
                pos += 1
                continue
            break
        pos += 4
        while pos + 4 <= n:
            # Check if next 4 bytes start a new LZ4 legacy frame
            if data[pos : pos + 4] == b"\x02\x21\x4c\x18":
                break
            (block_size,) = struct.unpack_from("<I", data, pos)
            if block_size == 0 or pos + 4 + block_size > n:
                break
            pos += 4
            out.extend(decompress_lz4_block(data[pos : pos + block_size]))
            pos += block_size
    return bytes(out)


def iter_cpio(cpio_data: bytes):
    """Yield (path, mode, content_bytes) from newc CPIO archive (handles concatenated archives)."""
    pos = 0
    n = len(cpio_data)
    while pos + 110 <= n:
        if cpio_data[pos : pos + 6] != b"070701":
            idx = cpio_data.find(b"070701", pos)
            if idx == -1:
                break
            pos = idx
        if pos + 110 > n:
            break
        hdr = cpio_data[pos : pos + 110].decode("ascii")
        mode = int(hdr[14:22], 16)
        filesize = int(hdr[54:62], 16)
        namesize = int(hdr[94:102], 16)
        pos += 110
        name = cpio_data[pos : pos + namesize - 1].decode("utf-8", errors="replace")
        pos = ((pos + namesize + 3) // 4) * 4
        content = cpio_data[pos : pos + filesize]
        pos = ((pos + filesize + 3) // 4) * 4
        if name == "TRAILER!!!":
            continue
        yield name, mode, content


if __name__ == "__main__":
    ramdisk_path = sys.argv[1]
    extract_dir = sys.argv[2] if len(sys.argv) > 2 else None
    with open(ramdisk_path, "rb") as f:
        raw = f.read()
    cpio_bytes = decompress_lz4_legacy(raw)
    print(f"Decompressed CPIO size: {len(cpio_bytes)} bytes")

    ko_vermagics: dict[str, list[str]] = {}
    pat = re.compile(rb"vermagic=([^\x00]+)")
    total_files = 0
    for name, mode, content in iter_cpio(cpio_bytes):
        total_files += 1
        if extract_dir and (mode & 0o170000) == 0o100000:
            dest = os.path.join(extract_dir, name.lstrip("/"))
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "wb") as out_f:
                out_f.write(content)
        if name.endswith(".ko"):
            m = pat.search(content)
            vm = m.group(1).decode("utf-8", errors="replace").strip() if m else "<none>"
            ko_vermagics.setdefault(vm, []).append(os.path.basename(name))

    print(f"Total CPIO entries: {total_files}")
    for vm, mods in ko_vermagics.items():
        print(f"VERMAGIC [{vm}]: {len(mods)} modules (sample: {sorted(mods)[:6]})")
