#!/usr/bin/env python3
"""Repack Android vendor_boot v4 image with 2 fragments:
  - Fragment 0 (PLATFORM, name=''): 100% bit-for-bit stock OS3.0.303.0.WOOIDXM
  - Fragment 1 (RECOVERY, name='recovery'): deduplicated OrangeFox recovery ramdisk + masks for conflicting stock .rc
"""
import hashlib
import os
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from extract_lz4_cpio import decompress_lz4_legacy, iter_cpio

MASKED_RC_FILES = {
    "system/etc/init/servicemanager.recovery.rc": b"# masked by OrangeFox recovery fragment\n",
    "system/etc/init/logd.rc": b"# masked by OrangeFox recovery fragment\n",
    "system/etc/init/android.hardware.boot-service.mtk_recovery.rc": b"# masked by OrangeFox recovery fragment\n",
    "system/etc/init/android.hardware.health-service.example_recovery.rc": b"# masked by OrangeFox recovery fragment\n",
    "system/etc/init/recovery-persist.rc": b"# masked by OrangeFox recovery fragment\n",
    "system/etc/init/recovery-refresh.rc": b"# masked by OrangeFox recovery fragment\n",
    "miui.factoryreset.rc": b"# masked by OrangeFox recovery fragment\n",
}

MASKED_VINTF_FILES = {
    "system/etc/vintf/manifest/android.hardware.boot-service.mtk.xml": b'<manifest version="1.0" type="framework">\n</manifest>\n',
    "system/etc/vintf/manifest/android.hardware.health-service.example.xml": b'<manifest version="1.0" type="framework">\n</manifest>\n',
}


def align(val: int, page: int) -> int:
    return ((val + page - 1) // page) * page


def pad_to(data: bytes, alignment: int) -> bytes:
    rem = len(data) % alignment
    return data if rem == 0 else data + b"\x00" * (alignment - rem)


def iter_cpio_full(cpio_data: bytes):
    """Yield (path, header_fields_dict, content_bytes) preserving all CPIO metadata."""
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
        fields = {
            "ino": int(hdr[6:14], 16),
            "mode": int(hdr[14:22], 16),
            "uid": int(hdr[22:30], 16),
            "gid": int(hdr[30:38], 16),
            "nlink": int(hdr[38:46], 16),
            "mtime": int(hdr[46:54], 16),
            "filesize": int(hdr[54:62], 16),
            "devmajor": int(hdr[62:70], 16),
            "devminor": int(hdr[70:78], 16),
            "rdevmajor": int(hdr[78:86], 16),
            "rdevminor": int(hdr[86:94], 16),
            "namesize": int(hdr[94:102], 16),
            "check": int(hdr[102:110], 16),
        }
        pos += 110
        name = cpio_data[pos : pos + fields["namesize"] - 1].decode("utf-8", errors="replace")
        pos = ((pos + fields["namesize"] + 3) // 4) * 4
        content = cpio_data[pos : pos + fields["filesize"]]
        pos = ((pos + fields["filesize"] + 3) // 4) * 4
        if name == "TRAILER!!!":
            continue
        yield name, fields, content


def build_cpio_entry(name: str, fields: dict, content: bytes) -> bytes:
    name_bytes = name.encode("utf-8") + b"\x00"
    hdr = (
        "070701"
        f"{fields['ino']:08X}"
        f"{fields['mode']:08X}"
        f"{fields['uid']:08X}"
        f"{fields['gid']:08X}"
        f"{fields['nlink']:08X}"
        f"{fields['mtime']:08X}"
        f"{len(content):08X}"
        f"{fields['devmajor']:08X}"
        f"{fields['devminor']:08X}"
        f"{fields['rdevmajor']:08X}"
        f"{fields['rdevminor']:08X}"
        f"{len(name_bytes):08X}"
        "00000000"
    ).encode("ascii")
    entry = pad_to(hdr + name_bytes, 4) + pad_to(content, 4)
    return entry


def compress_lz4_legacy(raw_cpio: bytes, lz4_bin: str = "lz4", level: int = 12) -> bytes:
    proc = subprocess.run(
        [lz4_bin, "-l", f"-{level}", "--stdout", "-"],
        input=raw_cpio,
        capture_output=True,
        check=True,
    )
    out = proc.stdout
    if out[:4] != b"\x02\x21\x4c\x18":
        raise ValueError(f"Unexpected LZ4 output magic: {out[:4].hex()}")
    return out


def repack_v4_two_fragment(
    stock_img: str,
    built_img: str,
    out_img: str,
    lz4_bin: str = "lz4",
    lz4_level: int = 12,
    partition_size: int = 67108864,
) -> dict:
    with open(stock_img, "rb") as f:
        s_data = f.read()
    with open(built_img, "rb") as f:
        b_data = f.read()

    if s_data[:8] != b"VNDRBOOT" or b_data[:8] != b"VNDRBOOT":
        raise ValueError("Both images must have VNDRBOOT magic")

    # Parse stock header & exact Fragment 0 (PLATFORM) bytes
    hver, page_size, kaddr, raddr, s_ramdisk_sz = struct.unpack_from("<IIIII", s_data, 8)
    cmdline_raw = s_data[28 : 28 + 2048]
    (tags_addr,) = struct.unpack_from("<I", s_data, 28 + 2048)
    name_raw = s_data[28 + 2048 + 4 : 28 + 2048 + 20]
    header_size, dtb_size, dtb_addr = struct.unpack_from("<IIQ", s_data, 28 + 2048 + 20)
    s_tbl_sz, s_entry_num, s_entry_sz, bootconfig_size = struct.unpack_from("<IIII", s_data, 28 + 2048 + 36)

    if hver != 4 or s_entry_num < 2:
        raise ValueError(f"Stock image must be v4 with >=2 fragments (got v{hver}, {s_entry_num})")

    s_ramdisk_off = align(header_size, page_size)
    s_dtb_off = s_ramdisk_off + align(s_ramdisk_sz, page_size)
    s_tbl_off = s_dtb_off + align(dtb_size, page_size)
    s_bc_off = s_tbl_off + align(s_tbl_sz, page_size)

    dtb_bytes = s_data[s_dtb_off : s_dtb_off + dtb_size]
    bootconfig_bytes = s_data[s_bc_off : s_bc_off + bootconfig_size]

    # Exact Stock Fragment 0 (PLATFORM) compressed blob & its entries for deduplication
    f0_size, f0_off, f0_type = struct.unpack_from("<III", s_data, s_tbl_off)
    f0_name_raw = s_data[s_tbl_off + 12 : s_tbl_off + 44]
    f0_board_id_raw = s_data[s_tbl_off + 44 : s_tbl_off + 108]
    if f0_type != 1:
        raise ValueError(f"Expected stock table[0] type=1 (PLATFORM), got {f0_type}")
    stock_f0_compressed = s_data[s_ramdisk_off + f0_off : s_ramdisk_off + f0_off + f0_size]

    # Stock Fragment 1 metadata (name='recovery', type=2, board_id)
    _, _, f1_type = struct.unpack_from("<III", s_data, s_tbl_off + s_entry_sz)
    f1_name_raw = s_data[s_tbl_off + s_entry_sz + 12 : s_tbl_off + s_entry_sz + 44]
    f1_board_id_raw = s_data[s_tbl_off + s_entry_sz + 44 : s_tbl_off + s_entry_sz + 108]

    # Decompress stock f0 to build exact lookup of (mode, sha256) for deduplication
    s0_cpio = decompress_lz4_legacy(stock_f0_compressed)
    s0_map: dict[str, tuple[int, str]] = {}
    for p, mode, content in iter_cpio(s0_cpio):
        s0_map[p.lstrip("/")] = (mode, hashlib.sha256(content).hexdigest())

    # Extract built OrangeFox ramdisk (Fragment 0 in single-fragment build)
    _, b_ps, _, _, b_ramdisk_sz = struct.unpack_from("<IIIII", b_data, 8)
    b_hsz = struct.unpack_from("<I", b_data, 28 + 2048 + 20)[0]
    b_ramdisk_off = align(b_hsz, b_ps)
    b_ramdisk_comp = b_data[b_ramdisk_off : b_ramdisk_off + b_ramdisk_sz]
    b_cpio = decompress_lz4_legacy(b_ramdisk_comp)

    # Build deduplicated RECOVERY CPIO (omit entries identical in path, mode, sha256 to s0)
    # Keep directory entries as needed (tiny, 112 bytes each) so parent dirs always exist
    out_cpio = bytearray()
    kept_entries = 0
    skipped_identical = 0
    max_ino = 0
    emitted_paths: set[str] = set()

    for path, fields, content in iter_cpio_full(b_cpio):
        norm = path.lstrip("/")
        if fields["ino"] > max_ino:
            max_ino = fields["ino"]
        is_dir = (fields["mode"] & 0o170000) == 0o040000
        sha = hashlib.sha256(content).hexdigest()
        if not is_dir and norm in s0_map and s0_map[norm] == (fields["mode"], sha):
            skipped_identical += 1
            continue
        out_cpio.extend(build_cpio_entry(norm, fields, content))
        emitted_paths.add(norm)
        kept_entries += 1

    # Add masks for conflicting stock PLATFORM recovery .rc & vintf xml files
    masked_added = 0
    for mask_map in (MASKED_RC_FILES, MASKED_VINTF_FILES):
        for mpath, mcontent in mask_map.items():
            if mpath in s0_map and mpath not in emitted_paths:
                max_ino += 1
                mfields = {
                    "ino": max_ino,
                    "mode": 0o100644,
                    "uid": 0,
                    "gid": 0,
                    "nlink": 1,
                    "mtime": 0,
                    "devmajor": 0,
                    "devminor": 0,
                    "rdevmajor": 0,
                    "rdevminor": 0,
                }
                out_cpio.extend(build_cpio_entry(mpath, mfields, mcontent))
                masked_added += 1

    # Append CPIO TRAILER!!!
    trailer_fields = {
        "ino": 0,
        "mode": 0,
        "uid": 0,
        "gid": 0,
        "nlink": 1,
        "mtime": 0,
        "devmajor": 0,
        "devminor": 0,
        "rdevmajor": 0,
        "rdevminor": 0,
    }
    out_cpio.extend(build_cpio_entry("TRAILER!!!", trailer_fields, b""))
    # Pad CPIO stream to 512-byte boundary
    raw_recovery_cpio = pad_to(bytes(out_cpio), 512)

    # Compress Fragment 1 (RECOVERY) with LZ4HC legacy
    recovery_f1_compressed = compress_lz4_legacy(raw_recovery_cpio, lz4_bin=lz4_bin, level=lz4_level)

    # Assemble vendor_boot v4 image
    combined_ramdisk = stock_f0_compressed + recovery_f1_compressed
    total_ramdisk_sz = len(combined_ramdisk)

    table_entry_0 = (
        struct.pack("<III", len(stock_f0_compressed), 0, 1) + f0_name_raw + f0_board_id_raw
    )
    table_entry_1 = (
        struct.pack("<III", len(recovery_f1_compressed), len(stock_f0_compressed), f1_type)
        + f1_name_raw
        + f1_board_id_raw
    )
    table_bytes = table_entry_0 + table_entry_1
    assert len(table_entry_0) == 108 and len(table_entry_1) == 108

    # Construct 2128-byte v4 header
    header = bytearray()
    header.extend(b"VNDRBOOT")
    header.extend(struct.pack("<IIIII", 4, page_size, kaddr, raddr, total_ramdisk_sz))
    header.extend(cmdline_raw)
    header.extend(struct.pack("<I", tags_addr))
    header.extend(name_raw)
    header.extend(struct.pack("<IIQ", header_size, len(dtb_bytes), dtb_addr))
    header.extend(struct.pack("<IIII", len(table_bytes), 2, 108, len(bootconfig_bytes)))
    assert len(header) == header_size == 2128

    image = bytearray()
    image.extend(pad_to(bytes(header), page_size))
    image.extend(pad_to(combined_ramdisk, page_size))
    image.extend(pad_to(dtb_bytes, page_size))
    image.extend(pad_to(table_bytes, page_size))
    if bootconfig_bytes:
        image.extend(pad_to(bootconfig_bytes, page_size))

    payload_size = len(image)
    if payload_size > partition_size:
        raise ValueError(
            f"Repacked image ({payload_size:,} B) exceeds partition size ({partition_size:,} B) by {payload_size - partition_size:,} B!"
        )

    # Pad to exact 64 MiB partition size (or leave unpadded? fastboot accepts <= 64MiB, padding matches stock/mkbootimg)
    image.extend(b"\x00" * (partition_size - payload_size))

    os.makedirs(os.path.dirname(os.path.abspath(out_img)), exist_ok=True)
    with open(out_img, "wb") as f:
        f.write(image)

    return {
        "out_img": out_img,
        "out_sha256": hashlib.sha256(image).hexdigest(),
        "payload_size": payload_size,
        "partition_size": partition_size,
        "free_bytes": partition_size - payload_size,
        "f0_stock_platform_size": len(stock_f0_compressed),
        "f1_recovery_raw_cpio": len(raw_recovery_cpio),
        "f1_recovery_compressed": len(recovery_f1_compressed),
        "kept_entries": kept_entries,
        "skipped_identical": skipped_identical,
        "masked_added": masked_added,
    }


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: repack_vendor_boot_v4.py <stock.img> <built.img> <out.img> [lz4_bin] [level]")
        sys.exit(2)
    lz4_b = sys.argv[4] if len(sys.argv) > 4 else "lz4"
    lvl = int(sys.argv[5]) if len(sys.argv) > 5 else 12
    res = repack_v4_two_fragment(sys.argv[1], sys.argv[2], sys.argv[3], lz4_bin=lz4_b, lz4_level=lvl)
    for k, v in res.items():
        print(f"{k}: {v}")
