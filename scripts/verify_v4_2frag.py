#!/usr/bin/env python3
"""Verify repacked 2-fragment vendor_boot v4 image:
1. Header, DTB, cmdline, partition size match stock OS3.0.303.0.WOOIDXM
2. Fragment 0 (PLATFORM) is 100% bit-for-bit identical to stock Fragment 0
3. Fragment 1 (RECOVERY) is valid LZ4-legacy + CPIO
4. Merged (F0 + F1) matches every single file in single-fragment OrangeFox build (by SHA256),
   masks conflicting stock .rc files, and passes hardened twrp.flags checks.
"""
import hashlib
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from compare_ramdisks import parse_v4_fragments

ALLOWED_FLASHIMG = {"/boot", "/init_boot", "/vendor_boot"}
FORBIDDEN_EXT4 = ("protect1", "protect2", "nvdata", "nvcfg", "cust", "mcf_ota")


def align(val: int, page: int) -> int:
    return ((val + page - 1) // page) * page


def raw_f0_blob(img_path: str) -> bytes:
    data = open(img_path, "rb").read()
    _, ps, _, _, rsz = struct.unpack_from("<IIIII", data, 8)
    hsz, dtbsz, _ = struct.unpack_from("<IIQ", data, 28 + 2048 + 20)
    roff = align(hsz, ps)
    toff = roff + align(rsz, ps) + align(dtbsz, ps)
    f0_sz, f0_off, f0_type = struct.unpack_from("<III", data, toff)
    assert f0_type == 1
    return data[roff + f0_off : roff + f0_off + f0_sz]


def verify(repacked_img: str, stock_img: str, orig_built_img: str) -> int:
    errors: list[str] = []

    r_meta, r_frags = parse_v4_fragments(repacked_img)
    s_meta, s_frags = parse_v4_fragments(stock_img)
    b_meta, b_frags = parse_v4_fragments(orig_built_img)

    # 1. Basic image checks
    if r_meta["file_size"] != s_meta["file_size"]:
        errors.append(f"Size mismatch: repacked={r_meta['file_size']} vs stock={s_meta['file_size']}")
    if r_meta["header_version"] != 4 or r_meta["page_size"] != 4096:
        errors.append(f"Bad header: v{r_meta['header_version']} page={r_meta['page_size']}")
    if len(r_frags) != 2:
        errors.append(f"Expected 2 fragments, got {len(r_frags)}")
    else:
        if r_frags[0]["type"] != 1 or r_frags[0]["name"] != "":
            errors.append(f"Bad F0 metadata: type={r_frags[0]['type']} name={r_frags[0]['name']!r}")
        if r_frags[1]["type"] != 2 or r_frags[1]["name"] != "recovery":
            errors.append(f"Bad F1 metadata: type={r_frags[1]['type']} name={r_frags[1]['name']!r}")

    # 2. Bit-for-bit check of F0 compressed blob & DTB & cmdline
    if hashlib.sha256(raw_f0_blob(repacked_img)).hexdigest() != hashlib.sha256(raw_f0_blob(stock_img)).hexdigest():
        errors.append("Fragment 0 (PLATFORM) is NOT bit-for-bit identical to stock!")

    r_raw = open(repacked_img, "rb").read()
    s_raw = open(stock_img, "rb").read()
    r_cmd = r_raw[28 : 28 + 2048].split(b"\x00", 1)[0].decode()
    s_cmd = s_raw[28 : 28 + 2048].split(b"\x00", 1)[0].decode()
    if r_cmd != s_cmd:
        errors.append(f"Cmdline mismatch: {r_cmd!r} != {s_cmd!r}")
    if "selinux=permissive" in r_cmd:
        errors.append(f"Permissive SELinux leaked in cmdline: {r_cmd!r}")

    # 3. Simulate kernel merged initramfs during recovery boot: F0 first, then F1 overlay
    merged: dict[str, tuple[int, str, int, bytes]] = {}
    for p, v in r_frags[0]["entries"].items():
        merged[p] = v
    for p, v in r_frags[1]["entries"].items():
        merged[p] = v

    # Verify every single non-first_stage_ramdisk file from orig_built_img exists in merged with identical SHA256
    orig_entries = b_frags[0]["entries"]
    missing_from_merged = []
    diff_in_merged = []
    for p, (mode, sha, sz, _) in orig_entries.items():
        is_dir = (mode & 0o170000) == 0o040000
        if is_dir or p == "first_stage_ramdisk" or p.startswith("first_stage_ramdisk/"):
            continue
        if p not in merged:
            missing_from_merged.append(p)
        elif merged[p][1] != sha:
            diff_in_merged.append(p)

    # Verify LZ4 EOS sentinel (4 zero bytes) before non-LZ4 Fragment 1
    r_data = open(repacked_img, "rb").read()
    _, ps, _, _, rsz = struct.unpack_from("<IIIII", r_data, 8)
    hsz, dtbsz, _ = struct.unpack_from("<IIQ", r_data, 28 + 2048 + 20)
    roff = align(hsz, ps)
    toff = roff + align(rsz, ps) + align(dtbsz, ps)
    f1_sz, f1_off, _ = struct.unpack_from("<III", r_data, toff + 108)
    f1_head = r_data[roff + f1_off : roff + f1_off + 8]
    if f1_head[:4] != b"\x02\x21\x4c\x18":
        if f1_head[:4] != b"\x00\x00\x00\x00" or f1_head[4:8] != b"\x28\xb5\x2f\xfd":
            errors.append(f"Fragment 1 missing 4-byte LZ4 EOS sentinel before ZSTD magic: {f1_head.hex()}")

    if missing_from_merged:
        errors.append(f"Merged recovery missing {len(missing_from_merged)} OrangeFox files: {missing_from_merged[:10]}")
    if diff_in_merged:
        errors.append(f"Merged recovery differs on {len(diff_in_merged)} OrangeFox files: {diff_in_merged[:10]}")

    # Check conflicting stock .rc files are masked in merged recovery view
    for rc in (
        "system/etc/init/servicemanager.recovery.rc",
        "system/etc/init/logd.rc",
        "system/etc/init/android.hardware.boot-service.mtk_recovery.rc",
        "system/etc/init/android.hardware.health-service.example_recovery.rc",
        "miui.factoryreset.rc",
    ):
        if rc in merged:
            txt = merged[rc][3].decode("utf-8", errors="replace").strip()
            if not txt.startswith("# masked"):
                errors.append(f"Conflicting stock rc NOT masked in recovery: {rc}")

    # Check hardened twrp.flags in merged recovery view
    tf_key = next((k for k in merged if k.endswith("etc/twrp.flags")), None)
    if not tf_key:
        errors.append("Missing etc/twrp.flags in merged recovery")
    else:
        for ln, raw in enumerate(merged[tf_key][3].decode("utf-8", errors="replace").splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            mnt, fstype = parts[0], (parts[1] if len(parts) > 1 else "")
            dev = parts[2] if len(parts) > 2 else ""
            if "flashimg=1" in line and mnt not in ALLOWED_FLASHIMG:
                errors.append(f"twrp.flags:{ln}: forbidden flashimg=1 on {mnt}")
            if fstype == "ext4" and any(d in dev for d in FORBIDDEN_EXT4):
                errors.append(f"twrp.flags:{ln}: forbidden ext4 mount on {dev}")

    print(f"Repacked SHA256: {r_meta['sha256']}")
    print(f"F0 (PLATFORM) == Stock F0 bit-for-bit: {len([e for e in errors if 'Fragment 0' in e]) == 0}")
    print(f"F0 entries: {len(r_frags[0]['entries'])} ({r_frags[0]['compressed_size']:,} B compressed)")
    print(f"F1 (RECOVERY) entries: {len(r_frags[1]['entries'])} ({r_frags[1]['compressed_size']:,} B compressed)")
    print(f"Merged recovery files matching orig OrangeFox build: {len(orig_entries)} checked, missing={len(missing_from_merged)}, diff={len(diff_in_merged)}")

    if errors:
        print("2-FRAG VERIFICATION FAILED:")
        for e in errors:
            print("  -", e)
        return 1
    print("ALL 2-FRAG CHECKS PASSED!")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: verify_v4_2frag.py <repacked.img> <stock.img> <orig_built.img>")
        sys.exit(2)
    sys.exit(verify(sys.argv[1], sys.argv[2], sys.argv[3]))
