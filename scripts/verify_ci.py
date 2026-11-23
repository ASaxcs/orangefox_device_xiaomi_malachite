#!/usr/bin/env python3
"""Verify built OrangeFox vendor_boot.img on GitHub Actions runner."""
import hashlib
import os
import re
import struct
import subprocess
import sys

BUILT = "release_out/vendor_boot.img"
SHA_FILE = "release_out/SHA256SUMS.txt"
EXPECTED_DTB_SHA = "e77d47ef3ef17e6d7547b6cff19f198a58f08a45348dfd83fb7448600c45357a"
MAX_SIZE = 67108864
ALLOWED_FLASHIMG = {"/boot", "/init_boot", "/vendor_boot"}
FORBIDDEN_EXT4 = ("protect1", "protect2", "nvdata", "nvcfg", "cust", "mcf_ota")


def align(v: int, p: int) -> int:
    return ((v + p - 1) // p) * p


def main() -> int:
    errors: list[str] = []
    with open(BUILT, "rb") as f:
        data = f.read()
    actual_sha = hashlib.sha256(data).hexdigest()

    matched = False
    with open(SHA_FILE, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 2 and os.path.basename(parts[-1]) == "vendor_boot.img":
                if parts[0].lower() != actual_sha.lower():
                    errors.append(f"SHA256 mismatch: {parts[0]} != {actual_sha}")
                matched = True
    if not matched:
        errors.append("vendor_boot.img missing from SHA256SUMS.txt")

    if data[:8] != b"VNDRBOOT":
        errors.append(f"Bad magic: {data[:8]!r}")
    hver, page_size, kaddr, raddr, ramdisk_size = struct.unpack_from("<IIIII", data, 8)
    cmdline = data[28 : 28 + 2048].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    header_size, dtb_size, dtb_addr = struct.unpack_from("<IIQ", data, 28 + 2048 + 20)

    off = align(header_size, page_size)
    ramdisk = data[off : off + ramdisk_size]
    off += align(ramdisk_size, page_size)
    dtb = data[off : off + dtb_size]
    dtb_sha = hashlib.sha256(dtb).hexdigest()

    print(f"Size: {len(data):,} / {MAX_SIZE:,} bytes")
    print(f"Header: v{hver} | Page: {page_size} | HeaderSize: {header_size}")
    print(f"Cmdline: {cmdline!r}")
    print(f"DTB: {dtb_size} bytes | SHA256: {dtb_sha}")

    if len(data) > MAX_SIZE:
        errors.append(f"Image exceeds 64MiB: {len(data)}")
    if hver != 4 or page_size != 4096:
        errors.append(f"Unexpected header v{hver} / page {page_size}")
    if dtb_sha != EXPECTED_DTB_SHA:
        errors.append(f"DTB SHA256 mismatch: {dtb_sha} != {EXPECTED_DTB_SHA}")
    if "androidboot.selinux=permissive" in cmdline:
        errors.append(f"SELinux permissive leaked in cmdline: {cmdline}")

    with open("/tmp/ramdisk.lz4", "wb") as f:
        f.write(ramdisk)
    os.makedirs("/tmp/ramdisk_fs", exist_ok=True)
    subprocess.run(
        "lz4 -dc /tmp/ramdisk.lz4 | (cd /tmp/ramdisk_fs && cpio -idmu --quiet)",
        shell=True,
        check=True,
    )

    has_recovery = os.path.exists("/tmp/ramdisk_fs/system/bin/recovery") or os.path.exists(
        "/tmp/ramdisk_fs/sbin/recovery"
    )
    fox_hits = []
    twrp_flags_path = None
    ko_count = 0
    vermagics = set()
    vm_pat = re.compile(rb"vermagic=([^\x00]+)")

    for root, _, files in os.walk("/tmp/ramdisk_fs"):
        for fn in files:
            full = os.path.join(root, fn)
            rel = os.path.relpath(full, "/tmp/ramdisk_fs")
            if "fox" in rel.lower() or "twres" in rel.lower():
                fox_hits.append(rel)
            if rel.endswith("etc/twrp.flags"):
                twrp_flags_path = full
            if fn.endswith(".ko"):
                ko_count += 1
                with open(full, "rb") as kf:
                    m = vm_pat.search(kf.read())
                if m:
                    vermagics.add(m.group(1).decode("utf-8", errors="replace").strip())

    print(f"Recovery binary: {has_recovery} | OrangeFox/twres files: {len(fox_hits)}")
    print(f"Kernel modules (.ko): {ko_count} | vermagic: {sorted(vermagics)}")

    if not has_recovery:
        errors.append("Missing recovery binary")
    if len(fox_hits) == 0:
        errors.append("Missing OrangeFox/twres assets")
    if ko_count == 0 or not any("6.1.138" in v for v in vermagics):
        errors.append(f"Invalid kernel modules: count={ko_count}, vermagic={vermagics}")
    if not twrp_flags_path:
        errors.append("Missing etc/twrp.flags in ramdisk")
    else:
        with open(twrp_flags_path, "r", encoding="utf-8", errors="replace") as tf:
            for ln, raw in enumerate(tf, 1):
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

    if errors:
        print("VERIFICATION FAILED:")
        for e in errors:
            print("  -", e)
        return 1
    print("ALL CHECKS PASSED: OrangeFox vendor_boot.img is 100% verified!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
