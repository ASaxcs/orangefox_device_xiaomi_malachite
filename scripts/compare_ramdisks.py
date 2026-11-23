#!/usr/bin/env python3
"""Compare vendor_boot v4 ramdisk fragments between built OrangeFox and stock OS3.0.303.0.WOOIDXM."""
import difflib
import hashlib
import os
import re
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from extract_lz4_cpio import decompress_lz4_legacy, iter_cpio

RAMDISK_TYPES = {
    0: "NONE",
    1: "PLATFORM",
    2: "RECOVERY",
    3: "DLKM",
}

CRITICAL_EXACT = {
    "first_stage_ramdisk/fstab.mt6878",
    "first_stage_ramdisk/fstab.emmc",
}
CRITICAL_BASENAMES = {
    "fstab.mt6878",
    "fstab.emmc",
    "modules.dep",
    "modules.alias",
    "modules.softdep",
    "ueventd.rc",
}


def is_critical(path: str) -> bool:
    norm = path.lstrip("/")
    if norm in CRITICAL_EXACT:
        return True
    base = os.path.basename(norm)
    if base in CRITICAL_BASENAMES or base.startswith("modules.load"):
        return True
    return False


def align(val: int, page: int) -> int:
    return ((val + page - 1) // page) * page


def parse_v4_fragments(img_path: str) -> tuple[dict, list[dict]]:
    with open(img_path, "rb") as f:
        data = f.read()

    if data[:8] != b"VNDRBOOT":
        raise ValueError(f"{img_path}: invalid magic {data[:8]!r}")

    header_version, page_size, _, _, vendor_ramdisk_size = struct.unpack_from("<IIIII", data, 8)
    if header_version < 4:
        raise ValueError(f"{img_path}: expected header_version >= 4, got {header_version}")

    header_size, dtb_size, _ = struct.unpack_from("<IIQ", data, 28 + 2048 + 20)
    table_size, entry_num, entry_size = struct.unpack_from("<III", data, 28 + 2048 + 36)

    if entry_size < 108:
        raise ValueError(f"{img_path}: unexpected table entry_size {entry_size}")
    if table_size < entry_num * entry_size:
        raise ValueError(f"{img_path}: table_size {table_size} < {entry_num * entry_size}")

    off = align(header_size, page_size)
    ramdisk_blob = data[off : off + vendor_ramdisk_size]
    off += align(vendor_ramdisk_size, page_size)
    off += align(dtb_size, page_size)
    table_blob = data[off : off + table_size]

    fragments: list[dict] = []
    for idx in range(entry_num):
        base = idx * entry_size
        frag_size, frag_off, frag_type = struct.unpack_from("<III", table_blob, base)
        name_raw = table_blob[base + 12 : base + 44]
        frag_name = name_raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        if frag_off + frag_size > len(ramdisk_blob):
            raise ValueError(
                f"{img_path}: fragment[{idx}] ({frag_name}) range {frag_off}+{frag_size} exceeds vendor_ramdisk_size {len(ramdisk_blob)}"
            )
        frag_bytes = ramdisk_blob[frag_off : frag_off + frag_size]
        magic = frag_bytes[:4]
        if magic != b"\x02\x21\x4c\x18":
            raise ValueError(
                f"{img_path}: fragment[{idx}] ({frag_name}) uses non-lz4-legacy magic {magic.hex()}"
            )
        cpio_bytes = decompress_lz4_legacy(frag_bytes)
        entries: dict[str, tuple[int, str, int, bytes]] = {}
        for path, mode, content in iter_cpio(cpio_bytes):
            norm = path.lstrip("/")
            sha = hashlib.sha256(content).hexdigest()
            entries[norm] = (mode, sha, len(content), content)

        fragments.append(
            {
                "index": idx,
                "name": frag_name,
                "type": frag_type,
                "type_name": RAMDISK_TYPES.get(frag_type, f"UNKNOWN({frag_type})"),
                "compressed_size": frag_size,
                "offset": frag_off,
                "cpio_size": len(cpio_bytes),
                "entries": entries,
            }
        )

    meta = {
        "file_size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "header_version": header_version,
        "page_size": page_size,
        "vendor_ramdisk_size": vendor_ramdisk_size,
        "entry_num": entry_num,
    }
    return meta, fragments


def pair_fragments(built_frags: list[dict], stock_frags: list[dict]) -> tuple[list[tuple[dict | None, dict | None]], bool]:
    pairs: list[tuple[dict | None, dict | None]] = []
    used_built: set[int] = set()
    ambiguous = False

    for sf in stock_frags:
        matches = [
            bf for bf in built_frags
            if bf["index"] not in used_built and bf["name"] == sf["name"] and bf["type"] == sf["type"]
        ]
        if not matches:
            matches = [
                bf for bf in built_frags
                if bf["index"] not in used_built and bf["type"] == sf["type"]
            ]
        if len(matches) == 1:
            used_built.add(matches[0]["index"])
            pairs.append((matches[0], sf))
        elif len(matches) > 1:
            ambiguous = True
            used_built.add(matches[0]["index"])
            pairs.append((matches[0], sf))
        else:
            pairs.append((None, sf))

    for bf in built_frags:
        if bf["index"] not in used_built:
            pairs.append((bf, None))

    if len(built_frags) != len(stock_frags):
        ambiguous = True

    return pairs, ambiguous


def compare(built_img: str, stock_img: str, out_md: str) -> int:
    b_meta, b_frags = parse_v4_fragments(built_img)
    s_meta, s_frags = parse_v4_fragments(stock_img)

    pairs, ambiguous = pair_fragments(b_frags, s_frags)

    # Combined maps across all fragments (path -> list of (frag_label, mode, sha, size, content))
    s_all: dict[str, tuple[int, str, int, bytes, str]] = {}
    for sf in s_frags:
        lbl = f"{sf['type_name']}:{sf['name'] or '<empty>'}"
        for p, (m, sha, sz, c) in sf["entries"].items():
            s_all[p] = (m, sha, sz, c, lbl)

    b_all: dict[str, tuple[int, str, int, bytes, str]] = {}
    for bf in b_frags:
        lbl = f"{bf['type_name']}:{bf['name'] or '<empty>'}"
        for p, (m, sha, sz, c) in bf["entries"].items():
            b_all[p] = (m, sha, sz, c, lbl)

    combined_missing = sorted(set(s_all) - set(b_all))
    combined_extra = sorted(set(b_all) - set(s_all))
    combined_diff = sorted(p for p in (set(s_all) & set(b_all)) if s_all[p][1] != b_all[p][1])

    # Check all .ko modules from stock
    stock_kos = {p: v for p, v in s_all.items() if p.endswith(".ko")}
    built_kos = {p: v for p, v in b_all.items() if p.endswith(".ko")}
    ko_missing = sorted(set(stock_kos) - set(built_kos))
    ko_diff = sorted(p for p in (set(stock_kos) & set(built_kos)) if stock_kos[p][1] != built_kos[p][1])

    # Critical files check (exact path or basename match)
    critical_paths = sorted(p for p in (set(s_all) | set(b_all)) if is_critical(p))
    critical_issues: list[str] = []
    critical_diffs: list[tuple[str, str]] = []

    for p in critical_paths:
        in_s = p in s_all
        in_b = p in b_all
        if in_s and not in_b:
            critical_issues.append(f"HILANG di build: `{p}` (dari stock {s_all[p][4]})")
        elif in_s and in_b and s_all[p][1] != b_all[p][1]:
            critical_issues.append(f"BERBEDA di build: `{p}`")
            s_txt = s_all[p][3].decode("utf-8", errors="replace").splitlines(keepends=True)
            b_txt = b_all[p][3].decode("utf-8", errors="replace").splitlines(keepends=True)
            diff_str = "".join(
                difflib.unified_diff(s_txt, b_txt, fromfile=f"stock/{p}", tofile=f"built/{p}")
            )
            critical_diffs.append((p, diff_str))

    lines: list[str] = []
    lines.append("# Perbandingan Ramdisk `vendor_boot.img` (OrangeFox Build vs Stock `OS3.0.303.0.WOOIDXM`)")
    lines.append("")
    lines.append(f"- **Built:** `{built_img}` (SHA256: `{b_meta['sha256']}`, size: {b_meta['file_size']:,} bytes, entries: {b_meta['entry_num']})")
    lines.append(f"- **Stock:** `{stock_img}` (SHA256: `{s_meta['sha256']}`, size: {s_meta['file_size']:,} bytes, entries: {s_meta['entry_num']})")
    lines.append("")

    # (a) Daftar fragmen
    lines.append("## a) Daftar Fragmen Vendor Ramdisk v4")
    lines.append("")
    lines.append("| Image | Index | Name | Type | Compressed Size | CPIO Size | Jumlah Entri |")
    lines.append("| :--- | :---: | :--- | :--- | ---: | ---: | ---: |")
    for tag, frags in [("Built", b_frags), ("Stock", s_frags)]:
        for fr in frags:
            nm = fr["name"] if fr["name"] else "`<empty>`"
            lines.append(
                f"| {tag} | {fr['index']} | {nm} | {fr['type_name']} ({fr['type']}) | {fr['compressed_size']:,} | {fr['cpio_size']:,} | {len(fr['entries'])} |"
            )
    lines.append("")

    # Per-fragment comparison
    lines.append("## b & c) Perbandingan Per Fragmen dan Gabungan")
    lines.append("")
    for bf, sf in pairs:
        if bf and sf:
            s_e, b_e = sf["entries"], bf["entries"]
            miss = sorted(set(s_e) - set(b_e))
            diff = sorted(p for p in (set(s_e) & set(b_e)) if s_e[p][1] != b_e[p][1])
            extra = sorted(set(b_e) - set(s_e))
            lines.append(f"### Pasangan Fragmen `{sf['type_name']}:{sf['name'] or '<empty>'}` vs `{bf['type_name']}:{bf['name'] or '<empty>'}`")
            lines.append(f"- File stock yang **hilang** di fragmen ini: **{len(miss)}**")
            for p in miss[:50]:
                lines.append(f"  - `{p}`")
            if len(miss) > 50:
                lines.append(f"  - ... dan {len(miss) - 50} lainnya")
            lines.append(f"- File yang ada di keduanya tapi **hash berbeda**: **{len(diff)}**")
            for p in diff[:50]:
                lines.append(f"  - `{p}` (stock {s_e[p][2]} B -> built {b_e[p][2]} B)")
            if len(diff) > 50:
                lines.append(f"  - ... dan {len(diff) - 50} lainnya")
            lines.append(f"- File tambahan di built pada fragmen ini: **{len(extra)}**")
            lines.append("")
        elif sf and not bf:
            lines.append(f"### Fragmen Stock `{sf['type_name']}:{sf['name'] or '<empty>'}` TIDAK PUNYA PASANGAN di Build ({len(sf['entries'])} entri)")
            lines.append("")
        elif bf and not sf:
            lines.append(f"### Fragmen Built `{bf['type_name']}:{bf['name'] or '<empty>'}` TIDAK ADA di Stock ({len(bf['entries'])} entri)")
            lines.append("")

    lines.append("### Gabungan (Lintas Fragmen)")
    lines.append(f"- Total entri unik Stock: **{len(s_all)}** | Built: **{len(b_all)}**")
    lines.append(f"- File stock yang **HILANG secara gabungan** di build: **{len(combined_missing)}**")
    for p in combined_missing:
        lines.append(f"  - `{p}` (dari `{s_all[p][4]}`)")
    lines.append(f"- File yang ada di keduanya tapi **hash berbeda**: **{len(combined_diff)}**")
    for p in combined_diff:
        lines.append(f"  - `{p}` (stock {s_all[p][2]} B -> built {b_all[p][2]} B)")
    lines.append(f"- File tambahan di build (recovery/OrangeFox): **{len(combined_extra)}**")
    lines.append("")

    # (d) Summary of extra files
    lines.append("## d) Ringkasan File Tambahan di Build")
    lines.append(f"Total **{len(combined_extra)}** file tambahan di build (termasuk aset OrangeFox/`twres`, binary `recovery`, library recovery, dsb.).")
    lines.append("")

    # (e) Critical files
    lines.append("## e) Audit File Kritis Boot Normal (`fstab.*`, `modules.load*`, `modules.*`, `ueventd.rc`)")
    for p in critical_paths:
        in_s = p in s_all
        in_b = p in b_all
        if in_s and in_b:
            status = "IDENTIK" if s_all[p][1] == b_all[p][1] else "BERBEDA"
        elif in_s:
            status = "HILANG DI BUILD"
        else:
            status = "HANYA DI BUILD (tambahan)"
        lines.append(f"- `{p}`: **{status}**")
    lines.append("")
    if critical_diffs:
        lines.append("### Diff Teks File Kritis yang Berbeda")
        for p, dtxt in critical_diffs:
            lines.append(f"#### `{p}`")
            lines.append("```diff")
            lines.append(dtxt.rstrip())
            lines.append("```")
            lines.append("")

    # (f) 224 .ko modules
    lines.append("## f) Audit Modul Kernel (`.ko`)")
    lines.append(f"- Jumlah `.ko` di Stock: **{len(stock_kos)}** | di Build: **{len(built_kos)}**")
    lines.append(f"- `.ko` stock yang hilang di build: **{len(ko_missing)}**")
    for p in ko_missing:
        lines.append(f"  - `{p}`")
    lines.append(f"- `.ko` stock yang hash-nya berbeda di build: **{len(ko_diff)}**")
    for p in ko_diff:
        lines.append(f"  - `{p}`")
    lines.append("")

    os.makedirs(os.path.dirname(os.path.abspath(out_md)), exist_ok=True)
    with open(out_md, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Report written to {out_md}")
    print(f"Ambiguous fragment pairing: {ambiguous}")
    print(f"Combined missing stock files: {len(combined_missing)}")
    print(f"Combined diff files: {len(combined_diff)}")
    print(f"Combined extra built files: {len(combined_extra)}")
    print(f"Critical issues: {len(critical_issues)}")
    print(f"Stock .ko: {len(stock_kos)}, missing: {len(ko_missing)}, diff: {len(ko_diff)}")

    passed = (len(combined_missing) == 0) and (len(critical_issues) == 0) and (len(ko_missing) == 0) and (len(ko_diff) == 0)
    return 0 if passed else 1


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python scripts/compare_ramdisks.py <built.img> <stock.img> <out_md>")
        sys.exit(2)
    sys.exit(compare(sys.argv[1], sys.argv[2], sys.argv[3]))
