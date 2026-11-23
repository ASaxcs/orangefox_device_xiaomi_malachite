#!/usr/bin/env python3
"""Safely apply AIDL haptics non-blocking patch to bootable/recovery/minuitwrp/events.cpp."""
import subprocess
import sys


def main() -> int:
    if len(sys.argv) < 3:
        print("Usage: apply_haptics_patch.py <recovery_dir> <patch_file>")
        return 2

    recovery_dir = sys.argv[1]
    patch_file = sys.argv[2]
    events_path = f"{recovery_dir}/minuitwrp/events.cpp"

    with open(events_path, "r", encoding="utf-8") as f:
        src = f.read()

    if "AServiceManager_checkService" in src:
        print("Haptics patch already present in events.cpp; skipping.")
        return 0

    chk = subprocess.run(
        ["git", "-C", recovery_dir, "apply", "--check", patch_file],
        capture_output=True,
        text=True,
    )
    if chk.returncode == 0:
        subprocess.run(["git", "-C", recovery_dir, "apply", patch_file], check=True)
        print("Applied haptics patch via git apply.")
        return 0

    if "#include <android-base/properties.h>" not in src:
        src = src.replace(
            "#include <android/binder_manager.h>",
            "#include <android-base/properties.h>\n#include <android/binder_manager.h>",
            1,
        )

    old = "std::shared_ptr<IVibrator> vib = IVibrator::fromBinder(ndk::SpAIBinder(AServiceManager_getService(kVibratorInstance.c_str())));"
    new = (
        "// Recovery may run before servicemanager; vibration is optional, so do not wait for it.\n"
        '    if (!android::base::GetBoolProperty("servicemanager.ready", false)) {\n'
        "        return 0;\n"
        "    }\n"
        "    std::shared_ptr<IVibrator> vib = IVibrator::fromBinder(ndk::SpAIBinder(\n"
        "            AServiceManager_checkService(kVibratorInstance.c_str())));"
    )
    if old in src:
        src = src.replace(old, new, 1)
        with open(events_path, "w", encoding="utf-8") as f:
            f.write(src)
        print("Applied haptics patch via python fallback.")
        return 0

    print("WARNING: Target haptics line not found in events.cpp; continuing unmodified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
