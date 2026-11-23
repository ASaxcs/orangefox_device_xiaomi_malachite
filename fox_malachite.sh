#!/usr/bin/env bash
# OrangeFox fox_14.1 build environment variables for Xiaomi Redmi Note 14 Pro 5G (malachite)

export FOX_BUILD_DEVICE="malachite"
export OF_TARGET_DEVICES="malachite,malachite_id_global"
export OF_MAINTAINER="ASaxcs"
export FOX_VARIANT="HOS3_A16"
export FOX_BUILD_TYPE="Unofficial"

# Virtual A/B & vendor_boot recovery
export OF_AB_DEVICE=1
export FOX_VIRTUAL_AB_DEVICE=1
export FOX_VENDOR_BOOT_RECOVERY=1
export OF_USE_LZ4_COMPRESSION=1

# Display (1220x2712 AMOLED 120Hz punch-hole)
export OF_SCREEN_H=2712
export OF_STATUS_H=110
export OF_STATUS_INDENT_LEFT=48
export OF_STATUS_INDENT_RIGHT=48
export OF_HIDE_NOTCH=1
export OF_CLOCK_POS=1
export OF_ALLOW_DISABLE_NAVBAR=0

# Features & compatibility
export OF_ENABLE_LPTOOLS=1
export OF_NO_TREBLE_COMPATIBILITY_CHECK=1
export OF_NO_MIUI_PATCH_WARNING=1
export OF_DONT_PATCH_ENCRYPTED_DEVICE=1
export OF_SKIP_MULTIUSER_FOLDERS_BACKUP=1
export FOX_DELETE_AROMAFM=1
export FOX_USE_BASH_SHELL=1
export FOX_ASH_IS_BASH=1
export FOX_USE_TAR_BINARY=1
export FOX_USE_SED_BINARY=1
export FOX_USE_XZ_UTILS=1
export FOX_USE_ZSTD_BINARY=1
export OF_USE_MAGISKBOOT=1
export OF_USE_MAGISKBOOT_FOR_ALL_PATCHES=1
