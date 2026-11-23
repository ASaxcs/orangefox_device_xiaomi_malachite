#
# Copyright (C) 2025-2026 The OrangeFox Recovery Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
#

DEVICE_PATH := device/xiaomi/malachite

# Inherit from device.mk configuration
$(call inherit-product, $(DEVICE_PATH)/device.mk)

# Device identifier
PRODUCT_DEVICE := malachite
PRODUCT_NAME := fox_malachite
PRODUCT_BRAND := Redmi
PRODUCT_MODEL := Redmi Note 14 Pro 5G
PRODUCT_MANUFACTURER := Xiaomi
PRODUCT_RELEASE_NAME := Redmi Note 14 Pro 5G
