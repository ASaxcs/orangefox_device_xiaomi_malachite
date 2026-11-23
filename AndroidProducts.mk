#
# Copyright (C) 2025-2026 The OrangeFox Recovery Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
#

PRODUCT_MAKEFILES := \
    $(LOCAL_DIR)/fox_malachite.mk \
    $(LOCAL_DIR)/twrp_malachite.mk

COMMON_LUNCH_CHOICES := \
    fox_malachite-user \
    fox_malachite-userdebug \
    fox_malachite-eng \
    twrp_malachite-eng
