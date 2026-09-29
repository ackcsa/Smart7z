# Copyright (C) 2026 Kurpphy
# SPDX-License-Identifier: GPL-3.0-only
"""Static attribution; contact encoding only discourages simple text harvesting."""

AUTHOR = "Kurpphy"
ATTRIBUTION = "by Kurpphy"
LICENSE_ID = "GPL-3.0-only"
SOURCE_MARK = "k7-6e83d9a4"


def contact_details():
    email = "".join(chr(code) for code in (
        97, 99, 107, 99, 115, 97, 64, 111, 117, 116, 108, 111, 111, 107, 46, 99, 111, 109
    ))
    qq = "".join(str(part) for part in (921, 408, 902))
    return f"{email}\nQQ: {qq}"
