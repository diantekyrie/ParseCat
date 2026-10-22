"""Deterministic scrubbing of personal data from free-text log fields before
they are written to the database (issue: redact PII from stored text).

Scope, deliberately narrow:
  * Applied only to free-text columns copied verbatim from device logs
    (crash / root-cause messages, kernel log lines, ANR subject/reason,
    focus / BT-framework / CDM detail, am_kill reason, tombstone cmdline).
  * Structured identifiers the parsers extract on purpose (serial, build
    fingerprint, BT / companion MAC, SSID / BSSID, lat/long) are NOT touched
    here; whether to keep them at rest is a separate FE / owner policy call.

Patterns are conservative by design: a missed bare number is preferable to
mangling a timestamp, PID, hex address, MAC, version string or build
fingerprint that diagnosis depends on. Known false negatives are listed in
the PR security note (bare 10-digit phone numbers, unformatted bare
15-digit IMEIs and IMSI / ICCID / MEID without a keyword, non-email account names outside the Account{} form, lower-case
multi-word unquoted account_name= values).

Every replacement is a typed token so a reader can still see *that* a value
was there and what kind it was, e.g. ``[redacted-email]``.
"""
from __future__ import annotations

import re
from typing import Optional

EMAIL_TOKEN = "[redacted-email]"
PHONE_TOKEN = "[redacted-phone]"
IMEI_TOKEN = "[redacted-imei]"
MEID_TOKEN = "[redacted-meid]"
IMSI_TOKEN = "[redacted-imsi]"
ICCID_TOKEN = "[redacted-iccid]"
ACCOUNT_TOKEN = "[redacted-account]"

# A value only counts as standalone when it is not glued to other
# identifier-ish characters. This is what keeps hex pointers (0x...),
# MACs (aa:bb:...), dotted versions / build ids, and nanosecond timestamp
# fractions (.123456789) from matching the numeric patterns below.
_NB = r"(?<![\w.:/@+-])"   # not-before
_NA = r"(?![\w:/@-]|\.\d)"  # not-after (a trailing sentence period is fine)

# Android account objects: `Account {name=..., type=...}`. The name may be
# an email or a free-form display name, so the whole name value goes.
_ACCOUNT_OBJ_RE = re.compile(r"(Account\s*\{\s*name=)([^,}]+)", re.IGNORECASE)
# key=value spellings seen in AccountManager / sync logs. The value is a
# quoted string (any content), or an unquoted first word plus up to three
# following Capitalised words so a display name like `Jane Doe` goes whole
# while trailing log prose (`... failed to sync`) survives. Lower-case
# multi-word unquoted names keep their tail: a listed false negative.
_ACCOUNT_KV_RE = re.compile(
    r"\b((?i:account_?name|authAccount)\s*[=:]\s*)"
    r"(?!\[redacted-)(\"[^\"]*\"|'[^']*'|[^\s,;}\]]+(?:[ ]+[A-Z][\w'.-]*(?![\w=:])){0,3})",
)

# Keyword-anchored identifiers. Without the keyword a 14-20 digit run is
# indistinguishable from epoch-ms/us/ns counters, so we require it.
_IMSI_KV_RE = re.compile(r"\b(imsi\s*[=:]?\s*)(\d{6,15})\b", re.IGNORECASE)
_ICCID_KV_RE = re.compile(r"\b(icc_?id\s*[=:]?\s*)(\d{18,22}[Ff]?)\b", re.IGNORECASE)
_MEID_KV_RE = re.compile(r"\b(meid\s*[=:]?\s*)([0-9A-Fa-f]{14}|\d{18})\b", re.IGNORECASE)
_IMEI_KV_RE = re.compile(r"\b(imei(?:sv)?\s*[=:]?\s*)(\d{14,16})\b", re.IGNORECASE)

# RFC-5322-ish, restricted so HIDL names (android.hardware.foo@1.0),
# versioned symbols (memcpy@GLIBC_2.14) and Java `Class@hash` toString()s
# glued onto a package/class path (`...Listener@e5e02decom.example.Player`,
# seen in a real audio-focus clientId) don't match:
#   * domain = dot-separated alnum labels ending in an alphabetic TLD,
#   * the match may not continue into another `.label` (no partial domain),
#   * the TLD may not be CamelCase (Java class names are),
#   * at most 5 domain labels (package paths are usually longer).
_EMAIL_RE = re.compile(
    r"(?<![\w.%+-])[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+([A-Za-z]{2,24}))"
    r"(?![\w-]|\.[A-Za-z0-9])"
)
_MAX_EMAIL_DOMAIN_LABELS = 5


def _email_sub(m: re.Match) -> str:
    domain, tld = m.group(1), m.group(2)
    if not (tld.islower() or tld.isupper()):
        return m.group(0)
    if domain.count(".") + 1 > _MAX_EMAIL_DOMAIN_LABELS:
        return m.group(0)
    return EMAIL_TOKEN


# Bare IMEI only in its printed, separated form (AA-BBBBBB-CCCCCC-D or
# with spaces), Luhn-checked. An unformatted bare 15-digit run is NOT
# redacted without a keyword: on a real capture a kernel nanosecond
# timestamp (IN_TS=<15 digits>) passed Luhn, and uptime-in-ns values are
# 15 digits for most of a device's first ~11 days.
_IMEI_SEP_RE = re.compile(_NB + r"(\d{2}[- ]\d{6}[- ]\d{6}[- ]\d)" + _NA)
_IMEI_DEVICE_ID_RE = re.compile(
    r"\b((?:device_?id|deviceId)\s*[=:]\s*)(\d{15})\b", re.IGNORECASE
)


# Phones. E.164 needs a leading '+'; NANP needs separators (so bare 10-digit
# runs -- epoch seconds, byte counts -- are left alone) and valid area /
# exchange first digits [2-9].
_E164_RE = re.compile(
    _NB + r"\+[1-9]\d{0,2}(?:[ -]?\(?\d{1,4}\)?){2,5}" + _NA
)
_NANP_RE = re.compile(
    _NB + r"(?:\+?1[ .-])?(?:\([2-9]\d{2}\)\s?|[2-9]\d{2}[ .-])[2-9]\d{2}[ .-]\d{4}" + _NA
)
_TEL_URI_RE = re.compile(r"\btel:\+?[\d().-]{7,}", re.IGNORECASE)


def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _e164_sub(m: re.Match) -> str:
    digits = re.sub(r"\D", "", m.group(0))
    # E.164 is at most 15 digits. Require 10+ so short "+12345678"-style
    # offsets / deltas stay as-is; this misses a few 8-9 digit national
    # plans, an accepted false negative.
    if 10 <= len(digits) <= 15:
        return PHONE_TOKEN
    return m.group(0)


def _imei_sep_sub(m: re.Match) -> str:
    digits = re.sub(r"\D", "", m.group(1))
    return IMEI_TOKEN if _luhn_ok(digits) else m.group(0)


def _device_id_sub(m: re.Match) -> str:
    # deviceId=<15 digits> is an IMEI on GSM phones; Luhn keeps us off
    # unrelated numeric ids that happen to share the key name.
    return m.group(1) + IMEI_TOKEN if _luhn_ok(m.group(2)) else m.group(0)


def redact_pii(text: Optional[str]) -> Optional[str]:
    """Return ``text`` with emails, phones, IMEI/MEID/IMSI/ICCID and account
    names replaced by typed tokens. ``None`` and empty strings pass through.
    Deterministic and idempotent (tokens never re-match)."""
    if not text:
        return text
    out = _ACCOUNT_OBJ_RE.sub(lambda m: m.group(1) + ACCOUNT_TOKEN, text)
    out = _ACCOUNT_KV_RE.sub(lambda m: m.group(1) + ACCOUNT_TOKEN, out)
    out = _IMSI_KV_RE.sub(lambda m: m.group(1) + IMSI_TOKEN, out)
    out = _ICCID_KV_RE.sub(lambda m: m.group(1) + ICCID_TOKEN, out)
    out = _MEID_KV_RE.sub(lambda m: m.group(1) + MEID_TOKEN, out)
    out = _IMEI_KV_RE.sub(lambda m: m.group(1) + IMEI_TOKEN, out)
    out = _IMEI_DEVICE_ID_RE.sub(_device_id_sub, out)
    out = _EMAIL_RE.sub(_email_sub, out)
    out = _IMEI_SEP_RE.sub(_imei_sep_sub, out)
    out = _TEL_URI_RE.sub("tel:" + PHONE_TOKEN, out)
    out = _NANP_RE.sub(PHONE_TOKEN, out)
    out = _E164_RE.sub(_e164_sub, out)
    return out
