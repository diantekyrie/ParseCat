"""Multi-capture correlation: the data model treats a device's captures as
one longitudinal history, not disposable single uploads. A finding like
"app X has never requested audio focus" is checked against every capture on
file for the device, not just whichever file happens to be in the current
request. Confidence uses how many of those captures actually contributed
evidence for the package, not how many captures sit on file.
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlmodel import Session, select

from app.models.db_models import Capture, Device, FocusEventRow, ForegroundServiceRow, PackageFactRow


@dataclass
class PackageHistory:
    package: str
    # Captures that actually contributed evidence for this package -- NOT
    # every capture on file. A capture with zero matching rows is still
    # genuinely checked, it just had nothing to report; conflating the two
    # numbers is exactly what made "Checked across N capture(s)" misleading
    # once N stopped meaning "captures on file" (see captures_on_file below).
    captures_checked: int
    # Total captures on file for this device, regardless of whether any of
    # them had evidence for this specific package. Kept alongside
    # captures_checked so a caller can render "checked N of M" instead of
    # implying only N captures exist or were examined.
    captures_on_file: int
    ever_requested_focus: bool
    focus_request_count: int
    target_sdk_by_capture: dict[int, int | None]
    ever_hosted_foreground_service: bool


def captures_for_device(session: Session, device_label: str) -> list[Capture]:
    device = session.exec(select(Device).where(Device.label == device_label)).first()
    if device is None:
        return []
    return list(session.exec(
        select(Capture).where(Capture.device_id == device.id).order_by(Capture.ingested_at)
    ))


def _evidence_capture_count(*row_groups) -> int:
    """Distinct captures that actually contributed rows, not captures-on-file.

    Mirrors reasoning.evidence_confidence's capture_id count; kept local so
    this module does not import reasoning (reasoning already imports us).
    """
    return len({row.capture_id for group in row_groups for row in group})


def package_history_across_device(session: Session, device_label: str, package: str) -> PackageHistory:
    """The check that would have turned "Disney+ apparently didn't request
    audio focus in this file" into a corroborated, multi-capture finding
    instead of a single-file guess.
    """
    captures = captures_for_device(session, device_label)
    capture_ids = [c.id for c in captures]

    request_count = 0
    target_sdk_by_capture: dict[int, int | None] = {}
    hosted_fgs = False
    focus_rows: list[FocusEventRow] = []
    fact_rows: list[PackageFactRow] = []
    fgs_rows: list[ForegroundServiceRow] = []

    if capture_ids:
        focus_rows = list(session.exec(
            select(FocusEventRow).where(
                FocusEventRow.capture_id.in_(capture_ids),
                FocusEventRow.package == package,
            )
        ).all())
        request_count = sum(1 for e in focus_rows if e.event_type == "request")

        fact_rows = list(session.exec(
            select(PackageFactRow).where(
                PackageFactRow.capture_id.in_(capture_ids),
                PackageFactRow.package == package,
            )
        ).all())
        target_sdk_by_capture = {cid: None for cid in capture_ids}
        for row in fact_rows:
            target_sdk_by_capture[row.capture_id] = row.target_sdk

        fgs_rows = list(session.exec(
            select(ForegroundServiceRow).where(
                ForegroundServiceRow.capture_id.in_(capture_ids),
                ForegroundServiceRow.package == package,
            )
        ).all())
        hosted_fgs = bool(fgs_rows)

    return PackageHistory(
        package=package,
        captures_checked=_evidence_capture_count(focus_rows, fact_rows, fgs_rows),
        captures_on_file=len(captures),
        ever_requested_focus=request_count > 0,
        focus_request_count=request_count,
        target_sdk_by_capture=target_sdk_by_capture,
        ever_hosted_foreground_service=hosted_fgs,
    )
