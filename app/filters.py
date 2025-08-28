# app/filters.py
from __future__ import annotations
from datetime import datetime
from typing import Optional, Union
from zoneinfo import ZoneInfo

PARIS = ZoneInfo("Europe/Paris")
UTC = ZoneInfo("UTC")

def _to_dt(val: Union[datetime, int, float, str, None]) -> Optional[datetime]:
    if val is None:
        return None
    if isinstance(val, datetime):
        dt = val
    elif isinstance(val, (int, float)):
        dt = datetime.fromtimestamp(val, tz=UTC)
    elif isinstance(val, str):
        # ISO 8601 souple
        try:
            from dateutil import parser  # python-dateutil
            dt = parser.isoparse(val)
        except Exception:
            # fallback naïf: essaye format commun "YYYY-MM-DD HH:MM:SS"
            try:
                dt = datetime.strptime(val, "%Y-%m-%d %H:%M:%S")
            except Exception:
                return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
    else:
        return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(PARIS)

def fr_datetime(value: Union[datetime, int, float, str, None], include_seconds: bool = False) -> str:
    dt = _to_dt(value)
    if not dt:
        return ""
    fmt = "%d/%m/%Y %H:%M:%S" if include_seconds else "%d/%m/%Y %H:%M"
    return dt.strftime(fmt)

def fr_date(value: Union[datetime, int, float, str, None]) -> str:
    dt = _to_dt(value)
    return dt.strftime("%d/%m/%Y") if dt else ""

def fr_time(value: Union[datetime, int, float, str, None], include_seconds: bool = False) -> str:
    dt = _to_dt(value)
    fmt = "%H:%M:%S" if include_seconds else "%H:%M"
    return dt.strftime(fmt) if dt else ""
