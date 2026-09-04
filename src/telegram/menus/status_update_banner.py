"""Shared status/update suffix used by Telegram observability menus."""

from __future__ import annotations


def suffix_status_update_banner(text: str) -> str:
    """Append upstream status and update banners when either is available."""
    extras: list[str] = []
    try:
        from ... import status_monitor
        line = status_monitor.get_active_summary()
        if line:
            extras.append(line)
    except Exception:
        pass
    try:
        from ... import update_checker
        line = update_checker.get_update_banner()
        if line:
            extras.append(line)
    except Exception:
        pass
    if not extras:
        return text
    return text + "\n\n" + "\n".join(extras)
